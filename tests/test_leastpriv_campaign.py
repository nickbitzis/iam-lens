from datetime import date, timedelta

import pytest
from helpers import A, allow, deny, doc, make_env, user

from iamlens.campaign import CampaignError, CampaignStore, NotReviewer, verify_chain
from iamlens.engine import evaluate
from iamlens.leastpriv import Config, build_policy, suggest, summarize
from iamlens.policy import Policy
from iamlens.usage import granted_actions


def ev(p, a, r, day="2026-10-01", res="allowed", ip="203.0.113.5", mfa=True):
    return {"t": f"{day}T10:00:00Z", "p": p, "a": a, "r": r, "ip": ip, "res": res, "mfa": mfa}


def lp_env():
    u = f"arn:aws:iam::{A}:user/ana"
    policies = {
        "power": doc(allow(["s3:*", "dynamodb:*", "kms:*", "ec2:Describe*", "logs:*"])),
        "guard": doc(deny("*", Condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}})),
    }
    events = [ev(u, "s3:GetObject", f"arn:aws:s3:::data/reports/{i}.csv") for i in range(8)]
    events += [
        ev(u, "s3:PutObject", "arn:aws:s3:::data/out/x.csv"),
        ev(u, "s3:ListBucket", "arn:aws:s3:::data"),
        ev(u, "ec2:DescribeInstances", "*"),
        ev(u, "dynamodb:GetItem", f"arn:aws:dynamodb:us-east-1:{A}:table/t0"),
    ]
    events += [ev(u, "dynamodb:Query", f"arn:aws:dynamodb:us-east-1:{A}:table/t{i}") for i in range(7)]
    events += [ev(u, "kms:Decrypt", f"arn:aws:kms:us-east-1:{A}:key/k1", res="denied")]
    return make_env([user("ana", policies=["power", "guard"])], policies, events=events), u


def test_generated_policy_shape():
    env, u = lp_env()
    d, notes = build_policy(env, env.principals[u], Config(max_resources=5, buffer=[]))
    stmts = {tuple(s["Action"]): s["Resource"] for s in d["Statement"]}
    assert stmts[("ec2:DescribeInstances",)] == "*"
    assert stmts[("s3:GetObject",)] == "arn:aws:s3:::data/reports/*"  # object ARNs collapse to their prefix
    # 7 tables exceed max_resources, so they collapse to the common prefix
    assert stmts[("dynamodb:Query",)] == f"arn:aws:dynamodb:us-east-1:{A}:table/*"
    assert not any("kms" in a for acts in stmts for a in acts)  # denied calls are not usage
    assert "s3:PutObject" in notes["rare_actions"]


def test_generated_policy_proves_coverage_and_denial():
    env, u = lp_env()
    r = suggest(env, u, Config(buffer=[]))
    pr = r["proof"]
    assert pr["passed"], pr
    assert pr["observed_still_allowed"] == pr["observed_requests"] > 0
    assert pr["unused_actions_denied"] == pr["unused_actions_checked"] > 50
    assert r["granted_after"] < r["granted_before"]
    assert r["kept_guardrails"] == ["guard"]


def test_buffer_keeps_rarely_used_actions():
    env, u = lp_env()
    r = suggest(env, u, Config(buffer=["dynamodb:CreateBackup", "rds:*"]))
    assert r["buffered_actions"] == ["dynamodb:CreateBackup"]  # rds is not granted, so not buffered
    new = Policy.parse(r["policy"])
    assert evaluate(
        env,
        u,
        "dynamodb:CreateBackup",
        f"arn:aws:dynamodb:us-east-1:{A}:table/t0",
        {"aws:MultiFactorAuthPresent": "true"},
        identity_override=[new],
    ).allowed
    assert r["proof"]["passed"]


def test_proof_catches_a_broken_policy():
    env, u = lp_env()
    from iamlens.leastpriv import prove_policy

    p = env.principals[u]
    too_narrow = Policy.parse(doc(allow("s3:ListBucket", "arn:aws:s3:::data")))
    pr = prove_policy(env, p, [too_narrow], granted_actions(env, p), set())
    assert not pr["passed"] and pr["observed_broken"]
    too_wide = Policy.parse(doc(allow("*")))
    pr = prove_policy(env, p, [too_wide], granted_actions(env, p), set())
    assert not pr["passed"] and pr["unused_still_allowed"]


def test_example_principals_all_prove(env):
    sample = [p for p in env.principals.values() if env.usage.get(p.arn) and env.usage[p.arn].used_actions][::25]
    assert len(sample) >= 10
    for p in sample:
        r = suggest(env, p)
        assert r["proof"]["passed"], (p.arn, r["proof"])
        assert r["granted_after"] <= r["granted_before"]


def test_reduction_summary(env):
    s = summarize(env)
    assert s["principals"] > 200
    assert s["granted_after"] < s["granted_before"]
    assert 70 < s["reduction_pct"] < 99


# ---------- campaign ----------


def camp_env():
    m = f"arn:aws:iam::{A}:user/"
    principals = [
        user("cto"),
        user("mgr", manager=m + "cto"),
        user(
            "ana",
            groups=["readers"],
            manager=m + "mgr",
            access_keys=[{"id": "k1", "status": "Active", "created": "2025-01-01", "last_used": "2026-06-01"}],
        ),
        user("bo", groups=["readers", "writers"], manager=m + "mgr"),
    ]
    policies = {"read": doc(allow("s3:GetObject")), "write": doc(allow("s3:PutObject"))}
    groups = [
        {"name": "readers", "account": A, "policies": ["read"]},
        {"name": "writers", "account": A, "policies": ["write"]},
    ]
    events = [ev(m + "ana", "s3:GetObject", "arn:aws:s3:::b/x"), ev(m + "bo", "s3:GetObject", "arn:aws:s3:::b/x")]
    return make_env(principals, policies, groups=groups, events=events), m


START, DUE = date(2026, 11, 7), date(2026, 11, 21)


def test_campaign_items_and_suggestions():
    env, m = camp_env()
    store = CampaignStore(env)
    c = store.create("Q4", START, DUE)
    items = {(i["user"].split("/")[-1], i["entitlement"]["name"]): i for i in c["items"]}
    assert set(items) == {("ana", "readers"), ("ana", "k1"), ("bo", "readers"), ("bo", "writers")}
    assert items[("ana", "readers")]["suggestion"] == "keep"
    assert items[("bo", "writers")]["suggestion"] == "revoke"  # never used s3:PutObject
    assert items[("ana", "k1")]["suggestion"] == "revoke"  # key idle since June
    assert all(i["reviewer"] == m + "mgr" for i in c["items"])


def test_campaign_decisions_and_authorization():
    env, m = camp_env()
    store = CampaignStore(env)
    c = store.create("Q4", START, DUE)
    first = c["items"][0]["id"]
    with pytest.raises(NotReviewer):
        store.decide(c["id"], first, m + "ana", "keep", START)
    item = next(i for i in c["items"] if i["suggestion"] == "revoke")
    with pytest.raises(CampaignError):
        store.decide(c["id"], item["id"], m + "mgr", "keep", START)  # override needs a comment
    store.decide(c["id"], item["id"], m + "mgr", "keep", START, "Needed for the year-end export")
    with pytest.raises(CampaignError):
        store.decide(c["id"], item["id"], m + "mgr", "revoke", START)  # already decided
    st = store.status(c["id"], START)
    assert st["decided"] == 1 and st["overrides"] == 1


def test_campaign_escalation_and_close():
    env, m = camp_env()
    store = CampaignStore(env)
    c = store.create("Q4", START, DUE, escalate_after_days=3)
    assert store.escalate(c["id"], DUE) == []  # due today is not overdue
    late = DUE + timedelta(days=1)
    moved = store.escalate(c["id"], late)
    assert len(moved) == len(c["items"])
    assert all(i["reviewer"] == m + "cto" and i["status"] == "escalated" for i in c["items"])
    assert store.status(c["id"], late)["overdue"] == 0
    with pytest.raises(NotReviewer):
        store.decide(c["id"], c["items"][0]["id"], m + "mgr", c["items"][0]["suggestion"], late)
    for i in c["items"]:
        store.decide(c["id"], i["id"], m + "cto", i["suggestion"], late)
    assert store.get(c["id"])["status"] == "closed"


def test_evidence_export_is_chained(tmp_path):
    env, m = camp_env()
    store = CampaignStore(env, tmp_path / "campaigns.json")
    c = store.create("Q4", START, DUE)
    store.decide(c["id"], c["items"][0]["id"], m + "mgr", c["items"][0]["suggestion"], START)
    import json

    data = json.loads(store.evidence(c["id"], START))
    assert data["integrity"]["head"] == data["items"][-1]["chain_hash"]
    assert verify_chain(data["items"])
    data["items"][0]["decision"] = "revoke" if data["items"][0]["decision"] == "keep" else "keep"
    assert not verify_chain(data["items"])  # tampering breaks the chain
    csv_text = store.evidence(c["id"], START, "csv")
    assert csv_text.splitlines()[0].startswith("item,user,user_name")
    # persisted and reloaded
    again = CampaignStore(env, tmp_path / "campaigns.json")
    assert again.get(c["id"])["items"][0]["decision"] is not None


def test_campaign_on_example_env(env):
    store = CampaignStore(env)
    c = store.create("Q4", env.as_of, env.as_of + timedelta(days=14))
    st = store.status(c["id"], env.as_of)
    assert st["items"] > 200 and st["suggested_revoke"] > 0
    assert all(env.principals[i["reviewer"]].kind == "human" for i in c["items"])
