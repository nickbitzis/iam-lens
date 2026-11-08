from collections import Counter

from helpers import EXT, A, allow, doc, make_env, role, user

from iamlens.escalation import ADMIN, EscalationGraph
from iamlens.findings import TYPES, analyze, public_statements, trust_findings
from iamlens.policy import Policy


def by_type(findings, t):
    return [f for f in findings if f.type == t]


def test_every_finding_type_present(findings):
    counts = Counter(f.type for f in findings)
    assert set(counts) == set(TYPES), counts


def test_wildcard_admin(findings, env):
    subs = {f.subject: f for f in by_type(findings, "wildcard_admin")}
    assert any(s.endswith(":user/svc-legacy-backup") for s in subs)
    bg = next(f for s, f in subs.items() if s.endswith(":role/breakglass-admin"))
    assert bg.severity == "medium" and "break-glass" in bg.detail
    # Sandbox admins have Action * but the SCP allowlist means they are not effective admins.
    assert not any(":role/sandbox-admin" in s for s in subs)


def test_unused_permissions_counts_are_consistent(findings):
    fs = by_type(findings, "unused_permissions")
    assert len(fs) > 50
    for f in fs:
        e = f.evidence
        assert e["granted"] == e["used"] + e["unused"]
        assert e["unused"] / e["granted"] >= 0.5


def test_unused_principals_have_no_successful_calls(findings, env):
    for f in by_type(findings, "unused_principal"):
        pu = env.usage.get(f.subject)
        assert pu is None or not pu.used_actions
    assert not any(":role/breakglass-admin" in f.subject for f in by_type(findings, "unused_principal"))


def test_external_trust_without_external_id(findings):
    subs = sorted(f.subject.split("/")[-1] for f in by_type(findings, "external_trust_without_external_id"))
    assert subs == ["vendor-quillsearch-indexer", "vendor-tapevault-backup"]


def test_external_trust_rules_on_small_env():
    trust_ok = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
        }
    )
    trust_bad = doc({"Effect": "Allow", "Principal": {"AWS": EXT}, "Action": "sts:AssumeRole"})
    trust_org = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})
    env = make_env([role("ok", trust=trust_ok), role("bad", trust=trust_bad), role("org", trust=trust_org)], {})
    got = {p.name: bool(trust_findings(env, p)) for p in env.principals.values()}
    assert got == {"ok": False, "bad": True, "org": False}


def test_public_resource_policies(findings):
    fs = {f.subject.split(":")[-1]: f for f in by_type(findings, "public_resource_policy")}
    assert fs["cobaltline-catalog-staging-exports"].severity == "critical"  # anyone can write
    assert fs["cobaltline-web-prod-assets"].severity == "high"  # read only
    assert any("billing-export" in k for k in fs)  # key policy open to *
    assert not any("partner-drop" in k or "data-lake" in k for k in fs)  # limited by aws:PrincipalOrgID


def test_public_statement_detection():
    p = Policy.parse(
        doc(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            },
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:PutObject", "Resource": "*"},
        )
    )
    pub = public_statements(p)
    assert len(pub) == 1 and pub[0]["write"]


def test_mfa_not_enforced(findings, env):
    fs = by_type(findings, "mfa_not_enforced")
    assert fs
    for f in fs:
        p = env.principals[f.subject]
        assert p.console and "all-staff-mfa" not in p.groups
        assert (f.severity == "high") == (not p.mfa)


def test_long_lived_keys(findings):
    fs = by_type(findings, "long_lived_access_key")
    assert all(f.evidence["age_days"] > 90 for f in fs)
    assert all((f.severity == "high") == (f.evidence["age_days"] > 365) for f in fs)


def test_findings_sorted_by_severity(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranks = [order[f.severity] for f in findings]
    assert ranks == sorted(ranks)


# ---------- escalation ----------


def esc_env():
    policies = {
        "admin": doc(allow("*")),
        "attach-self": doc(allow(["iam:AttachUserPolicy"], f"arn:aws:iam::{A}:user/${{aws:username}}")),
        "assume-ops": doc(allow("sts:AssumeRole", f"arn:aws:iam::{A}:role/ops")),
        "ops": doc(allow(["iam:AttachRolePolicy"], f"arn:aws:iam::{A}:role/*")),
        "pass": doc(allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])),
        "update-fn": doc(allow("lambda:UpdateFunctionCode")),
        "keys": doc(allow("iam:CreateAccessKey", f"arn:aws:iam::{A}:user/*")),
        "read": doc(allow("s3:GetObject")),
    }
    acct_trust = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})
    lam_trust = doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"})
    principals = [
        user("selfie", policies=["attach-self"]),
        user("eng", policies=["assume-ops"]),
        role("ops", policies=["ops"], trust=acct_trust),
        user("deployer", policies=["pass"]),
        role("lambda-admin", policies=["admin"], trust=lam_trust),
        user("coder", policies=["update-fn"]),
        user("helpdesk", policies=["keys"]),
        user("boss", policies=["admin"]),
        user("reader", policies=["read"]),
    ]
    resources = [
        {
            "arn": f"arn:aws:lambda:us-east-1:{A}:function:nightly",
            "type": "lambda_function",
            "account": A,
            "name": "nightly",
            "role": f"arn:aws:iam::{A}:role/lambda-admin",
        }
    ]
    return make_env(principals, policies, resources)


def test_escalation_edge_kinds_and_paths():
    env = esc_env()
    g = EscalationGraph(env)
    arn = lambda n: next(p.arn for p in env.principals.values() if p.name == n)  # noqa: E731
    assert g.admins == {arn("boss"), arn("lambda-admin")}
    paths = g.all_paths()
    kinds = {env.principals[s].name: [e.kind for e in p] for s, p in paths.items()}
    assert kinds["selfie"] == ["self-attach"]
    assert kinds["eng"] == ["assume", "self-attach"]
    assert kinds["ops"] == ["self-attach"]
    assert kinds["deployer"] == ["pass-role (lambda)"]
    assert kinds["coder"] == ["update-function"]
    assert kinds["helpdesk"] == ["user-takeover"]
    assert "reader" not in kinds
    assert paths[arn("eng")][-1].dst == ADMIN


def test_scp_cuts_an_escalation_path():
    env = esc_env()
    from helpers import deny

    env2 = make_env(
        [p for p in env.raw["principals"]],
        {k: v["document"] for k, v in env.raw["policies"].items() if v["kind"] != "scp"},
        env.raw["resources"],
        scps={"NoKeys": doc(deny(["iam:CreateAccessKey", "lambda:UpdateFunctionCode"]))},
    )
    names = {env2.principals[s].name for s in EscalationGraph(env2).all_paths()}
    assert "helpdesk" not in names and "coder" not in names
    assert "selfie" in names


def test_example_paths(graph, env):
    paths = graph.all_paths()
    assert len(paths) >= 20
    names = {s.split("/")[-1]: [e.kind for e in p] for s, p in paths.items()}
    assert names["orders-prod-ops"] == ["self-attach"]
    assert names["ci-runner"] == ["assume"]
    # Platform engineers have iam:* by policy, but the PlatformBoundary removes self-attach.
    for s, p in paths.items():
        prin = env.principals[s]
        if prin.boundary == "PlatformBoundary":
            assert p[0].kind != "self-attach"


def test_analyze_small_env_has_escalation_finding():
    env = esc_env()
    fs = analyze(env)
    esc = [f for f in fs if f.type == "privilege_escalation"]
    assert {f.subject.split("/")[-1] for f in esc} >= {"selfie", "eng", "deployer", "coder", "helpdesk"}
    two = next(f for f in esc if f.subject.endswith("/eng"))
    assert two.severity == "high" and len(two.evidence["path"]) == 2
