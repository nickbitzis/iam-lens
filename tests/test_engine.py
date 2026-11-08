"""The evaluation engine against a table of hand-written cases, plus targeted checks of each rule."""

import pytest
from helpers import EXT, MGMT, A, B, allow, deny, doc, make_env, role, user

from iamlens.engine import evaluate

LOCKED_TRUST = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{MGMT}:root"}, "Action": "sts:AssumeRole"})
READER_TRUST = doc(
    {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"},
    {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "vendor-42"}},
    },
)


def build():
    policies = {
        "s3read": doc(allow("s3:GetObject", "arn:aws:s3:::alpha-data/*")),
        "admin": doc(allow("*")),
        "deny-delete": doc(deny("s3:DeleteObject")),
        "mfa-required": doc(
            {
                "Effect": "Deny",
                "NotAction": "sts:GetSessionToken",
                "Resource": "*",
                "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
            }
        ),
        "corp-ip": doc(allow("ec2:Describe*", Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})),
        "self-home": doc(allow("s3:*", "arn:aws:s3:::alpha-data/home/${aws:username}/*")),
        "kms-use": doc(allow("kms:Decrypt")),
        "assume-b": doc(allow("sts:AssumeRole", f"arn:aws:iam::{B}:role/*")),
        "assume-a": doc(allow("sts:AssumeRole", f"arn:aws:iam::{A}:role/*")),
        "s3-any-read": doc(allow("s3:GetObject")),
        "notaction-power": doc({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}),
        "boundary-s3": doc(allow("s3:*")),
        "boundary-ec2": doc(allow("ec2:*")),
    }
    principals = [
        user("ana", groups=["readers"], policies=["assume-b"]),
        user("bo", policies=["admin"], boundary="boundary-s3"),
        user("cy", policies=["admin", "mfa-required"]),
        user("dee", policies=["corp-ip"]),
        user("eve", policies=["self-home"]),
        user("fin", policies=["notaction-power"]),
        user("gus", boundary="boundary-ec2"),
        role("hal", boundary="boundary-ec2"),
        role("app", policies=["kms-use"]),
        role("locked", trust=LOCKED_TRUST, policies=["admin"]),
        role("reader", account=B, policies=["s3-any-read"], trust=READER_TRUST),
        role("reader2", account=B, policies=["s3-any-read"]),
        user("bob", account=B, policies=["admin", "assume-a"]),
        user("root-admin", account=MGMT, policies=["admin"]),
    ]
    resources = [
        {
            "arn": "arn:aws:s3:::alpha-data",
            "type": "s3_bucket",
            "account": A,
            "name": "alpha-data",
            "policy": doc(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{B}:role/reader"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::alpha-data/*",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [f"arn:aws:iam::{A}:user/gus", f"arn:aws:iam::{A}:role/hal"]},
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::alpha-data/uploads/*",
                },
            ),
        },
        {"arn": "arn:aws:s3:::bravo-data", "type": "s3_bucket", "account": B, "name": "bravo-data"},
        {
            "arn": f"arn:aws:kms:us-east-1:{A}:key/k1",
            "type": "kms_key",
            "account": A,
            "name": "k1",
            "policy": doc(
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"},
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{A}:role/app"},
                    "Action": "kms:Encrypt",
                    "Resource": "*",
                },
            ),
        },
        {
            "arn": f"arn:aws:kms:us-east-1:{A}:key/k2",
            "type": "kms_key",
            "account": A,
            "name": "k2",
            "policy": doc(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{A}:role/someone-else"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
            ),
        },
    ]
    groups = [{"name": "readers", "account": A, "policies": ["s3read", "deny-delete"]}]
    scps = {
        "NoDynamo": doc(deny("dynamodb:*")),
        "RegionLock": doc(
            {
                "Effect": "Deny",
                "NotAction": ["iam:*", "sts:*"],
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
            }
        ),
    }
    return make_env(principals, policies, resources, groups, scps, account_scps={B: ["NoDynamo"]})


ENV = build()
ARN = {p.name: p.arn for p in ENV.principals.values()}
K1, K2 = f"arn:aws:kms:us-east-1:{A}:key/k1", f"arn:aws:kms:us-east-1:{A}:key/k2"
MFA_T, MFA_F = {"aws:MultiFactorAuthPresent": "true"}, {"aws:MultiFactorAuthPresent": "false"}

CASES = [
    # (id, principal, action, resource, context, expected decision)
    ("group grant", "ana", "s3:GetObject", "arn:aws:s3:::alpha-data/x", {}, "Allow"),
    ("scoped grant misses other bucket", "ana", "s3:GetObject", "arn:aws:s3:::bravo-data/x", {}, "ImplicitDeny"),
    ("explicit deny without any allow", "ana", "s3:DeleteObject", "arn:aws:s3:::alpha-data/x", {}, "ExplicitDeny"),
    ("admin inside s3 boundary", "bo", "s3:PutObject", "arn:aws:s3:::alpha-data/x", {}, "Allow"),
    ("boundary caps admin", "bo", "ec2:DescribeInstances", "*", {}, "ImplicitDeny"),
    ("mfa deny when false", "cy", "s3:GetObject", "arn:aws:s3:::alpha-data/x", MFA_F, "ExplicitDeny"),
    ("mfa deny when missing (IfExists)", "cy", "s3:GetObject", "arn:aws:s3:::alpha-data/x", {}, "ExplicitDeny"),
    ("mfa present", "cy", "s3:GetObject", "arn:aws:s3:::alpha-data/x", MFA_T, "Allow"),
    ("ip inside corp range", "dee", "ec2:DescribeInstances", "*", {"aws:SourceIp": "203.0.113.9"}, "Allow"),
    ("ip outside corp range", "dee", "ec2:DescribeInstances", "*", {"aws:SourceIp": "192.0.2.9"}, "ImplicitDeny"),
    ("policy variable own home", "eve", "s3:PutObject", "arn:aws:s3:::alpha-data/home/eve/a", {}, "Allow"),
    ("policy variable other home", "eve", "s3:PutObject", "arn:aws:s3:::alpha-data/home/ana/a", {}, "ImplicitDeny"),
    ("NotAction excludes iam", "fin", "iam:CreateUser", "*", {}, "ImplicitDeny"),
    ("NotAction allows the rest", "fin", "s3:ListBucket", "arn:aws:s3:::alpha-data", {}, "Allow"),
    ("cross-account both sides allow", "reader", "s3:GetObject", "arn:aws:s3:::alpha-data/x", {}, "Allow"),
    ("cross-account no resource grant", "reader2", "s3:GetObject", "arn:aws:s3:::alpha-data/x", {}, "ImplicitDeny"),
    ("cross-account assume with trust", "ana", "sts:AssumeRole", f"arn:aws:iam::{B}:role/reader", {}, "Allow"),
    ("assume without identity grant", "dee", "sts:AssumeRole", f"arn:aws:iam::{B}:role/reader", {}, "ImplicitDeny"),
    ("trust does not name account", "bob", "sts:AssumeRole", f"arn:aws:iam::{A}:role/locked", {}, "ImplicitDeny"),
    ("key policy delegates to account", "app", "kms:Decrypt", K1, {}, "Allow"),
    ("key policy does not delegate", "app", "kms:Decrypt", K2, {}, "ImplicitDeny"),
    ("key policy grants directly", "app", "kms:Encrypt", K1, {}, "Allow"),
    (
        "SCP explicit deny beats admin",
        "bob",
        "dynamodb:GetItem",
        f"arn:aws:dynamodb:us-east-1:{B}:table/t",
        {},
        "ExplicitDeny",
    ),
    (
        "region lock SCP",
        "ana",
        "s3:GetObject",
        "arn:aws:s3:::alpha-data/x",
        {"aws:RequestedRegion": "eu-west-1"},
        "ExplicitDeny",
    ),
    (
        "management account ignores SCPs",
        "root-admin",
        "dynamodb:GetItem",
        f"arn:aws:dynamodb:eu-west-1:{MGMT}:table/t",
        {},
        "Allow",
    ),
    (
        "boundary does not cap direct user grant",
        "gus",
        "s3:PutObject",
        "arn:aws:s3:::alpha-data/uploads/x",
        {},
        "Allow",
    ),
    ("boundary caps direct role grant", "hal", "s3:PutObject", "arn:aws:s3:::alpha-data/uploads/x", {}, "ImplicitDeny"),
]


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_case_table(case):
    _, who, action, resource, ctx, expected = case
    d = evaluate(ENV, ARN[who], action, resource, ctx)
    assert d.decision == expected, d.to_dict()
    assert d.allowed is (expected == "Allow")
    assert d.steps[-1].stage == "decision"


def test_decision_path_names_the_deny_statement():
    d = evaluate(ENV, ARN["ana"], "s3:DeleteObject", "arn:aws:s3:::alpha-data/x")
    assert d.steps[0].stage == "explicit deny" and d.steps[0].outcome == "deny"
    assert d.steps[0].statements[0].policy_id == "deny-delete"


def test_deny_wins_over_allow_in_same_policy_set():
    env = make_env([user("z", policies=["a", "d"])], {"a": doc(allow("s3:*")), "d": doc(deny("s3:PutObject"))})
    assert evaluate(env, f"arn:aws:iam::{A}:user/z", "s3:GetObject", "arn:aws:s3:::b/x").allowed
    assert evaluate(env, f"arn:aws:iam::{A}:user/z", "s3:PutObject", "arn:aws:s3:::b/x").decision == "ExplicitDeny"


def test_scp_allowlist_missing_at_one_level_is_implicit_deny():
    env = make_env(
        [user("z", policies=["admin"])],
        {"admin": doc(allow("*"))},
        scps={"OnlyS3": doc(allow("s3:*"))},
        ou_scps=["OnlyS3"],
    )
    ok = evaluate(env, f"arn:aws:iam::{A}:user/z", "s3:GetObject", "arn:aws:s3:::b/x")
    no = evaluate(env, f"arn:aws:iam::{A}:user/z", "ec2:RunInstances", "*")
    assert ok.allowed
    assert no.decision == "ImplicitDeny" and "OU Work" in no.reason
    assert any(s.stage == "service control policies" and s.outcome == "fail" for s in no.steps)


def test_cross_account_requires_identity_side_too():
    env = make_env(
        [user("x", account=B)],
        {},
        [
            {
                "arn": "arn:aws:s3:::shared",
                "type": "s3_bucket",
                "account": A,
                "name": "shared",
                "policy": doc(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{B}:root"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::shared/*",
                    }
                ),
            }
        ],
    )
    d = evaluate(env, f"arn:aws:iam::{B}:user/x", "s3:GetObject", "arn:aws:s3:::shared/f")
    assert d.decision == "ImplicitDeny" and "no identity policy" in d.reason


def test_same_account_resource_policy_alone_allows():
    env = make_env(
        [user("x")],
        {},
        [
            {
                "arn": "arn:aws:s3:::own",
                "type": "s3_bucket",
                "account": A,
                "name": "own",
                "policy": doc(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{A}:user/x"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::own/*",
                    }
                ),
            }
        ],
    )
    assert evaluate(env, f"arn:aws:iam::{A}:user/x", "s3:GetObject", "arn:aws:s3:::own/f").allowed


def test_external_id_condition_on_trust():
    vendor = make_env([role("v", account=EXT, policies=["assume"])], {"assume": doc(allow("sts:AssumeRole"))})
    # The vendor's role lives outside the org; borrow the trust policy from the case env.
    p = vendor.principals[f"arn:aws:iam::{EXT}:role/v"]
    target = f"arn:aws:iam::{B}:role/reader"
    ENV.principals[p.arn] = p
    vendor_id_policy = vendor.policies["assume"]
    ENV.policies["assume"] = vendor_id_policy
    try:
        assert not evaluate(ENV, p.arn, "sts:AssumeRole", target).allowed
        assert evaluate(ENV, p.arn, "sts:AssumeRole", target, {"sts:ExternalId": "vendor-42"}).allowed
        assert not evaluate(ENV, p.arn, "sts:AssumeRole", target, {"sts:ExternalId": "guess"}).allowed
    finally:
        del ENV.principals[p.arn]
        del ENV.policies["assume"]


def test_identity_override_replaces_identity_policies():
    from iamlens.policy import Policy

    narrow = Policy.parse(doc(allow("s3:ListBucket", "arn:aws:s3:::alpha-data")), id="narrow")
    d = evaluate(ENV, ARN["fin"], "s3:GetObject", "arn:aws:s3:::alpha-data/x", identity_override=[narrow])
    assert not d.allowed
    assert evaluate(ENV, ARN["fin"], "s3:ListBucket", "arn:aws:s3:::alpha-data", identity_override=[narrow]).allowed


def test_auto_context_keys():
    d = evaluate(ENV, ARN["eve"], "s3:GetObject", "arn:aws:s3:::alpha-data/x")
    assert d.context["aws:username"] == "eve"
    assert d.context["aws:principalorgid"] == "o-test12345"
    assert d.context["aws:requestedregion"] == "us-east-1"
