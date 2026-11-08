import pytest

from iamlens.conditions import ConditionError, eval_conditions, parse_operator
from iamlens.matching import action_match, arn_match, substitute
from iamlens.policy import Policy, PolicyError


@pytest.mark.parametrize(
    "pattern,action,expected",
    [
        ("s3:GetObject", "s3:GetObject", True),
        ("s3:Get*", "s3:GetObjectAcl", True),
        ("s3:get*", "S3:GETOBJECT", True),  # actions ignore case
        ("s3:*", "ec2:DescribeInstances", False),
        ("*", "kms:Decrypt", True),
        ("iam:*Policy", "iam:AttachRolePolicy", True),
        ("iam:*Policy", "iam:PassRole", False),
        ("ec2:Describe?nstances", "ec2:DescribeInstances", True),
        ("ec2:Describe?", "ec2:DescribeVpcs", False),
    ],
)
def test_action_wildcards(pattern, action, expected):
    assert action_match(pattern, action) is expected


@pytest.mark.parametrize(
    "pattern,arn,expected",
    [
        ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c.json", True),
        ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket", False),
        ("arn:aws:s3:::bucket*", "arn:aws:s3:::bucket-two/x", True),
        ("arn:aws:iam::*:role/ci-*", "arn:aws:iam::111111111111:role/ci-deploy", True),
        ("arn:aws:iam::*:role/ci-*", "arn:aws:iam::111111111111:user/ci-deploy", False),
        ("arn:aws:s3:::Bucket/*", "arn:aws:s3:::bucket/x", False),  # resources are case sensitive
        ("arn:aws:*:us-east-1:111111111111:*", "arn:aws:sqs:us-east-1:111111111111:q", True),
        ("arn:aws:logs:*:*:log-group:/app/x:*", "arn:aws:logs:us-east-1:1:log-group:/app/x:log-stream:a", True),
        ("*", "anything", True),
    ],
)
def test_arn_wildcards(pattern, arn, expected):
    assert arn_match(pattern, arn) is expected


def test_segment_wildcards_stay_in_their_segment():
    assert arn_match("arn:aws:sqs:us-*:111111111111:q", "arn:aws:sqs:us-west-2:111111111111:q")
    assert not arn_match("arn:aws:sqs:us-*:111111111111:q", "arn:aws:sqs:eu-west-1:111111111111:q")
    assert not arn_match("arn:aws:iam::1*:role/x", "arn:aws:iam::222222222222:role/x")


def test_policy_variables():
    ctx = {"aws:username": "ana"}
    assert substitute("arn:aws:iam::*:user/${aws:username}", ctx) == "arn:aws:iam::*:user/ana"
    assert "unresolved" in substitute("home/${aws:userid}/*", ctx)


def ctx(**kw):
    return {k.replace("__", ":").lower(): v for k, v in kw.items()}


def check(block, c):
    return eval_conditions(block, c)[0]


def test_string_equals_and_not_equals():
    c = ctx(aws__PrincipalOrgID="o-abc")
    assert check({"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}, c)
    assert not check({"StringEquals": {"aws:PrincipalOrgID": "o-xyz"}}, c)
    assert check({"StringEquals": {"aws:PrincipalOrgID": ["o-xyz", "o-abc"]}}, c)  # values are OR
    assert check({"StringNotEquals": {"aws:PrincipalOrgID": "o-xyz"}}, c)
    assert not check({"StringEquals": {"aws:PrincipalOrgID": "O-ABC"}}, c)
    assert check({"StringEqualsIgnoreCase": {"aws:PrincipalOrgID": "O-ABC"}}, c)


def test_string_like():
    c = ctx(aws__PrincipalArn="arn:aws:iam::111111111111:role/ci-deploy")
    assert check({"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/ci-*"}}, c)
    assert not check({"StringLike": {"aws:PrincipalArn": "*:user/*"}}, c)
    assert check({"StringNotLike": {"aws:PrincipalArn": "*:user/*"}}, c)


def test_ip_address():
    c = ctx(aws__SourceIp="203.0.113.77")
    assert check({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, c)
    assert not check({"IpAddress": {"aws:SourceIp": ["198.51.100.0/24", "10.0.0.0/8"]}}, c)
    assert check({"NotIpAddress": {"aws:SourceIp": "198.51.100.0/24"}}, c)
    assert check({"IpAddress": {"aws:SourceIp": "203.0.113.77"}}, c)  # single address
    assert not check({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, ctx(aws__SourceIp="not-an-ip"))


def test_bool_mfa():
    assert check({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, ctx(aws__MultiFactorAuthPresent="true"))
    assert not check({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, ctx(aws__MultiFactorAuthPresent="false"))
    assert check({"Bool": {"aws:MultiFactorAuthPresent": True}}, ctx(aws__MultiFactorAuthPresent="TRUE"))


def test_missing_keys_and_if_exists():
    empty = {}
    assert not check({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, empty)  # positive op, missing key: false
    assert check({"StringNotEquals": {"aws:PrincipalOrgID": "o-abc"}}, empty)  # negated op, missing key: true
    assert check({"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}, empty)  # IfExists, missing: true
    assert not check({"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}, ctx(aws__MultiFactorAuthPresent="true"))
    assert check({"Null": {"aws:MultiFactorAuthPresent": "true"}}, empty)
    assert not check({"Null": {"aws:MultiFactorAuthPresent": "false"}}, empty)


def test_multiple_operators_and_keys_are_and():
    c = ctx(aws__SourceIp="203.0.113.5", aws__MultiFactorAuthPresent="false")
    block = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}, "Bool": {"aws:MultiFactorAuthPresent": "true"}}
    assert not check(block, c)


def test_set_operators():
    c = {"aws:tagkeys": ["team", "env"]}
    assert check({"ForAllValues:StringEquals": {"aws:TagKeys": ["team", "env", "owner"]}}, c)
    assert not check({"ForAllValues:StringEquals": {"aws:TagKeys": ["team"]}}, c)
    assert check({"ForAnyValue:StringEquals": {"aws:TagKeys": ["env"]}}, c)


def test_condition_with_policy_variable():
    c = ctx(aws__username="ana", s3__prefix="home/ana/")
    assert check({"StringLike": {"s3:prefix": "home/${aws:username}/*"}}, c)


def test_unknown_operator_rejected():
    with pytest.raises(ConditionError):
        parse_operator("StringSortOf")
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Fuzzy": {"a": "b"}}}]}
        )


@pytest.mark.parametrize(
    "stmt",
    [
        {"Effect": "Maybe", "Action": "*", "Resource": "*"},
        {"Effect": "Allow", "Resource": "*"},
        {"Effect": "Allow", "Action": "*", "NotAction": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "*", "Resources": "*"},
    ],
)
def test_invalid_statements(stmt):
    with pytest.raises(PolicyError):
        Policy.parse({"Version": "2012-10-17", "Statement": [stmt]})


def test_notaction_and_notresource():
    p = Policy.parse(
        {"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "NotResource": "arn:aws:s3:::secret/*"}]}
    )
    s = p.statements[0]
    assert s.matches_action("s3:GetObject") and not s.matches_action("iam:CreateUser")
    assert s.matches_resource("arn:aws:s3:::public/a", {}) and not s.matches_resource("arn:aws:s3:::secret/a", {})
