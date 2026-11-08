"""Small hand-built environments for engine tests. Account ids are placeholders."""

from __future__ import annotations

from iamlens.model import Environment

A = "111111111111"
B = "222222222222"
MGMT = "999999999999"
EXT = "333333333333"
ORG = "o-test12345"


def doc(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **kw) -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **kw}


def deny(action, resource="*", **kw) -> dict:
    return {"Effect": "Deny", "Action": action, "Resource": resource, **kw}


def user(name, account=A, policies=(), groups=(), boundary=None, **kw) -> dict:
    return {
        "arn": f"arn:aws:iam::{account}:user/{name}",
        "name": name,
        "type": "user",
        "account": account,
        "kind": kw.pop("kind", "human"),
        "policies": list(policies),
        "groups": list(groups),
        "boundary": boundary,
        **kw,
    }


def role(name, account=A, policies=(), trust=None, boundary=None, **kw) -> dict:
    return {
        "arn": f"arn:aws:iam::{account}:role/{name}",
        "name": name,
        "type": "role",
        "account": account,
        "kind": kw.pop("kind", "service"),
        "policies": list(policies),
        "trust_policy": trust,
        "boundary": boundary,
        **kw,
    }


def make_env(
    principals, policies, resources=(), groups=(), scps=None, ou_scps=None, account_scps=None, events=None
) -> Environment:
    """Org: root and OU 'Work' with accounts A and B. Root has FullAWSAccess. The OU gets `ou_scps`, by default
    FullAWSAccess plus every SCP in `scps`. Accounts get FullAWSAccess plus `account_scps[acct]`."""
    scps = scps or {}
    pols = {"FullAWSAccess": {"kind": "scp", "document": doc(allow("*"))}}
    for pid, d in policies.items():
        pols[pid] = {"document": d, "kind": "managed"}
    for pid, d in scps.items():
        pols[pid] = {"document": d, "kind": "scp"}
    if ou_scps is None:
        ou_scps = ["FullAWSAccess"] + [s for s in scps if not any(s in v for v in (account_scps or {}).values())]

    def acct(i, n):
        extra = (account_scps or {}).get(i, [])
        return {"id": i, "name": n, "parent": "ou-work", "env": "prod", "scps": ["FullAWSAccess"] + extra}

    data = {
        "company": "Test Co",
        "as_of": "2026-11-07",
        "organization": {
            "id": ORG,
            "management_account": MGMT,
            "nodes": [
                {"id": "r", "name": "Root", "parent": None, "scps": ["FullAWSAccess"]},
                {"id": "ou-work", "name": "Work", "parent": "r", "scps": ou_scps},
            ],
        },
        "accounts": [
            acct(A, "alpha"),
            acct(B, "bravo"),
            {"id": MGMT, "name": "management", "parent": "r", "env": "mgmt", "scps": []},
        ],
        "external_accounts": [{"id": EXT, "name": "Vendor"}],
        "policies": pols,
        "groups": list(groups),
        "principals": list(principals),
        "resources": list(resources),
    }
    return Environment(data, events or [])
