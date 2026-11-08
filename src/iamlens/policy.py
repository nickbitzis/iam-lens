"""IAM JSON policy grammar: parsing, validation, and statement matching."""

from __future__ import annotations

from dataclasses import dataclass, field

from .conditions import ConditionError, eval_conditions, parse_operator
from .matching import action_match, arn_match, substitute

VALID_KEYS = {
    "Sid",
    "Effect",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Principal",
    "NotPrincipal",
    "Condition",
}


class PolicyError(ValueError):
    pass


def _list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@dataclass
class Principals:
    """Normalized Principal element. `wildcard` means `"*"` or `{"AWS": "*"}`."""

    wildcard: bool = False
    aws: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    federated: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, v) -> Principals | None:
        if v is None:
            return None
        if v == "*":
            return cls(wildcard=True)
        if not isinstance(v, dict):
            raise PolicyError(f"Principal must be '*' or an object, got {v!r}")
        p = cls()
        for k, vals in v.items():
            vals = _list(vals)
            if k == "AWS":
                if "*" in vals:
                    p.wildcard = True
                p.aws = [x for x in vals if x != "*"]
            elif k == "Service":
                p.service = vals
            elif k == "Federated":
                p.federated = vals
            else:
                raise PolicyError(f"unknown principal type {k}")
        return p

    def accounts(self) -> set[str]:
        """Accounts named in AWS principals, as a bare id or `arn:aws:iam::ID:root` or any ARN in that account."""
        out = set()
        for a in self.aws:
            if a.isdigit():
                out.add(a)
            elif a.startswith("arn:"):
                parts = a.split(":")
                if len(parts) > 4 and parts[4]:
                    out.add(parts[4])
        return out


@dataclass
class Statement:
    sid: str
    effect: str
    actions: list[str]
    not_actions: list[str]
    resources: list[str]
    not_resources: list[str]
    principal: Principals | None
    not_principal: Principals | None
    condition: dict
    index: int

    @property
    def label(self) -> str:
        return self.sid or f"#{self.index}"

    def matches_action(self, action: str) -> bool:
        if self.not_actions:
            return not any(action_match(p, action) for p in self.not_actions)
        return any(action_match(p, action) for p in self.actions)

    def matches_resource(self, resource: str, ctx: dict) -> bool:
        if self.not_resources:
            return not any(arn_match(substitute(p, ctx), resource) for p in self.not_resources)
        if not self.resources:
            return True  # trust policies and some resource policies omit Resource
        return any(arn_match(substitute(p, ctx), resource) for p in self.resources)


@dataclass
class Policy:
    id: str
    name: str
    document: dict
    statements: list[Statement]
    kind: str = "managed"  # managed | inline | scp | boundary | resource | trust

    @classmethod
    def parse(cls, doc: dict, id: str = "inline", name: str | None = None, kind: str = "managed") -> Policy:
        return cls(id=id, name=name or id, document=doc, statements=parse_statements(doc), kind=kind)

    @property
    def is_resource_policy(self) -> bool:
        return any(s.principal is not None or s.not_principal is not None for s in self.statements)


def parse_statements(doc: dict) -> list[Statement]:
    if not isinstance(doc, dict):
        raise PolicyError("policy document must be a JSON object")
    raw = doc.get("Statement")
    if raw is None:
        raise PolicyError("policy has no Statement")
    out = []
    for i, s in enumerate(_list(raw)):
        if not isinstance(s, dict):
            raise PolicyError(f"statement {i} is not an object")
        unknown = set(s) - VALID_KEYS
        if unknown:
            raise PolicyError(f"statement {i} has unknown keys {sorted(unknown)}")
        effect = s.get("Effect")
        if effect not in ("Allow", "Deny"):
            raise PolicyError(f"statement {i} Effect must be Allow or Deny, got {effect!r}")
        if ("Action" in s) == ("NotAction" in s):
            raise PolicyError(f"statement {i} needs exactly one of Action or NotAction")
        if "Resource" in s and "NotResource" in s:
            raise PolicyError(f"statement {i} has both Resource and NotResource")
        cond = s.get("Condition") or {}
        try:
            for op in cond:
                parse_operator(op)
        except ConditionError as e:
            raise PolicyError(f"statement {i}: {e}") from e
        out.append(
            Statement(
                sid=s.get("Sid", ""),
                effect=effect,
                actions=[str(a) for a in _list(s.get("Action"))],
                not_actions=[str(a) for a in _list(s.get("NotAction"))],
                resources=[str(r) for r in _list(s.get("Resource"))],
                not_resources=[str(r) for r in _list(s.get("NotResource"))],
                principal=Principals.parse(s.get("Principal")),
                not_principal=Principals.parse(s.get("NotPrincipal")),
                condition=cond,
                index=i,
            )
        )
    return out


@dataclass
class Caller:
    """Who is making the request, as far as Principal matching needs to know."""

    arn: str
    account: str
    service: str | None = None  # set when the caller is an AWS service principal, e.g. lambda.amazonaws.com


def principal_match(p: Principals, caller: Caller) -> str | None:
    """How a Principal element matches: 'public', 'direct', 'account', or None.

    'account' means the policy trusts the whole account (`arn:aws:iam::ID:root` or a bare id), which delegates
    the decision to that account's identity policies.
    """
    if caller.service:
        return "direct" if caller.service in p.service else ("public" if p.wildcard else None)
    if p.wildcard:
        return "public"
    for a in p.aws:
        if a == caller.arn or (("*" in a or "?" in a) and arn_match(a, caller.arn)):
            return "direct"
    for a in p.aws:
        if a == caller.account or a == f"arn:aws:iam::{caller.account}:root":
            return "account"
    return None


@dataclass
class StatementHit:
    policy_id: str
    policy_name: str
    sid: str
    effect: str
    principal_match: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {"policy": self.policy_id, "policy_name": self.policy_name, "sid": self.sid, "effect": self.effect}
        if self.principal_match:
            d["principal_match"] = self.principal_match
        if self.notes:
            d["conditions"] = self.notes
        return d


def evaluate_policy(
    policy: Policy, action: str, resource: str, ctx: dict, caller: Caller | None = None
) -> tuple[list[StatementHit], list[StatementHit]]:
    """Return (allow hits, deny hits) for statements whose action, resource, principal, and conditions all match."""
    allows, denies = [], []
    for s in policy.statements:
        if not s.matches_action(action):
            continue
        if not s.matches_resource(resource, ctx):
            continue
        how = None
        if s.principal is not None or s.not_principal is not None:
            if caller is None:
                continue
            if s.principal is not None:
                how = principal_match(s.principal, caller)
                if how is None:
                    continue
            else:
                if principal_match(s.not_principal, caller) is not None:
                    continue
                how = "public"
        ok, notes = eval_conditions(s.condition, ctx)
        if not ok:
            continue
        hit = StatementHit(policy.id, policy.name, s.label, s.effect, how, notes)
        (allows if s.effect == "Allow" else denies).append(hit)
    return allows, denies
