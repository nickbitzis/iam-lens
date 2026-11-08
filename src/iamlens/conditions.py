"""Condition block evaluation.

A Condition block is `{operator: {key: value_or_values}}`. All operators must be true, all keys inside an
operator must be true, and any one of a key's values is enough (OR). Supported operators:

StringEquals, StringNotEquals, StringEqualsIgnoreCase, StringNotEqualsIgnoreCase, StringLike, StringNotLike,
ArnEquals, ArnLike, ArnNotEquals, ArnNotLike, IpAddress, NotIpAddress, Bool, Null, NumericEquals,
NumericLessThan, NumericGreaterThan, plus the `...IfExists` suffix and the `ForAnyValue:` / `ForAllValues:`
set prefixes.

Missing keys: a positive operator is false, a negated operator is true, `IfExists` makes either true.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache

from .matching import arn_match, glob_match, substitute


class ConditionError(ValueError):
    pass


@lru_cache(maxsize=1024)
def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def _str_eq(p: str, v: str) -> bool:
    return p == v


def _str_eq_ic(p: str, v: str) -> bool:
    return p.lower() == v.lower()


def _str_like(p: str, v: str) -> bool:
    return glob_match(p, v)


def _ip(p: str, v: str) -> bool:
    try:
        return ipaddress.ip_address(v) in _net(p)
    except ValueError:
        return False


def _bool(p: str, v: str) -> bool:
    return str(p).lower() == str(v).lower()


def _num(op):
    def f(p: str, v: str) -> bool:
        try:
            return op(float(v), float(p))
        except ValueError:
            return False

    return f


# name -> (match function, negated)
OPERATORS = {
    "StringEquals": (_str_eq, False),
    "StringNotEquals": (_str_eq, True),
    "StringEqualsIgnoreCase": (_str_eq_ic, False),
    "StringNotEqualsIgnoreCase": (_str_eq_ic, True),
    "StringLike": (_str_like, False),
    "StringNotLike": (_str_like, True),
    "ArnEquals": (_str_eq, False),
    "ArnNotEquals": (_str_eq, True),
    "ArnLike": (arn_match, False),
    "ArnNotLike": (arn_match, True),
    "IpAddress": (_ip, False),
    "NotIpAddress": (_ip, True),
    "Bool": (_bool, False),
    "NumericEquals": (_num(lambda a, b: a == b), False),
    "NumericLessThan": (_num(lambda a, b: a < b), False),
    "NumericGreaterThan": (_num(lambda a, b: a > b), False),
}


@dataclass(frozen=True)
class ParsedOp:
    base: str
    if_exists: bool
    set_op: str | None  # "ForAnyValue" | "ForAllValues" | None


def parse_operator(name: str) -> ParsedOp:
    set_op = None
    if ":" in name:
        set_op, name = name.split(":", 1)
        if set_op not in ("ForAnyValue", "ForAllValues"):
            raise ConditionError(f"unknown set operator {set_op}")
    if_exists = name.endswith("IfExists") and name != "IfExists"
    base = name[: -len("IfExists")] if if_exists else name
    if base != "Null" and base not in OPERATORS:
        raise ConditionError(f"unsupported condition operator {name}")
    return ParsedOp(base, if_exists, set_op)


def _as_list(v) -> list[str]:
    if isinstance(v, list):
        return [str(x).lower() if isinstance(x, bool) else str(x) for x in v]
    if isinstance(v, bool):
        return [str(v).lower()]
    return [str(v)]


def eval_key(op: ParsedOp, key: str, policy_values, ctx: dict) -> bool:
    present = key.lower() in ctx
    pvals = [substitute(p, ctx) for p in _as_list(policy_values)]
    if op.base == "Null":
        want_absent = pvals[0].lower() == "true"
        return (not present) if want_absent else present
    fn, negated = OPERATORS[op.base]
    if not present:
        if op.set_op == "ForAllValues":
            return True
        return op.if_exists or negated
    cvals = _as_list(ctx[key.lower()])

    def one(cv: str) -> bool:
        hit = any(fn(p, cv) for p in pvals)
        return not hit if negated else hit

    if op.set_op == "ForAllValues":
        return all(one(cv) for cv in cvals)
    if op.set_op == "ForAnyValue":
        return any(one(cv) for cv in cvals)
    if negated:
        return all(one(cv) for cv in cvals)
    return any(one(cv) for cv in cvals)


def eval_conditions(block: dict | None, ctx: dict) -> tuple[bool, list[str]]:
    """Return (all true, explanations). Explanations name each key test and its outcome."""
    if not block:
        return True, []
    notes = []
    ok = True
    for op_name, keys in block.items():
        op = parse_operator(op_name)
        for key, values in keys.items():
            r = eval_key(op, key, values, ctx)
            actual = ctx.get(key.lower(), "(missing)")
            notes.append(f"{op_name} {key} {values!r}: request has {actual!r}, {'true' if r else 'false'}")
            ok = ok and r
    return ok, notes
