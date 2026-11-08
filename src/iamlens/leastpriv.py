"""Least-privilege generation from observed usage, with a proof run through the evaluation engine.

For one principal:
1. Take every action it successfully called in the 90-day window and the resources it called them on.
2. Group by service. Actions that only take Resource "*" stay "*". S3 object ARNs collapse to their prefix
   (`bucket/reports/*`). More than `max_resources` distinct ARNs collapse to their common prefix plus `*`.
3. Keep a buffer: granted but unused actions that match `buffer` patterns (quarterly or yearly jobs a 90-day
   window can miss), only for services the principal already uses.
4. Keep guardrail policies (any identity policy with a Deny statement) as they are.
5. Prove it: re-run every distinct observed request against the new policy set and require Allow; run every
   unused, unbuffered action against probe resources and require Deny.
"""

from __future__ import annotations

import difflib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field

from .catalog import STAR_ONLY, placeholder
from .engine import evaluate
from .matching import action_match, service_of
from .model import Environment, Principal
from .policy import Policy
from .usage import PrincipalUsage, granted_actions

DEFAULT_BUFFER = [
    "kms:EnableKeyRotation",
    "secretsmanager:RotateSecret",
    "iam:UpdateAccessKey",
    "s3:PutLifecycleConfiguration",
    "rds:CreateDBSnapshot",
    "dynamodb:CreateBackup",
    "logs:PutRetentionPolicy",
    "lambda:PublishVersion",
    "s3:ListBucket",
]


@dataclass
class Config:
    max_resources: int = 5
    buffer: list[str] = field(default_factory=lambda: list(DEFAULT_BUFFER))


def _is_object_arn(arn: str) -> bool:
    return arn.startswith("arn:aws:s3:::") and "/" in arn


def _generalize(action: str, resources: set[str], max_resources: int) -> list[str]:
    if action in STAR_ONLY or "*" in resources:
        return ["*"]
    out = set()
    for r in resources:
        if _is_object_arn(r):
            bucket, _, key = r.partition("/")
            prefix = key.rsplit("/", 1)[0] + "/" if "/" in key else ""
            out.add(f"{bucket}/{prefix}*")
        else:
            out.add(r)
    if len(out) > max_resources:
        prefix = _common_prefix(sorted(out))
        cut = max(prefix.rfind("/"), prefix.rfind(":"))
        return [prefix[: cut + 1] + "*"] if cut > 12 else ["*"]
    return sorted(out)


def _common_prefix(items: list[str]) -> str:
    if not items:
        return ""
    a, b = items[0], items[-1]
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    return a[:i]


def _sid(service: str, n: int, tag: str = "") -> str:
    return re.sub(r"[^A-Za-z0-9]", "", service.title()) + tag + str(n)


def guardrails(env: Environment, p: Principal) -> list[Policy]:
    seen, out = set(), []
    for _, pol in env.identity_policies(p):
        if pol.id not in seen and any(s.effect == "Deny" for s in pol.statements):
            seen.add(pol.id)
            out.append(pol)
    return out


def build_policy(env: Environment, p: Principal, cfg: Config | None = None) -> tuple[dict, dict]:
    """Return (policy document, notes) for one principal."""
    cfg = cfg or Config()
    pu = env.usage.get(p.arn, PrincipalUsage())
    used = {a: u for a, u in pu.actions.items() if u.count}
    granted = granted_actions(env, p)
    by_svc: dict[str, dict[str, set[str]]] = defaultdict(dict)
    for a, u in used.items():
        by_svc[service_of(a)][a] = set(u.resources)
    statements = []
    rare = sorted(a for a, u in used.items() if u.count <= 2)
    buffered: list[str] = []
    for svc in sorted(by_svc):
        groups: dict[tuple, list[str]] = defaultdict(list)
        for a, res in sorted(by_svc[svc].items()):
            groups[tuple(_generalize(a, res, cfg.max_resources))].append(a)
        svc_resources = sorted({r for rs in groups for r in rs})
        for i, (res, acts) in enumerate(sorted(groups.items(), key=lambda kv: kv[1]), start=1):
            statements.append(
                {
                    "Sid": _sid(svc, i),
                    "Effect": "Allow",
                    "Action": sorted(acts),
                    "Resource": res[0] if len(res) == 1 else list(res),
                }
            )
        extra = sorted(
            a for a in granted - set(used) if service_of(a) == svc and any(action_match(b, a) for b in cfg.buffer)
        )
        if extra:
            buffered += extra
            star = [a for a in extra if a in STAR_ONLY]
            scoped = [a for a in extra if a not in STAR_ONLY]
            if scoped:
                bucket_level = [r.split("/", 1)[0] if _is_object_arn(r) else r for r in svc_resources if r != "*"]
                res = sorted(set(bucket_level)) or ["*"]
                statements.append(
                    {
                        "Sid": _sid(svc, 1, "Buffer"),
                        "Effect": "Allow",
                        "Action": scoped,
                        "Resource": res[0] if len(res) == 1 else res,
                    }
                )
            if star:
                statements.append({"Sid": _sid(svc, 2, "Buffer"), "Effect": "Allow", "Action": star, "Resource": "*"})
    doc = {"Version": "2012-10-17", "Statement": statements}
    return doc, {"rare_actions": rare, "buffered_actions": buffered}


def _identity_docs(env: Environment, p: Principal, keep: set[str]) -> dict:
    stmts = []
    for src, pol in env.identity_policies(p):
        if pol.id in keep:
            continue
        for s in (
            pol.document["Statement"] if isinstance(pol.document["Statement"], list) else [pol.document["Statement"]]
        ):
            stmts.append({"_from": f"{pol.name} ({src})", **s})
    return {"Version": "2012-10-17", "Statement": stmts}


def suggest(env: Environment, p: Principal | str, cfg: Config | None = None, prove: bool = True) -> dict:
    p = env.principals[p] if isinstance(p, str) else p
    cfg = cfg or Config()
    doc, notes = build_policy(env, p, cfg)
    guards = guardrails(env, p)
    new = Policy.parse(doc, id=f"lp:{p.name}", name="generated least-privilege policy")
    override = [new] + guards
    before = granted_actions(env, p)
    after = granted_actions(env, p, identity_override=override)
    pu = env.usage.get(p.arn, PrincipalUsage())
    result = {
        "principal": p.arn,
        "policy": doc,
        "kept_guardrails": [g.name for g in guards],
        "granted_before": len(before),
        "granted_after": len(after),
        "reduction_pct": round(100 * (1 - len(after) / len(before)), 1) if before else 0.0,
        "used_actions": len(pu.used_actions),
        "rare_actions": notes["rare_actions"],
        "buffered_actions": notes["buffered_actions"],
        "removed_services": sorted({service_of(a) for a in before} - {service_of(a) for a in after}),
        "config": {"max_resources": cfg.max_resources, "buffer": cfg.buffer},
    }
    old_doc = _identity_docs(env, p, {g.id for g in guards})
    result["diff"] = list(
        difflib.unified_diff(
            json.dumps(old_doc, indent=2).splitlines(),
            json.dumps(doc, indent=2).splitlines(),
            "current (allow policies)",
            "suggested",
            lineterm="",
            n=1,
        )
    )
    if prove:
        result["proof"] = prove_policy(env, p, override, before, set(notes["buffered_actions"]))
    return result


def prove_policy(env: Environment, p: Principal, override: list[Policy], before: set[str], buffered: set[str]) -> dict:
    observed = {}
    for e in env.events_for(p.arn):
        if e["res"] != "allowed":
            continue
        ctx = {"aws:SourceIp": e["ip"]}
        if "mfa" in e:
            ctx["aws:MultiFactorAuthPresent"] = "true" if e["mfa"] else "false"
            ctx["aws:ViaAWSService"] = "false"
        observed[(e["a"], e["r"], e.get("mfa"), e["ip"].rsplit(".", 1)[0])] = ctx
    still, broken = 0, []
    for (a, r, _, _), ctx in observed.items():
        if evaluate(env, p, a, r, ctx, identity_override=override).allowed:
            still += 1
        else:
            broken.append({"action": a, "resource": r})
    pu = env.usage.get(p.arn, PrincipalUsage())
    used = pu.used_actions
    seen_res = defaultdict(set)
    for a, u in pu.actions.items():
        for r in u.resources:
            seen_res[service_of(a)].add(r)
    probe_ctx = {"aws:MultiFactorAuthPresent": "true", "aws:SourceIp": "203.0.113.10", "aws:ViaAWSService": "false"}
    unused = sorted(before - used - buffered)
    denied, leaks = 0, []
    for a in unused:
        probes = {placeholder(a, p.account)} | set(sorted(seen_res.get(service_of(a), set()))[:4])
        hit = next(
            (r for r in sorted(probes) if evaluate(env, p, a, r, probe_ctx, identity_override=override).allowed), None
        )
        if hit is None:
            denied += 1
        else:
            leaks.append({"action": a, "resource": hit})
    return {
        "observed_requests": len(observed),
        "observed_still_allowed": still,
        "observed_broken": broken[:20],
        "unused_actions_checked": len(unused),
        "unused_actions_denied": denied,
        "unused_still_allowed": leaks[:20],
        "passed": not broken and not leaks,
    }


def summarize(env: Environment, cfg: Config | None = None) -> dict:
    """Granted actions before and after across every principal with usage. No proof (that runs per principal)."""
    cfg = cfg or Config()
    rows = []
    for p in env.principals.values():
        pu = env.usage.get(p.arn)
        if not pu or not pu.used_actions or p.kind == "breakglass":
            continue
        doc, _ = build_policy(env, p, cfg)
        new = Policy.parse(doc, id=f"lp:{p.name}")
        before = granted_actions(env, p)
        after = granted_actions(env, p, identity_override=[new] + guardrails(env, p))
        rows.append({"principal": p.arn, "kind": p.kind, "before": len(before), "after": len(after)})
    by_kind: dict[str, dict] = {}
    for r in rows:
        k = by_kind.setdefault(r["kind"], {"kind": r["kind"], "principals": 0, "before": 0, "after": 0})
        k["principals"] += 1
        k["before"] += r["before"]
        k["after"] += r["after"]
    tb, ta = sum(r["before"] for r in rows), sum(r["after"] for r in rows)
    return {
        "principals": len(rows),
        "granted_before": tb,
        "granted_after": ta,
        "reduction_pct": round(100 * (1 - ta / tb), 1) if tb else 0.0,
        "by_kind": sorted(by_kind.values(), key=lambda k: -k["before"]),
        "rows": rows,
    }
