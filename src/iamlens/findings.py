"""Findings over the whole environment."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date

from .catalog import PERMISSIONS_MANAGEMENT
from .engine import is_allowed
from .escalation import ADMIN, EscalationGraph
from .model import Environment, Principal
from .usage import PrincipalUsage, granted_actions

SEVERITIES = ["critical", "high", "medium", "low"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
WRITE_HINTS = ("Put", "Delete", "Create", "Update", "Attach", "*", "Encrypt", "Decrypt", "Upload", "Restore")
LIMITING_KEYS = {
    "aws:principalorgid",
    "aws:principalaccount",
    "aws:sourceip",
    "aws:sourcevpce",
    "aws:sourcevpc",
    "aws:principalarn",
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:principalorgpaths",
}

TYPES = {
    "wildcard_admin": "Wildcard admin access",
    "unused_permissions": "Unused permissions",
    "unused_principal": "Unused principal",
    "external_trust_without_external_id": "External account trust without an external ID",
    "public_resource_policy": "Public resource policy",
    "privilege_escalation": "Privilege escalation path",
    "mfa_not_enforced": "MFA not enforced for a console user",
    "long_lived_access_key": "Long-lived access key",
}


@dataclass
class Finding:
    type: str
    severity: str
    subject: str  # principal or resource ARN
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return "F-" + hashlib.sha256(f"{self.type}|{self.subject}".encode()).hexdigest()[:10]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "type_label": TYPES[self.type],
            "severity": self.severity,
            "subject": self.subject,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def has_star_statement(env: Environment, p: Principal) -> list[str]:
    out = []
    for src, pol in env.identity_policies(p):
        for s in pol.statements:
            if s.effect == "Allow" and "*" in s.actions and "*" in (s.resources or ["*"]) and not s.condition:
                out.append(f"{pol.name} ({src})")
    return out


def public_statements(policy) -> list[dict]:
    """Allow statements open to any principal with no condition that limits who can call."""
    out = []
    for s in policy.statements:
        if s.effect != "Allow" or s.principal is None or not s.principal.wildcard:
            continue
        keys = {k.lower() for block in s.condition.values() for k in block}
        if keys & LIMITING_KEYS:
            continue
        out.append(
            {
                "sid": s.label,
                "actions": s.actions or [f"NotAction {s.not_actions}"],
                "write": any(any(h in a for h in WRITE_HINTS) for a in (s.actions or ["*"])),
            }
        )
    return out


def trust_findings(env: Environment, p: Principal) -> list[dict]:
    out = []
    if p.trust is None:
        return out
    for s in p.trust.statements:
        if s.effect != "Allow" or s.principal is None:
            continue
        external = [a for a in s.principal.accounts() if a not in env.accounts and a != env.management_account]
        if not external and not s.principal.wildcard:
            continue
        keys = {k.lower() for block in s.condition.values() for k in block}
        if "sts:externalid" in keys or "aws:principalorgid" in keys:
            continue
        out.append({"sid": s.label, "accounts": external or ["*"], "names": [env.account_name(a) for a in external]})
    return out


def analyze(env: Environment, graph: EscalationGraph | None = None) -> list[Finding]:
    graph = graph or EscalationGraph(env)
    usage: dict[str, PrincipalUsage] = env.usage
    today = env.as_of
    out: list[Finding] = []
    paths = graph.all_paths()

    for p in env.principals.values():
        pu = usage.get(p.arn)
        used = pu.used_actions if pu else set()
        stars = has_star_statement(env, p)
        if stars and p.arn in graph.admins:
            sev = "medium" if p.kind == "breakglass" else "critical"
            note = (
                " Expected for break-glass: keep the trust MFA condition and alert on every use."
                if p.kind == "breakglass"
                else ""
            )
            out.append(
                Finding(
                    "wildcard_admin",
                    sev,
                    p.arn,
                    f"{_short(p.arn)} has Action * on Resource *",
                    f"Granted by {', '.join(stars)}. {len(used)} distinct actions used in 90 days.{note}",
                    {"policies": stars, "used_actions": len(used)},
                )
            )

        if pu is None or not used:
            if p.kind != "breakglass":
                active_keys = [k for k in p.access_keys if k["status"] == "Active"]
                sev = "medium" if p.kind in ("human", "vendor") or active_keys else "low"
                out.append(
                    Finding(
                        "unused_principal",
                        sev,
                        p.arn,
                        f"{_short(p.arn)} made no successful calls in 90 days",
                        f"{p.kind} {p.type} created {p.created}. "
                        + (f"{len(active_keys)} active access key(s). " if active_keys else "")
                        + ("Console password set. " if p.console else "")
                        + "Candidate for removal.",
                        {"kind": p.kind, "active_keys": len(active_keys), "console": p.console},
                    )
                )
        else:
            granted = granted_actions(env, p)
            unused = granted - used
            if granted and len(unused) >= 10 and len(unused) / len(granted) >= 0.5:
                perm = sorted(unused & PERMISSIONS_MANAGEMENT)
                sev = "high" if len(perm) >= 5 else "medium"
                services = sorted({a.split(":")[0] for a in granted} - {a.split(":")[0] for a in used})
                out.append(
                    Finding(
                        "unused_permissions",
                        sev,
                        p.arn,
                        f"{_short(p.arn)} uses {len(used & granted)} of {len(granted)} granted actions",
                        f"{len(unused)} granted actions unused in 90 days ({len(unused) * 100 // len(granted)}%), "
                        f"including {len(services)} service{'s' if len(services) != 1 else ''} never called"
                        + (
                            f" and {len(perm)} permission-management action{'s' if len(perm) != 1 else ''}."
                            if perm
                            else "."
                        ),
                        {
                            "granted": len(granted),
                            "used": len(used & granted),
                            "unused": len(unused),
                            "unused_services": services,
                            "unused_permission_actions": perm[:20],
                        },
                    )
                )

        for t in trust_findings(env, p):
            out.append(
                Finding(
                    "external_trust_without_external_id",
                    "high",
                    p.arn,
                    f"{_short(p.arn)} is assumable by {', '.join(t['accounts'])} without sts:ExternalId",
                    f"Trust statement {t['sid']} accepts {', '.join(t['names']) or 'any account'}. Without an "
                    "external ID condition, anyone the vendor acts for can make the vendor assume this role "
                    "(the confused deputy problem).",
                    t,
                )
            )

        if p.arn in paths:
            path = paths[p.arn]
            steps = [e.to_dict() for e in path]
            end = path[-1].dst
            target = "admin" if end == ADMIN else _short(end)
            out.append(
                Finding(
                    "privilege_escalation",
                    "critical" if len(path) == 1 else "high",
                    p.arn,
                    f"{_short(p.arn)} can reach admin in {len(path)} step{'s' if len(path) > 1 else ''}",
                    " then ".join(f"{e.kind} via {e.action} on {_short(e.resource)}" for e in path)
                    + f", ending at {target}.",
                    {"path": steps},
                )
            )

        if p.type == "user" and p.kind == "human" and p.console:
            probe = None
            if pu:
                best = sorted(
                    ((u.count, a, u.resources.most_common(1)[0][0]) for a, u in pu.actions.items() if u.count),
                    reverse=True,
                )
                probe = (best[0][1], best[0][2]) if best else None
            if probe:
                ctx = {
                    "aws:MultiFactorAuthPresent": "false",
                    "aws:SourceIp": "203.0.113.10",
                    "aws:ViaAWSService": "false",
                }
                if is_allowed(env, p, probe[0], probe[1], ctx):
                    sev = "high" if not p.mfa else "medium"
                    out.append(
                        Finding(
                            "mfa_not_enforced",
                            sev,
                            p.arn,
                            f"{_short(p.arn)} can work without MFA",
                            f"Simulated {probe[0]} on {_short(probe[1])} with aws:MultiFactorAuthPresent "
                            f"false: allowed. MFA device registered: {'yes' if p.mfa else 'no'}. No policy "
                            "denies requests without MFA.",
                            {"probe_action": probe[0], "probe_resource": probe[1], "mfa_device": p.mfa},
                        )
                    )

        for k in p.access_keys:
            if k["status"] != "Active":
                continue
            age = (today - date.fromisoformat(k["created"])).days
            if age <= 90:
                continue
            idle = (today - date.fromisoformat(k["last_used"])).days
            sev = "high" if age > 365 else "medium"
            out.append(
                Finding(
                    "long_lived_access_key",
                    sev,
                    p.arn,
                    f"{_short(p.arn)} has a {age}-day-old access key",
                    f"Key {k['id']} created {k['created']}, last used {k['last_used']} ({idle} days ago). "
                    "Rotate at 90 days or move the workload to a role.",
                    {"key_id": k["id"], "age_days": age, "idle_days": idle},
                )
            )

    for r in env.resources.values():
        if r.policy is None:
            continue
        pub = public_statements(r.policy)
        if pub:
            write = any(s["write"] for s in pub) or r.type == "kms_key"
            out.append(
                Finding(
                    "public_resource_policy",
                    "critical" if write else "high",
                    r.arn,
                    f"{r.name} ({r.type}) is open to any principal",
                    f"Statement {', '.join(s['sid'] for s in pub)} allows "
                    f"{', '.join(a for s in pub for a in s['actions'])} to Principal * with no limiting "
                    "condition (aws:PrincipalOrgID, aws:SourceIp, aws:SourceVpce).",
                    {"statements": pub, "resource_type": r.type},
                )
            )

    out.sort(key=lambda f: (SEV_RANK[f.severity], f.type, f.subject))
    return out
