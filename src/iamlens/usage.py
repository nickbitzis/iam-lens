"""Granted versus used: what each principal's policies allow, and what the 90 days of logs show it doing."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .catalog import ALL_ACTIONS
from .matching import service_of
from .model import Environment, Principal
from .policy import Policy, Statement


@dataclass
class ActionUse:
    count: int = 0
    last_seen: str = ""
    resources: Counter = field(default_factory=Counter)
    denied: int = 0


@dataclass
class PrincipalUsage:
    actions: dict[str, ActionUse] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    events: int = 0
    denied: int = 0

    @property
    def used_actions(self) -> set[str]:
        return {a for a, u in self.actions.items() if u.count}


def build_usage(env: Environment) -> dict[str, PrincipalUsage]:
    out: dict[str, PrincipalUsage] = defaultdict(PrincipalUsage)
    canon = {a.lower(): a for a in ALL_ACTIONS}
    for e in env.events:
        pu = out[e["p"]]
        action = canon.get(e["a"].lower(), e["a"])
        au = pu.actions.setdefault(action, ActionUse())
        pu.events += 1
        day = e["t"][:10]
        pu.first_seen = pu.first_seen or day
        pu.last_seen = day
        if e["res"] == "allowed":
            au.count += 1
            au.last_seen = day
            au.resources[e["r"]] += 1
        else:
            au.denied += 1
            pu.denied += 1
    return dict(out)


def _unconditional_deny(s: Statement, action: str) -> bool:
    return s.effect == "Deny" and not s.condition and s.resources == ["*"] and s.matches_action(action)


def _any_allow(policies: list[Policy], action: str) -> bool:
    return any(s.effect == "Allow" and s.matches_action(action) for pol in policies for s in pol.statements)


def granted_actions(env: Environment, p: Principal, identity_override: list[Policy] | None = None) -> set[str]:
    """Catalog actions the principal's identity policies grant on at least some resource, after SCPs and the
    permissions boundary. Conditions and resource scoping are ignored on Allow statements (so this is an upper
    bound) and only unconditional Deny on every resource removes an action."""
    identity = identity_override if identity_override is not None else [pol for _, pol in env.identity_policies(p)]
    levels = [pols for _, pols in env.scp_levels(p.account)]
    boundary = env.boundary(p)
    every = identity + [x for lv in levels for x in lv] + ([boundary] if boundary else [])
    out = set()
    for a in ALL_ACTIONS:
        if not _any_allow(identity, a):
            continue
        if any(not _any_allow(lv, a) for lv in levels):
            continue
        if boundary and not _any_allow([boundary], a):
            continue
        if any(_unconditional_deny(s, a) for pol in every for s in pol.statements):
            continue
        out.add(a)
    return out


def by_service(actions: set[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for a in actions:
        out[service_of(a)].add(a)
    return dict(out)


def usage_summary(env: Environment, p: Principal) -> dict:
    granted = granted_actions(env, p)
    pu = env.usage.get(p.arn, PrincipalUsage())
    used = pu.used_actions
    g_svc, u_svc = by_service(granted), by_service(used)
    services = []
    for svc in sorted(set(g_svc) | set(u_svc)):
        g, u = g_svc.get(svc, set()), u_svc.get(svc, set())
        services.append(
            {
                "service": svc,
                "granted": len(g),
                "used": len(u & g) if g else len(u),
                "unused": sorted(g - u),
                "used_actions": sorted(u),
            }
        )
    return {
        "granted": len(granted),
        "used": len(used & granted),
        "used_outside_grant": sorted(used - granted),
        "unused": len(granted - used),
        "services_granted": len(g_svc),
        "services_used": len(set(u_svc) & set(g_svc)),
        "services_unused": sorted(set(g_svc) - set(u_svc)),
        "events": pu.events,
        "denied": pu.denied,
        "last_seen": pu.last_seen or None,
        "services": services,
    }
