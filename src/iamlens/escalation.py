"""Privilege escalation paths: a graph of "principal A can become principal B" edges, searched for admin.

Edges (each one checked with the evaluation engine, so SCPs, boundaries, and denies cut them):
- self-attach: change your own policies (Attach/Put User or Role Policy, CreatePolicyVersion on an attached
  policy, AddUserToGroup into an admin group). Leads straight to admin.
- assume: sts:AssumeRole into a role whose trust policy accepts you.
- pass-role: iam:PassRole on a role that trusts lambda.amazonaws.com, plus lambda:CreateFunction and
  lambda:InvokeFunction (or ec2.amazonaws.com plus ec2:RunInstances).
- update-function: lambda:UpdateFunctionCode on a function, which runs as its execution role.
- update-trust: iam:UpdateAssumeRolePolicy on a role, then assume it.
- user-takeover: iam:CreateAccessKey, iam:CreateLoginProfile, or iam:UpdateLoginProfile on another user.

The attacker context assumes MFA and a corporate IP, so conditions that only demand those do not stop a path.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from functools import cached_property

from .catalog import placeholder
from .engine import is_allowed
from .model import Environment, Principal
from .policy import Caller, principal_match

ATTACK_CTX = {"aws:MultiFactorAuthPresent": "true", "aws:SourceIp": "203.0.113.10", "aws:ViaAWSService": "false"}
ADMIN = "ADMIN"
ADMIN_PROBES = [
    "iam:AttachRolePolicy",
    "s3:DeleteBucket",
    "ec2:TerminateInstances",
    "secretsmanager:DeleteSecret",
    "dynamodb:DeleteTable",
]
ESCALATION_ACTIONS = [
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:AddUserToGroup",
    "iam:PassRole",
    "lambda:UpdateFunctionCode",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
]


@dataclass
class Edge:
    src: str
    dst: str  # principal ARN or ADMIN
    kind: str
    action: str
    resource: str

    def to_dict(self) -> dict:
        return {"from": self.src, "to": self.dst, "kind": self.kind, "action": self.action, "resource": self.resource}


class EscalationGraph:
    def __init__(self, env: Environment):
        self.env = env
        self.edges: dict[str, list[Edge]] = {}
        self._build()

    def can(self, p: Principal, action: str, resource: str) -> bool:
        return is_allowed(self.env, p, action, resource, ATTACK_CTX)

    def is_admin(self, p: Principal) -> bool:
        return all(
            self.can(
                p,
                a,
                placeholder(a, p.account)
                if a != "iam:AttachRolePolicy"
                else f"arn:aws:iam::{p.account}:role/iamlens-probe",
            )
            for a in ADMIN_PROBES
        )

    @cached_property
    def admins(self) -> set[str]:
        return {arn for arn, p in self.env.principals.items() if self.is_admin(p)}

    def _maybe(self, p: Principal) -> set[str]:
        """Escalation actions any identity Allow statement mentions, a cheap filter before the engine runs."""
        out = set()
        for _, pol in self.env.identity_policies(p):
            for s in pol.statements:
                if s.effect == "Allow":
                    out |= {a for a in ESCALATION_ACTIONS if s.matches_action(a)}
        return out

    def _build(self) -> None:
        env = self.env
        roles = [p for p in env.principals.values() if p.type == "role"]
        users = [p for p in env.principals.values() if p.type == "user"]
        admin_groups = {
            g
            for g, info in env.groups.items()
            if any(
                any(
                    s.effect == "Allow" and s.matches_action("iam:CreateUser") and "*" in s.resources
                    for s in env.policies[pid].statements
                )
                for pid in info["policies"]
            )
        }
        functions = [r for r in env.resources.values() if r.type == "lambda_function" and r.role]
        for p in env.principals.values():
            if p.arn in self.admins:
                continue
            out: list[Edge] = []
            maybe = self._maybe(p)
            acct = p.account
            # self-attach
            if p.type == "user":
                for a in ("iam:AttachUserPolicy", "iam:PutUserPolicy"):
                    if a in maybe and self.can(p, a, p.arn):
                        out.append(Edge(p.arn, ADMIN, "self-attach", a, p.arn))
                        break
                if "iam:AddUserToGroup" in maybe:
                    for g in sorted(admin_groups):
                        garn = f"arn:aws:iam::{acct}:group/{g}"
                        if self.can(p, "iam:AddUserToGroup", garn):
                            out.append(Edge(p.arn, ADMIN, "self-attach", "iam:AddUserToGroup", garn))
                            break
            else:
                for a in ("iam:AttachRolePolicy", "iam:PutRolePolicy"):
                    if a in maybe and self.can(p, a, p.arn):
                        out.append(Edge(p.arn, ADMIN, "self-attach", a, p.arn))
                        break
            if "iam:CreatePolicyVersion" in maybe:
                for _, pol in env.identity_policies(p):
                    parn = f"arn:aws:iam::{acct}:policy/{pol.id}"
                    if env.raw["policies"][pol.id].get("account") == acct and self.can(
                        p, "iam:CreatePolicyVersion", parn
                    ):
                        out.append(Edge(p.arn, ADMIN, "self-attach", "iam:CreatePolicyVersion", parn))
                        break
            # assume
            caller = Caller(p.arn, p.account)
            for r in roles:
                if r.arn == p.arn or r.trust is None:
                    continue
                trusts = any(
                    s.effect == "Allow" and s.principal and principal_match(s.principal, caller)
                    for s in r.trust.statements
                )
                if trusts and self.can(p, "sts:AssumeRole", r.arn):
                    out.append(Edge(p.arn, r.arn, "assume", "sts:AssumeRole", r.arn))
            same = [r for r in roles if r.account == acct and r.arn != p.arn]
            if "iam:PassRole" in maybe:
                fn = placeholder("lambda:CreateFunction", acct)
                lam = self.can(p, "lambda:CreateFunction", fn) and self.can(p, "lambda:InvokeFunction", fn)
                ec2 = self.can(p, "ec2:RunInstances", "*")
                for r in same:
                    svcs = (
                        {svc for s in r.trust.statements if s.principal for svc in s.principal.service}
                        if r.trust
                        else set()
                    )
                    via = (
                        "lambda"
                        if lam and "lambda.amazonaws.com" in svcs
                        else "ec2"
                        if ec2 and "ec2.amazonaws.com" in svcs
                        else None
                    )
                    if via and self.can(p, "iam:PassRole", r.arn):
                        out.append(Edge(p.arn, r.arn, f"pass-role ({via})", "iam:PassRole", r.arn))
            if "lambda:UpdateFunctionCode" in maybe:
                for f in functions:
                    if f.account == acct and f.role != p.arn and self.can(p, "lambda:UpdateFunctionCode", f.arn):
                        out.append(Edge(p.arn, f.role, "update-function", "lambda:UpdateFunctionCode", f.arn))
            if "iam:UpdateAssumeRolePolicy" in maybe:
                for r in same:
                    if self.can(p, "iam:UpdateAssumeRolePolicy", r.arn):
                        out.append(Edge(p.arn, r.arn, "update-trust", "iam:UpdateAssumeRolePolicy", r.arn))
            if maybe & {"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"}:
                for u in users:
                    if u.account != acct or u.arn == p.arn:
                        continue
                    for a in ("iam:CreateAccessKey", "iam:UpdateLoginProfile", "iam:CreateLoginProfile"):
                        if a in maybe and self.can(p, a, u.arn):
                            out.append(Edge(p.arn, u.arn, "user-takeover", a, u.arn))
                            break
            if out:
                self.edges[p.arn] = out

    def shortest_path(self, start: str) -> list[Edge] | None:
        if start in self.admins:
            return None
        prev: dict[str, Edge] = {}
        seen = {start}
        q = deque([start])
        while q:
            cur = q.popleft()
            for e in self.edges.get(cur, []):
                if e.dst in seen:
                    continue
                prev[e.dst] = e
                if e.dst == ADMIN or e.dst in self.admins:
                    path = [e]
                    while path[0].src != start:
                        path.insert(0, prev[path[0].src])
                    return path
                seen.add(e.dst)
                q.append(e.dst)
        return None

    def all_paths(self) -> dict[str, list[Edge]]:
        out = {}
        for arn in self.env.principals:
            path = self.shortest_path(arn)
            if path:
                out[arn] = path
        return out
