"""The environment: organization, accounts, policies, principals, resources, and access logs."""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .matching import account_of, split_arn
from .policy import Policy


@dataclass
class Principal:
    arn: str
    name: str
    type: str  # user | role
    account: str
    kind: str  # human | service | ci | breakglass | vendor | audit | automation
    team: str = ""
    display_name: str = ""
    groups: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    boundary: str | None = None
    trust: Policy | None = None
    manager: str | None = None
    console: bool = False
    mfa: bool = False
    access_keys: list[dict] = field(default_factory=list)
    created: str = ""
    tags: dict = field(default_factory=dict)
    title: str = ""

    def summary(self) -> dict:
        return {
            "arn": self.arn,
            "name": self.name,
            "type": self.type,
            "account": self.account,
            "kind": self.kind,
            "team": self.team,
            "display_name": self.display_name,
        }


@dataclass
class Resource:
    arn: str
    type: str  # s3_bucket | kms_key | lambda_function | dynamodb_table | sqs_queue | secret
    account: str
    name: str
    policy: Policy | None = None
    role: str | None = None  # execution role of a function


@dataclass
class OrgNode:
    id: str
    name: str
    parent: str | None
    scps: list[str]


class Environment:
    def __init__(self, data: dict, events: list[dict] | None = None):
        self.raw = data
        self.company = data["company"]
        self.as_of = date.fromisoformat(data["as_of"])
        org = data["organization"]
        self.org_id = org["id"]
        self.management_account = org["management_account"]
        self.nodes: dict[str, OrgNode] = {}
        for n in org["nodes"]:
            self.nodes[n["id"]] = OrgNode(n["id"], n["name"], n.get("parent"), n.get("scps", []))
        self.accounts: dict[str, dict] = {a["id"]: a for a in data["accounts"]}
        self.external_accounts: dict[str, dict] = {a["id"]: a for a in data.get("external_accounts", [])}
        self.policies: dict[str, Policy] = {}
        for pid, p in data["policies"].items():
            self.policies[pid] = Policy.parse(
                p["document"], id=pid, name=p.get("name", pid), kind=p.get("kind", "managed")
            )
        self.groups: dict[str, dict] = {g["name"]: g for g in data.get("groups", [])}
        self.principals: dict[str, Principal] = {}
        for p in data["principals"]:
            trust = (
                Policy.parse(p["trust_policy"], id=f"trust:{p['name']}", name=f"{p['name']} trust policy", kind="trust")
                if p.get("trust_policy")
                else None
            )
            self.principals[p["arn"]] = Principal(
                arn=p["arn"],
                name=p["name"],
                type=p["type"],
                account=p["account"],
                kind=p["kind"],
                team=p.get("team", ""),
                display_name=p.get("display_name", ""),
                groups=p.get("groups", []),
                policies=p.get("policies", []),
                boundary=p.get("boundary"),
                trust=trust,
                manager=p.get("manager"),
                console=p.get("console", False),
                mfa=p.get("mfa", False),
                access_keys=p.get("access_keys", []),
                created=p.get("created", ""),
                tags=p.get("tags", {}),
                title=p.get("title", ""),
            )
        self.resources: dict[str, Resource] = {}
        for r in data.get("resources", []):
            pol = (
                Policy.parse(r["policy"], id=f"rp:{r['name']}", name=f"{r['name']} resource policy", kind="resource")
                if r.get("policy")
                else None
            )
            self.resources[r["arn"]] = Resource(r["arn"], r["type"], r["account"], r["name"], pol, r.get("role"))
        self.events: list[dict] = events or []
        self._usage = None
        self._by_principal: dict[str, list[dict]] | None = None

    def events_for(self, arn: str) -> list[dict]:
        if self._by_principal is None:
            idx: dict[str, list[dict]] = {}
            for e in self.events:
                idx.setdefault(e["p"], []).append(e)
            self._by_principal = idx
        return self._by_principal.get(arn, [])

    # ---- organization ----
    def in_org(self, account: str) -> bool:
        return account in self.accounts

    def scp_levels(self, account: str) -> list[tuple[str, list[Policy]]]:
        """SCPs from the root down to the account. Empty for the management account and outside accounts."""
        if account == self.management_account or account not in self.accounts:
            return []
        chain = []
        acct = self.accounts[account]
        chain.append((f"account {acct['name']}", [self.policies[s] for s in acct.get("scps", [])]))
        node = self.nodes.get(acct["parent"])
        while node is not None:
            chain.append(
                (f"{'root' if node.parent is None else 'OU'} {node.name}", [self.policies[s] for s in node.scps])
            )
            node = self.nodes.get(node.parent) if node.parent else None
        return list(reversed(chain))

    def ou_path(self, account: str) -> list[str]:
        acct = self.accounts.get(account)
        if not acct:
            return []
        out = []
        node = self.nodes.get(acct["parent"])
        while node is not None:
            out.append(node.name)
            node = self.nodes.get(node.parent) if node.parent else None
        return list(reversed(out))

    # ---- identities ----
    def identity_policies(self, p: Principal) -> list[tuple[str, Policy]]:
        out = [("attached", self.policies[pid]) for pid in p.policies]
        for g in p.groups:
            for pid in self.groups[g]["policies"]:
                out.append((f"group {g}", self.policies[pid]))
        return out

    def boundary(self, p: Principal) -> Policy | None:
        return self.policies[p.boundary] if p.boundary else None

    def account_name(self, acct: str) -> str:
        if acct in self.accounts:
            return self.accounts[acct]["name"]
        if acct in self.external_accounts:
            return self.external_accounts[acct]["name"]
        return "unknown account"

    # ---- resources ----
    def find_resource(self, arn: str) -> Resource | None:
        if arn in self.resources:
            return self.resources[arn]
        if arn.startswith("arn:aws:s3:::") and "/" in arn:
            return self.resources.get(arn.split("/", 1)[0])
        return None

    def resource_account(self, arn: str) -> str | None:
        if arn in self.principals:
            return self.principals[arn].account
        r = self.find_resource(arn)
        if r:
            return r.account
        acct = account_of(arn)
        return acct

    def resource_policy(self, arn: str, action: str) -> tuple[str | None, Policy | None]:
        """The resource-based policy that governs this request, and its kind (trust, key, bucket, ...)."""
        if arn in self.principals and action.lower().startswith("sts:assumerole"):
            p = self.principals[arn]
            return "trust", p.trust
        r = self.find_resource(arn)
        if r is not None:
            return r.type, r.policy
        parts = split_arn(arn)
        if parts and parts[2] == "kms":
            return "kms_key", None
        return None, None

    # ---- usage ----
    @property
    def usage(self):
        if self._usage is None:
            from .usage import build_usage

            self._usage = build_usage(self)
        return self._usage


def load_environment(path: Path | str) -> Environment:
    path = Path(path)
    data = json.loads((path / "environment.json").read_text())
    events: list[dict] = []
    log = path / "access_logs.jsonl.gz"
    if log.exists():
        with gzip.open(log, "rt") as f:
            events = [json.loads(line) for line in f if line.strip()]
    return Environment(data, events)
