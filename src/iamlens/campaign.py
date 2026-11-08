"""Access review campaigns: managers keep or revoke each report's entitlements, with usage-based suggestions,
deadlines, escalation up the management chain, and a tamper-evident evidence export for auditors."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import threading
from datetime import date, timedelta
from pathlib import Path

from .model import Environment, Principal
from .usage import PrincipalUsage, granted_actions

DECISIONS = ("keep", "revoke")


class CampaignError(ValueError):
    pass


class NotReviewer(PermissionError):
    pass


def _entitlements(env: Environment, p: Principal) -> list[dict]:
    out = [{"type": "group", "name": g, "policies": env.groups[g]["policies"]} for g in p.groups]
    out += [{"type": "policy", "name": pid, "policies": [pid]} for pid in p.policies]
    out += [
        {"type": "access_key", "name": k["id"], "created": k["created"], "last_used": k["last_used"]}
        for k in p.access_keys
        if k["status"] == "Active"
    ]
    return out


def _suggest(env: Environment, p: Principal, ent: dict, today: date) -> tuple[str, str, dict]:
    pu = env.usage.get(p.arn, PrincipalUsage())
    if ent["type"] == "access_key":
        idle = (today - date.fromisoformat(ent["last_used"])).days
        age = (today - date.fromisoformat(ent["created"])).days
        if idle > 90:
            return "revoke", f"Key unused for {idle} days.", {"idle_days": idle, "age_days": age}
        return (
            "keep",
            f"Key used {idle} days ago ({age} days old, rotate if over 90).",
            {"idle_days": idle, "age_days": age},
        )
    pols = [env.policies[pid] for pid in ent["policies"]]
    if any(s.effect == "Deny" for pol in pols for s in pol.statements) and all(
        all(s.effect == "Deny" or not s.resources or "${aws:username}" in "".join(s.resources) for s in pol.statements)
        for pol in pols
    ):
        return "keep", "Guardrail (deny or self-service only). Keep.", {"guardrail": True}
    granted = granted_actions(env, p, identity_override=pols)
    used = {a for a in pu.used_actions if a in granted}
    last = max((pu.actions[a].last_seen for a in used), default=None)
    ev = {"granted_actions": len(granted), "used_actions": len(used), "last_used": last, "examples": sorted(used)[:5]}
    if not pu.events:
        return "revoke", "No activity at all in 90 days.", ev
    if not used:
        return "revoke", f"None of the {len(granted)} actions it grants were used in 90 days.", ev
    return "keep", f"Used {len(used)} of {len(granted)} actions it grants, last on {last}.", ev


def _hash(prev: str, row: dict) -> str:
    return hashlib.sha256((prev + json.dumps(row, sort_keys=True, default=str)).encode()).hexdigest()


class CampaignStore:
    """Campaign state in memory with an optional JSON file. Dates are passed in so tests control time."""

    def __init__(self, env: Environment, path: Path | None = None):
        self.env = env
        self.path = path
        self.lock = threading.Lock()
        self.campaigns: dict[str, dict] = {}
        if path and path.exists():
            self.campaigns = json.loads(path.read_text())

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.campaigns, indent=1))
            tmp.replace(self.path)

    def create(
        self, name: str, created: date, deadline: date, escalate_after_days: int = 3, managers: list[str] | None = None
    ) -> dict:
        if deadline <= created:
            raise CampaignError("deadline must be after the start date")
        env = self.env
        items = []
        for p in sorted(env.principals.values(), key=lambda x: x.arn):
            if p.kind != "human" or not p.manager or p.manager not in env.principals:
                continue
            if managers and p.manager not in managers:
                continue
            for ent in _entitlements(env, p):
                sug, why, ev = _suggest(env, p, ent, created)
                n = len(items) + 1
                items.append(
                    {
                        "id": f"I-{n:04d}",
                        "user": p.arn,
                        "user_name": p.display_name or p.name,
                        "team": p.team,
                        "entitlement": {k: v for k, v in ent.items() if k != "policies"},
                        "policies": ent.get("policies", []),
                        "reviewer": p.manager,
                        "original_reviewer": p.manager,
                        "due": deadline.isoformat(),
                        "status": "pending",
                        "suggestion": sug,
                        "suggestion_reason": why,
                        "evidence": ev,
                        "decision": None,
                        "decided_by": None,
                        "decided_at": None,
                        "comment": "",
                        "escalations": [],
                    }
                )
        if not items:
            raise CampaignError("no review items in scope")
        with self.lock:
            cid = f"C-{len(self.campaigns) + 1:03d}"
            c = {
                "id": cid,
                "name": name,
                "created": created.isoformat(),
                "deadline": deadline.isoformat(),
                "escalate_after_days": escalate_after_days,
                "status": "open",
                "items": items,
                "log": [],
            }
            c["log"].append({"at": created.isoformat(), "event": "created", "items": len(items)})
            self.campaigns[cid] = c
            self._save()
        return c

    def get(self, cid: str) -> dict:
        if cid not in self.campaigns:
            raise KeyError(cid)
        return self.campaigns[cid]

    def decide(self, cid: str, item_id: str, reviewer: str, decision: str, now: date, comment: str = "") -> dict:
        if decision not in DECISIONS:
            raise CampaignError(f"decision must be one of {DECISIONS}")
        with self.lock:
            c = self.get(cid)
            if c["status"] == "closed":
                raise CampaignError("campaign is closed")
            item = next((i for i in c["items"] if i["id"] == item_id), None)
            if item is None:
                raise KeyError(item_id)
            if item["reviewer"] != reviewer:
                raise NotReviewer(f"{reviewer} is not the current reviewer for {item_id}")
            if item["decision"] is not None:
                raise CampaignError(f"{item_id} already decided")
            if decision != item["suggestion"] and not comment.strip():
                raise CampaignError("a comment is required when overriding the suggestion")
            item.update(
                decision=decision, decided_by=reviewer, decided_at=now.isoformat(), comment=comment, status="decided"
            )
            c["log"].append(
                {"at": now.isoformat(), "event": "decided", "item": item_id, "by": reviewer, "decision": decision}
            )
            if all(i["decision"] for i in c["items"]):
                c["status"] = "closed"
                c["log"].append({"at": now.isoformat(), "event": "closed"})
            self._save()
            return item

    def escalate(self, cid: str, now: date) -> list[dict]:
        """Move overdue pending items to the reviewer's manager, with a new due date."""
        moved = []
        with self.lock:
            c = self.get(cid)
            for item in c["items"]:
                if item["decision"] is not None or date.fromisoformat(item["due"]) >= now:
                    continue
                cur = self.env.principals.get(item["reviewer"])
                nxt = cur.manager if cur else None
                if not nxt:
                    continue
                item["escalations"].append({"at": now.isoformat(), "from": item["reviewer"], "to": nxt})
                item["reviewer"] = nxt
                item["status"] = "escalated"
                item["due"] = (now + timedelta(days=c["escalate_after_days"])).isoformat()
                moved.append(item)
            if moved:
                c["log"].append({"at": now.isoformat(), "event": "escalated", "items": len(moved)})
            self._save()
        return moved

    def status(self, cid: str, now: date) -> dict:
        c = self.get(cid)
        items = c["items"]
        overdue = [i for i in items if i["decision"] is None and date.fromisoformat(i["due"]) < now]
        by_rev: dict[str, dict] = {}
        for i in items:
            r = by_rev.setdefault(i["reviewer"], {"reviewer": i["reviewer"], "pending": 0, "decided": 0})
            r["decided" if i["decision"] else "pending"] += 1
        for r in by_rev.values():
            p = self.env.principals.get(r["reviewer"])
            r["name"] = (p.display_name or p.name) if p else r["reviewer"]
        return {
            "id": c["id"],
            "name": c["name"],
            "status": c["status"],
            "created": c["created"],
            "deadline": c["deadline"],
            "items": len(items),
            "decided": sum(1 for i in items if i["decision"]),
            "pending": sum(1 for i in items if not i["decision"]),
            "overdue": len(overdue),
            "escalated": sum(1 for i in items if i["escalations"]),
            "suggested_revoke": sum(1 for i in items if i["suggestion"] == "revoke"),
            "revoked": sum(1 for i in items if i["decision"] == "revoke"),
            "overrides": sum(1 for i in items if i["decision"] and i["decision"] != i["suggestion"]),
            "reviewers": sorted(by_rev.values(), key=lambda r: -r["pending"]),
        }

    def evidence(self, cid: str, now: date, fmt: str = "json") -> str:
        c = self.get(cid)
        rows, prev = [], "0" * 64
        for i in c["items"]:
            row = {
                "item": i["id"],
                "user": i["user"],
                "user_name": i["user_name"],
                "entitlement_type": i["entitlement"]["type"],
                "entitlement": i["entitlement"]["name"],
                "suggestion": i["suggestion"],
                "suggestion_reason": i["suggestion_reason"],
                "decision": i["decision"] or "",
                "decided_by": i["decided_by"] or "",
                "decided_at": i["decided_at"] or "",
                "comment": i["comment"],
                "original_reviewer": i["original_reviewer"],
                "escalated_to": " > ".join(e["to"] for e in i["escalations"]),
                "used_actions": i["evidence"].get("used_actions", ""),
                "last_used": i["evidence"].get("last_used") or "",
            }
            prev = _hash(prev, row)
            row["chain_hash"] = prev
            rows.append(row)
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
            return buf.getvalue()
        doc = {
            "campaign": {k: c[k] for k in ("id", "name", "created", "deadline", "status")},
            "exported": now.isoformat(),
            "summary": self.status(cid, now),
            "log": c["log"],
            "items": rows,
            "integrity": {"algorithm": "sha256 chain over items in order", "head": prev},
        }
        return json.dumps(doc, indent=2)


def verify_chain(items: list[dict]) -> bool:
    prev = "0" * 64
    for row in items:
        body = {k: v for k, v in row.items() if k != "chain_hash"}
        prev = _hash(prev, body)
        if row["chain_hash"] != prev:
            return False
    return True
