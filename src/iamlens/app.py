"""FastAPI service: findings, principal detail, simulate, least-privilege suggestions, escalation graph, access
review campaigns, health, metrics, and the web UI."""

from __future__ import annotations

import os
import threading
import time
import uuid
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from .campaign import CampaignError, CampaignStore, NotReviewer
from .engine import evaluate
from .escalation import ADMIN, EscalationGraph
from .findings import SEV_RANK, SEVERITIES, TYPES, analyze
from .leastpriv import DEFAULT_BUFFER, Config, suggest, summarize
from .logs import get_logger, log_event
from .metrics import Metrics
from .model import Environment, load_environment
from .policy import PolicyError
from .usage import usage_summary

STATIC = Path(__file__).parent / "static"


def short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


class State:
    def __init__(self, data_dir: Path, state_dir: Path | None):
        t0 = time.perf_counter()
        self.env: Environment = load_environment(data_dir)
        self.graph = EscalationGraph(self.env)
        self.findings = analyze(self.env, self.graph)
        self.by_id = {f.id: f for f in self.findings}
        self.by_subject: dict[str, list] = {}
        for f in self.findings:
            self.by_subject.setdefault(f.subject, []).append(f)
        self.paths = self.graph.all_paths()
        self.campaigns = CampaignStore(self.env, state_dir / "campaigns.json" if state_dir else None)
        self._summary = None
        self.lock = threading.Lock()
        self.load_seconds = time.perf_counter() - t0

    def lp_summary(self) -> dict:
        with self.lock:
            if self._summary is None:
                self._summary = summarize(self.env)
            return self._summary

    def graph_view(self) -> dict:
        """Escalation paths as a small layered graph. Start principals that share a path are clustered."""
        env = self.env
        clusters: dict[tuple, list[str]] = {}
        for start, path in self.paths.items():
            p = env.principals[start]
            key = (p.account, p.type, tuple((e.kind, e.dst) for e in path))
            clusters.setdefault(key, []).append(start)
        nodes: dict[str, dict] = {ADMIN: {"id": ADMIN, "label": "admin", "kind": "admin", "depth": 0}}
        edges: dict[tuple, dict] = {}
        path_list = []
        for i, ((acct, ptype, hops), members) in enumerate(sorted(clusters.items(), key=lambda kv: -len(kv[1]))):
            label = short(members[0]) if len(members) == 1 else f"{len(members)} {ptype}s in {env.account_name(acct)}"
            # A single start principal uses its ARN as the node id, so it merges with the same principal as a hop.
            cid = members[0] if len(members) == 1 else f"c{i}"
            if cid in nodes:
                nodes[cid]["depth"] = max(nodes[cid]["depth"], len(hops))
            else:
                nodes[cid] = {"id": cid, "label": label, "kind": "start", "members": members, "depth": len(hops)}
            path = self.paths[members[0]]
            prev = cid
            for j, e in enumerate(path):
                dst = e.dst
                if dst != ADMIN and dst not in nodes:
                    adm = dst in self.graph.admins
                    nodes[dst] = {
                        "id": dst,
                        "label": short(dst),
                        "kind": "admin-principal" if adm else "hop",
                        "depth": len(path) - j - 1,
                    }
                elif dst != ADMIN:
                    nodes[dst]["depth"] = max(nodes[dst]["depth"], len(path) - j - 1)
                k = (prev, dst, e.kind)
                if k not in edges:
                    edges[k] = {"from": prev, "to": dst, "kind": e.kind, "action": e.action, "resource": e.resource}
                prev = dst
            path_list.append(
                {"cluster": cid, "members": len(members), "label": label, "steps": [e.to_dict() for e in path]}
            )
        return {
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
            "paths": path_list,
            "admins": sorted(self.graph.admins),
        }


def create_app(data_dir: Path | None = None, state_dir: Path | None = None) -> FastAPI:
    data_dir = Path(data_dir or os.environ.get("IAMLENS_DATA", "examples"))
    sd = state_dir or os.environ.get("IAMLENS_STATE")
    log = get_logger()
    metrics = Metrics()
    state = State(data_dir, Path(sd) if sd else None)
    env = state.env
    app = FastAPI(title="iamlens", version="1.0.0")
    app.state.iam = state
    if os.environ.get("IAMLENS_WARM", "1") == "1":
        threading.Thread(target=state.lp_summary, daemon=True).start()
    log_event(
        log,
        "environment loaded",
        principals=len(env.principals),
        accounts=len(env.accounts),
        events=len(env.events),
        findings=len(state.findings),
        seconds=round(state.load_seconds, 2),
    )

    def gauges() -> None:
        for s in SEVERITIES:
            metrics.set_gauge(
                f"iamlens_findings_{s}", f"Open {s} findings.", sum(f.severity == s for f in state.findings)
            )
        metrics.set_gauge("iamlens_principals", "Principals in the environment.", len(env.principals))
        metrics.set_gauge("iamlens_escalation_paths", "Principals with a path to admin.", len(state.paths))
        metrics.set_gauge("iamlens_access_events", "Access log events loaded.", len(env.events))

    @app.middleware("http")
    async def observe(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        t0 = time.perf_counter()
        try:
            resp = await call_next(request)
        except Exception:
            log.exception("unhandled error", extra={"fields": {"request_id": rid, "path": request.url.path}})
            resp = JSONResponse({"detail": "internal error", "request_id": rid}, status_code=500)
        dt = time.perf_counter() - t0
        route = request.scope.get("route")
        metrics.observe_request(getattr(route, "path", "unmatched"), resp.status_code, dt)
        resp.headers["x-request-id"] = rid
        if request.url.path not in ("/healthz", "/metrics"):
            log_event(
                log,
                "request",
                request_id=rid,
                method=request.method,
                path=request.url.path,
                status=resp.status_code,
                ms=round(dt * 1000, 1),
            )
        return resp

    def principal_or_404(arn: str):
        p = env.principals.get(arn)
        if p is None:
            raise HTTPException(404, f"unknown principal {arn}")
        return p

    @app.get("/healthz")
    def healthz():
        return {
            "status": "ok",
            "principals": len(env.principals),
            "accounts": len(env.accounts),
            "events": len(env.events),
            "findings": len(state.findings),
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics_endpoint():
        gauges()
        return metrics.render()

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/summary")
    def summary():
        kinds = Counter(p.kind for p in env.principals.values())
        return {
            "company": env.company,
            "as_of": env.as_of.isoformat(),
            "org_id": env.org_id,
            "accounts": len(env.accounts),
            "principals": len(env.principals),
            "principal_kinds": dict(kinds),
            "policies": len(env.policies),
            "resources": len(env.resources),
            "events": len(env.events),
            "findings": len(state.findings),
            "by_severity": {s: sum(f.severity == s for f in state.findings) for s in SEVERITIES},
            "by_type": [
                {
                    "type": t,
                    "label": label,
                    **{s: sum(f.severity == s and f.type == t for f in state.findings) for s in SEVERITIES},
                    "total": sum(f.type == t for f in state.findings),
                }
                for t, label in TYPES.items()
            ],
            "escalation_paths": len(state.paths),
            "admins": len(state.graph.admins),
        }

    @app.get("/api/findings")
    def findings(
        severity: Annotated[list[str] | None, Query()] = None,
        type: str | None = None,
        q: str | None = None,
        limit: int = Query(200, ge=1, le=2000),
        offset: int = Query(0, ge=0),
    ):
        rows = state.findings
        if severity:
            sev = {s for x in severity for s in x.split(",")}
            rows = [f for f in rows if f.severity in sev]
        if type:
            rows = [f for f in rows if f.type == type]
        if q:
            ql = q.lower()
            rows = [f for f in rows if ql in f.subject.lower() or ql in f.title.lower()]
        return {"total": len(rows), "items": [f.to_dict() for f in rows[offset : offset + limit]]}

    @app.get("/api/findings/{fid}")
    def finding(fid: str):
        f = state.by_id.get(fid)
        if f is None:
            raise HTTPException(404, "unknown finding")
        return f.to_dict()

    @app.get("/api/principals")
    def principals(q: str | None = None, kind: str | None = None, limit: int = Query(500, ge=1, le=1000)):
        rows = list(env.principals.values())
        if kind:
            rows = [p for p in rows if p.kind == kind]
        if q:
            ql = q.lower()
            rows = [p for p in rows if ql in p.arn.lower() or ql in (p.display_name or "").lower()]
        out = []
        for p in rows[:limit]:
            fs = state.by_subject.get(p.arn, [])
            worst = min((SEV_RANK[f.severity] for f in fs), default=None)
            out.append({**p.summary(), "findings": len(fs), "worst": SEVERITIES[worst] if worst is not None else None})
        return {"total": len(rows), "items": out}

    @app.get("/api/principal")
    def principal(arn: str):
        p = principal_or_404(arn)
        pu = env.usage.get(p.arn)
        top = []
        if pu:
            for a, u in sorted(pu.actions.items(), key=lambda kv: -kv[1].count)[:25]:
                top.append(
                    {
                        "action": a,
                        "count": u.count,
                        "denied": u.denied,
                        "last_seen": u.last_seen,
                        "resources": [short(r) for r, _ in u.resources.most_common(3)],
                    }
                )
        mgr = env.principals.get(p.manager) if p.manager else None
        return {
            **p.summary(),
            "title": p.title,
            "ou_path": env.ou_path(p.account),
            "account_name": env.account_name(p.account),
            "groups": p.groups,
            "manager": {"arn": mgr.arn, "name": mgr.display_name or mgr.name} if mgr else None,
            "console": p.console,
            "mfa": p.mfa,
            "access_keys": p.access_keys,
            "created": p.created,
            "policies": [
                {"id": pol.id, "name": pol.name, "source": src, "document": pol.document}
                for src, pol in env.identity_policies(p)
            ],
            "boundary": {"id": p.boundary, "document": env.policies[p.boundary].document} if p.boundary else None,
            "trust": p.trust.document if p.trust else None,
            "scps": [{"level": label, "policies": [x.name for x in pols]} for label, pols in env.scp_levels(p.account)],
            "usage": usage_summary(env, p),
            "top_actions": top,
            "findings": [f.to_dict() for f in state.by_subject.get(p.arn, [])],
            "escalation": [e.to_dict() for e in state.paths.get(p.arn, [])],
            "is_admin": p.arn in state.graph.admins,
        }

    @app.post("/api/simulate")
    def simulate(body: Annotated[dict, Body()]):
        for k in ("principal", "action", "resource"):
            if not body.get(k):
                raise HTTPException(422, f"{k} is required")
        p = principal_or_404(body["principal"])
        ctx = body.get("context") or {}
        if not isinstance(ctx, dict):
            raise HTTPException(422, "context must be an object of condition keys")
        try:
            d = evaluate(env, p, body["action"], body["resource"], ctx)
        except PolicyError as e:
            raise HTTPException(422, str(e)) from e
        metrics.action("simulate", "allow" if d.allowed else "deny")
        return d.to_dict()

    @app.get("/api/least-privilege")
    def least_privilege(
        arn: str, max_resources: int = Query(5, ge=1, le=50), buffer: Annotated[list[str] | None, Query()] = None
    ):
        p = principal_or_404(arn)
        cfg = Config(max_resources=max_resources, buffer=buffer if buffer is not None else list(DEFAULT_BUFFER))
        r = suggest(env, p, cfg)
        metrics.action("suggest", "pass" if r["proof"]["passed"] else "fail")
        return r

    @app.get("/api/least-privilege/summary")
    def lp_summary():
        s = state.lp_summary()
        return {k: v for k, v in s.items() if k != "rows"}

    @app.get("/api/escalation")
    def escalation():
        return state.graph_view()

    # ---------- campaigns ----------
    def now_or(v: str | None) -> date:
        return date.fromisoformat(v) if v else env.as_of

    @app.get("/api/campaigns")
    def campaigns():
        return [state.campaigns.status(cid, env.as_of) for cid in state.campaigns.campaigns]

    @app.post("/api/campaigns", status_code=201)
    def create_campaign(body: Annotated[dict, Body()]):
        try:
            start = now_or(body.get("created"))
            deadline = (
                date.fromisoformat(body["deadline"])
                if body.get("deadline")
                else date.fromordinal(start.toordinal() + 14)
            )
            c = state.campaigns.create(
                body.get("name") or "Access review",
                start,
                deadline,
                int(body.get("escalate_after_days", 3)),
                body.get("managers"),
            )
        except (CampaignError, ValueError) as e:
            raise HTTPException(422, str(e)) from e
        metrics.action("campaign_create", "ok")
        return state.campaigns.status(c["id"], start)

    @app.get("/api/campaigns/{cid}")
    def get_campaign(
        cid: str,
        reviewer: str | None = None,
        status: str | None = None,
        now: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
    ):
        try:
            c = state.campaigns.get(cid)
        except KeyError as e:
            raise HTTPException(404, "unknown campaign") from e
        items = c["items"]
        if reviewer:
            items = [i for i in items if i["reviewer"] == reviewer]
        if status == "pending":
            items = [i for i in items if not i["decision"]]
        elif status:
            items = [i for i in items if i["status"] == status]
        return {**state.campaigns.status(cid, now_or(now)), "item_list": items[:limit], "log": c["log"][-50:]}

    @app.post("/api/campaigns/{cid}/items/{iid}/decision")
    def decide(cid: str, iid: str, body: Annotated[dict, Body()]):
        try:
            item = state.campaigns.decide(
                cid,
                iid,
                body.get("reviewer", ""),
                body.get("decision", ""),
                now_or(body.get("now")),
                body.get("comment", ""),
            )
        except KeyError as e:
            raise HTTPException(404, f"unknown {e}") from e
        except NotReviewer as e:
            metrics.action("review_decision", "forbidden")
            raise HTTPException(403, str(e)) from e
        except CampaignError as e:
            raise HTTPException(409, str(e)) from e
        metrics.action("review_decision", item["decision"])
        return item

    @app.post("/api/campaigns/{cid}/escalate")
    def escalate(cid: str, body: Annotated[dict | None, Body()] = None):
        try:
            moved = state.campaigns.escalate(cid, now_or((body or {}).get("now")))
        except KeyError as e:
            raise HTTPException(404, "unknown campaign") from e
        return {"escalated": len(moved), "items": [i["id"] for i in moved]}

    @app.get("/api/campaigns/{cid}/evidence")
    def evidence(cid: str, format: str = "json", now: str | None = None):
        try:
            body = state.campaigns.evidence(cid, now_or(now), format)
        except KeyError as e:
            raise HTTPException(404, "unknown campaign") from e
        media = "text/csv" if format == "csv" else "application/json"
        headers = {
            "content-disposition": f'attachment; filename="{cid}-evidence.{"csv" if format == "csv" else "json"}"'
        }
        return PlainTextResponse(body, media_type=media, headers=headers)

    return app
