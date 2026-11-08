"""Command line: generate, findings, simulate, suggest, reduction, check, campaign, serve."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

from .model import Environment, Principal, load_environment

DATA = os.environ.get("IAMLENS_DATA", "examples")


def resolve(env: Environment, key: str) -> Principal:
    if key in env.principals:
        return env.principals[key]
    hits = [
        p for p in env.principals.values() if p.arn.endswith(":" + key) or p.arn.endswith("/" + key) or p.name == key
    ]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise SystemExit(f"no principal matches {key!r}")
    raise SystemExit(f"{key!r} is ambiguous: " + ", ".join(h.arn for h in hits[:6]))


def parse_context(pairs: list[str]) -> dict:
    ctx = {}
    for kv in pairs or []:
        if "=" not in kv:
            raise SystemExit(f"context must be key=value, got {kv!r}")
        k, v = kv.split("=", 1)
        ctx[k] = v
    return ctx


def cmd_generate(a) -> int:
    from .generator import write

    stats = write(Path(a.out), a.seed)
    print(json.dumps(stats))
    return 0


def cmd_findings(a) -> int:
    from .findings import analyze

    env = load_environment(a.data)
    fs = analyze(env)
    if a.severity:
        fs = [f for f in fs if f.severity in a.severity]
    if a.type:
        fs = [f for f in fs if f.type == a.type]
    if a.json:
        print(json.dumps([f.to_dict() for f in fs], indent=2))
        return 0
    for f in fs[: a.limit]:
        print(f"{f.severity:<8}  {f.type:<36}  {f.title}")
    print(f"\n{len(fs)} findings")
    return 0


def cmd_simulate(a) -> int:
    from .engine import evaluate

    env = load_environment(a.data)
    p = resolve(env, a.principal)
    d = evaluate(env, p, a.action, a.resource, parse_context(a.context))
    if a.json:
        print(json.dumps(d.to_dict(), indent=2))
    else:
        print(f"{d.decision}: {d.reason}")
        for s in d.steps[:-1]:
            print(f"  {s.stage:<26} {s.outcome:<15} {s.detail}")
    return 0 if d.allowed else 3


def cmd_suggest(a) -> int:
    from .leastpriv import DEFAULT_BUFFER, Config, suggest

    env = load_environment(a.data)
    p = resolve(env, a.principal)
    cfg = Config(max_resources=a.max_resources, buffer=a.buffer if a.buffer is not None else list(DEFAULT_BUFFER))
    r = suggest(env, p, cfg)
    if a.json:
        print(json.dumps(r, indent=2))
        return 0
    print(json.dumps(r["policy"], indent=2))
    pr = r["proof"]
    print(f"\ngranted actions {r['granted_before']} -> {r['granted_after']} ({r['reduction_pct']}% fewer)")
    print(
        f"proof: {pr['observed_still_allowed']}/{pr['observed_requests']} observed requests still allowed, "
        f"{pr['unused_actions_denied']}/{pr['unused_actions_checked']} unused actions denied: "
        f"{'PASS' if pr['passed'] else 'FAIL'}"
    )
    return 0 if pr["passed"] else 1


def cmd_reduction(a) -> int:
    from .leastpriv import summarize

    env = load_environment(a.data)
    s = summarize(env)
    if a.json:
        print(json.dumps({k: v for k, v in s.items() if k != "rows"}, indent=2))
        return 0
    print(f"{'kind':<12} {'principals':>10} {'before':>8} {'after':>7} {'reduction':>9}")
    for k in s["by_kind"]:
        pct = 100 * (1 - k["after"] / k["before"]) if k["before"] else 0
        print(f"{k['kind']:<12} {k['principals']:>10} {k['before']:>8} {k['after']:>7} {pct:>8.1f}%")
    print(
        f"{'total':<12} {s['principals']:>10} {s['granted_before']:>8} {s['granted_after']:>7} "
        f"{s['reduction_pct']:>8.1f}%"
    )
    return 0


def cmd_check(a) -> int:
    from .check import changed_files, gate, render_markdown, render_sarif, run_check

    root = Path(a.path)
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2
    only = None
    note = ""
    if a.changed:
        only = [Path(x) for x in a.changed]
    elif a.base:
        only = changed_files(a.base, root)
        if only is None:
            note = f"git could not diff against {a.base}; checked every file."
    findings, files = run_check(root, only)
    failed = gate(findings, a.fail_on)
    if a.sarif:
        Path(a.sarif).write_text(render_sarif(findings))
    md = render_markdown(findings, files, a.fail_on, failed) + (f"\n{note}\n" if note else "")
    if a.summary:
        Path(a.summary).write_text(md)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a") as f:
            f.write(md)
    if a.json:
        print(json.dumps({"failed": failed, "files": files, "findings": [f.to_dict() for f in findings]}, indent=2))
    elif not a.quiet:
        for f in findings:
            print(f"{f.severity:<8} {f.rule}  {f.file}:{f.line}  {f.message}")
        if note:
            print(note)
        print(f"{len(files)} file(s), {len(findings)} finding(s): {'FAIL' if failed else 'PASS'} (gate {a.fail_on})")
    return 1 if failed else 0


def cmd_campaign(a) -> int:
    from .campaign import CampaignStore

    env = load_environment(a.data)
    store = CampaignStore(env)
    start = env.as_of
    c = store.create(a.name, start, start + timedelta(days=a.days))
    st = store.status(c["id"], start)
    print(json.dumps({k: v for k, v in st.items() if k != "reviewers"}, indent=2))
    if a.evidence:
        Path(a.evidence).write_text(store.evidence(c["id"], start, "csv" if a.evidence.endswith(".csv") else "json"))
        print(f"wrote {a.evidence}")
    return 0


def cmd_serve(a) -> int:
    import uvicorn

    from .app import create_app

    uvicorn.run(create_app(Path(a.data)), host=a.host, port=a.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="iamlens", description="Cloud identity and access analyzer (teaching build).")
    ap.add_argument("--data", default=DATA, help="environment directory (default: examples)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write the seeded synthetic environment")
    g.add_argument("--out", default="examples")
    g.add_argument("--seed", type=int, default=7)
    g.set_defaults(fn=cmd_generate)

    f = sub.add_parser("findings", help="list findings")
    f.add_argument("--severity", action="append")
    f.add_argument("--type")
    f.add_argument("--limit", type=int, default=50)
    f.add_argument("--json", action="store_true")
    f.set_defaults(fn=cmd_findings)

    s = sub.add_parser("simulate", help="can PRINCIPAL do ACTION on RESOURCE")
    s.add_argument("principal")
    s.add_argument("action")
    s.add_argument("resource")
    s.add_argument("--context", "-c", action="append", help="condition key=value, repeatable")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_simulate)

    lp = sub.add_parser("suggest", help="least-privilege policy for a principal, with proof")
    lp.add_argument("principal")
    lp.add_argument("--max-resources", type=int, default=5)
    lp.add_argument("--buffer", action="append", help="action pattern kept when granted but unused, repeatable")
    lp.add_argument("--json", action="store_true")
    lp.set_defaults(fn=cmd_suggest)

    r = sub.add_parser("reduction", help="granted actions before and after least privilege, all principals")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_reduction)

    c = sub.add_parser("check", help="CI gate on policy files: SARIF and a Markdown summary")
    c.add_argument("path")
    c.add_argument("--base", help="git ref; only files changed since it are checked")
    c.add_argument("--changed", action="append", help="check only this file, repeatable")
    c.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"])
    c.add_argument("--sarif")
    c.add_argument("--summary")
    c.add_argument("--json", action="store_true")
    c.add_argument("--quiet", action="store_true")
    c.set_defaults(fn=cmd_check)

    cp = sub.add_parser("campaign", help="start an access review campaign and export evidence")
    cp.add_argument("--name", default="Quarterly access review")
    cp.add_argument("--days", type=int, default=14)
    cp.add_argument("--evidence", help="write evidence to this .json or .csv file")
    cp.set_defaults(fn=cmd_campaign)

    sv = sub.add_parser("serve", help="run the API and UI")
    sv.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8839")))
    sv.set_defaults(fn=cmd_serve)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
