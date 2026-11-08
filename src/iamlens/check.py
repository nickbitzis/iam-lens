"""`iamlens check`: static checks on policy files in a repository, for CI.

Each `*.json` file is one IAM policy document. A file whose statements have a Principal is treated as a
resource policy (a trust policy when every action is sts:AssumeRole*). An optional `iamlens.json` in the
checked directory lists the organization's account ids so trust to other accounts can be flagged.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .findings import LIMITING_KEYS, WRITE_HINTS
from .policy import Policy, PolicyError

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
INFO_URI = "https://github.com/nickbitzis/iam-lens"

ESCALATION = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "lambda:UpdateFunctionCode",
]

RULES = {
    "IAM001": (
        "wildcard-admin",
        "critical",
        "Allow on Action * and Resource * with no condition grants full admin.",
        "Grant the actions the workload needs, scoped to its resources. Use `iamlens suggest` for a start.",
    ),
    "IAM002": (
        "allow-notaction",
        "high",
        "Allow with NotAction on Resource * grants every action except a few, including services added later.",
        "List the allowed actions instead of the excluded ones.",
    ),
    "IAM003": (
        "public-resource-policy",
        "critical",
        "A resource policy grants access to Principal * with no condition that limits the caller.",
        "Name the principals, or add aws:PrincipalOrgID or aws:SourceVpce.",
    ),
    "IAM004": (
        "external-trust-without-external-id",
        "high",
        "A trust policy lets an account outside the organization assume the role without an sts:ExternalId condition.",
        "Add a StringEquals sts:ExternalId condition with the value the vendor gave you.",
    ),
    "IAM005": (
        "escalation-action-on-any-resource",
        "high",
        "An action that can change permissions or run code as another role is allowed on Resource *.",
        "Scope the resource to the specific roles, users, or functions, for example arn:aws:iam::ACCOUNT:role/app-*.",
    ),
    "IAM006": (
        "service-wildcard",
        "medium",
        "A whole service (svc:*) is allowed on Resource *.",
        "List the actions used. `iamlens suggest` derives them from access logs.",
    ),
    "IAM007": ("invalid-policy", "high", "The file is not a valid IAM policy document.", "Fix the JSON grammar."),
    "IAM008": (
        "old-policy-version",
        "low",
        "Version is not 2012-10-17, so policy variables are not expanded.",
        'Set "Version": "2012-10-17".',
    ),
}


@dataclass
class CheckFinding:
    rule: str
    severity: str
    file: str
    line: int
    sid: str
    message: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "name": RULES[self.rule][0],
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "sid": self.sid,
            "message": self.message,
        }


def _statement_lines(text: str) -> list[int]:
    return [text.count("\n", 0, m.start()) + 1 for m in re.finditer(r'"Effect"\s*:', text)]


def _matches_any(patterns: list[str], action: str) -> bool:
    from .matching import action_match

    return any(action_match(p, action) for p in patterns)


def check_document(doc: dict, file: str, text: str, org_accounts: set[str]) -> list[CheckFinding]:
    out: list[CheckFinding] = []
    try:
        pol = Policy.parse(doc, id=file)
    except PolicyError as e:
        return [CheckFinding("IAM007", "high", file, 1, "", str(e))]
    lines = _statement_lines(text)

    def add(rule, s, msg, sev=None):
        line = lines[s.index] if s.index < len(lines) else 1
        out.append(CheckFinding(rule, sev or RULES[rule][1], file, line, s.label, msg))

    if doc.get("Version") != "2012-10-17":
        out.append(CheckFinding("IAM008", "low", file, 1, "", f"Version is {doc.get('Version')!r}."))
    resource_policy = pol.is_resource_policy
    for s in pol.statements:
        if s.effect != "Allow":
            continue
        keys = {k.lower() for block in s.condition.values() for k in block}
        on_star = s.resources == ["*"] or (not s.resources and not s.not_resources)
        if resource_policy and s.principal is not None:
            trust = s.actions and all(a.lower().startswith("sts:assumerole") for a in s.actions)
            if s.principal.wildcard and not keys & LIMITING_KEYS:
                write = any(any(h in a for h in WRITE_HINTS) for a in (s.actions or ["*"])) or trust
                add(
                    "IAM003",
                    s,
                    f"Statement {s.label} allows {', '.join(s.actions or ['NotAction'])} to Principal *.",
                    "critical" if write else "high",
                )
            if trust:
                external = sorted(a for a in s.principal.accounts() if a not in org_accounts)
                if external and "sts:externalid" not in keys and "aws:principalorgid" not in keys:
                    add(
                        "IAM004",
                        s,
                        f"Trust statement {s.label} accepts account {', '.join(external)} with no "
                        "sts:ExternalId condition.",
                    )
            continue
        if s.actions and any(a in ("*", "*:*") for a in s.actions) and on_star and not s.condition:
            add("IAM001", s, f"Statement {s.label} allows Action * on Resource *.")
            continue
        if s.not_actions and on_star:
            add("IAM002", s, f"Statement {s.label} allows everything except {', '.join(s.not_actions)}.")
        if on_star and s.actions:
            esc = [a for a in ESCALATION if _matches_any(s.actions, a)]
            if esc:
                add(
                    "IAM005",
                    s,
                    f"Statement {s.label} allows {', '.join(esc[:4])}"
                    f"{' and more' if len(esc) > 4 else ''} on Resource *.",
                )
            svc = sorted(a for a in s.actions if a.endswith(":*") and a != "*:*")
            if svc:
                add("IAM006", s, f"Statement {s.label} allows {', '.join(svc)} on Resource *.")
    return out


def load_config(root: Path) -> set[str]:
    cfg = root / "iamlens.json"
    if cfg.exists():
        data = json.loads(cfg.read_text())
        return set(data.get("org_accounts", []))
    return set()


def changed_files(base: str, root: Path) -> list[Path] | None:
    """Files under root changed since `base` according to git, or None when git cannot answer."""
    cwd = root if root.is_dir() else root.parent
    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...HEAD", "--", "."],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, timeout=10, check=True
        ).stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    return [Path(top) / line for line in res.stdout.splitlines() if line.endswith(".json")]


def run_check(root: Path, only: list[Path] | None = None) -> tuple[list[CheckFinding], list[str]]:
    root = Path(root)
    files = sorted(root.rglob("*.json")) if root.is_dir() else [root]
    files = [f for f in files if f.name != "iamlens.json"]
    if only is not None:
        wanted = {p.resolve() for p in only}
        files = [f for f in files if f.resolve() in wanted]
    org = load_config(root if root.is_dir() else root.parent)
    out: list[CheckFinding] = []
    for f in files:
        text = f.read_text()
        rel = f.as_posix()
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            out.append(CheckFinding("IAM007", "high", rel, e.lineno, "", f"invalid JSON: {e.msg}"))
            continue
        out += check_document(doc, rel, text, org)
    out.sort(key=lambda x: (SEVERITY_RANK[x.severity], x.file, x.line))
    return out, [f.as_posix() for f in files]


def gate(findings: list[CheckFinding], fail_on: str) -> bool:
    """True when the build should fail."""
    return any(SEVERITY_RANK[f.severity] <= SEVERITY_RANK[fail_on] for f in findings)


def render_sarif(findings: list[CheckFinding]) -> str:
    ids = list(RULES)
    rules = [
        {
            "id": rid,
            "name": name,
            "shortDescription": {"text": why},
            "fullDescription": {"text": why},
            "help": {"text": f"{why} Fix: {fix}", "markdown": f"{why}\n\n**Fix:** {fix}"},
            "defaultConfiguration": {"level": SARIF_LEVEL[sev]},
            "properties": {"tags": ["security", "iam", "least-privilege"], "security-severity": SECURITY_SEVERITY[sev]},
        }
        for rid, (name, sev, why, fix) in RULES.items()
    ]
    results = [
        {
            "ruleId": f.rule,
            "ruleIndex": ids.index(f.rule),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
            "partialFingerprints": {"iamlens/v1": f"{f.rule}:{f.file}:{f.sid}"},
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "severity": f.severity},
        }
        for f in findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "iamlens", "version": __version__, "informationUri": INFO_URI, "rules": rules}
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def render_markdown(findings: list[CheckFinding], files: list[str], fail_on: str, failed: bool) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_RANK}
    lines = [
        "## iamlens policy check",
        "",
        f"**{'FAILED' if failed else 'PASSED'}**: {len(files)} policy file(s) checked, gate is {fail_on} and above.",
        "",
        "| Critical | High | Medium | Low |",
        "|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
        "",
    ]
    if findings:
        lines += ["| Severity | Rule | File | Line | Message |", "|---|---|---|---:|---|"]
        for f in findings:
            lines.append(f"| {f.severity} | {f.rule} {RULES[f.rule][0]} | `{f.file}` | {f.line} | {f.message} |")
    else:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"
