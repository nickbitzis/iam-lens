"""Wildcard matching for actions, ARNs, and policy variables.

IAM wildcards: `*` matches any run of characters (including none), `?` matches exactly one. Actions are
case-insensitive. ARNs are case-sensitive and matched segment by segment: the first five colon-separated
segments (arn, partition, service, region, account) cannot be spanned by a wildcard, the resource segment
can contain colons and slashes.
"""

from __future__ import annotations

import re
from functools import lru_cache

VAR_RE = re.compile(r"\$\{([^}]+)\}")


@lru_cache(maxsize=8192)
def _glob(pattern: str, ignore_case: bool) -> re.Pattern:
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out), re.DOTALL | (re.IGNORECASE if ignore_case else 0))


def glob_match(pattern: str, value: str, ignore_case: bool = False) -> bool:
    if pattern == "*":
        return True
    return _glob(pattern, ignore_case).fullmatch(value) is not None


def action_match(pattern: str, action: str) -> bool:
    """`s3:Get*` matches `s3:GetObject`; `*` matches everything; case does not matter."""
    return glob_match(pattern, action, ignore_case=True)


def split_arn(arn: str) -> list[str] | None:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return None
    return parts


def arn_match(pattern: str, arn: str) -> bool:
    if pattern == "*":
        return True
    p, a = split_arn(pattern), split_arn(arn)
    if p is None or a is None:
        return glob_match(pattern, arn)
    for i in range(5):
        if not glob_match(p[i], a[i]):
            return False
    return glob_match(p[5], a[5])


def substitute(text: str, ctx: dict[str, object]) -> str:
    """Replace `${aws:username}` style policy variables from the (lowercased) request context.

    An unknown variable is left unresolved with a marker that cannot match a real value, which is what the
    provider does: a statement that needs a missing variable does not apply.
    """
    if "${" not in text:
        return text

    def repl(m: re.Match) -> str:
        key = m.group(1)
        if key in ("*", "?", "$"):
            return key
        v = ctx.get(key.lower())
        if isinstance(v, list):
            v = v[0] if v else None
        return "\x00unresolved\x00" if v is None else str(v)

    return VAR_RE.sub(repl, text)


def account_of(arn: str) -> str | None:
    parts = split_arn(arn)
    if parts is None:
        return None
    return parts[4] or None


def service_of(action: str) -> str:
    return action.split(":", 1)[0].lower()
