"""Policy evaluation: can principal P do action A on resource R with context C, and why.

The order follows the provider's documented logic, simplified for teaching:

1. Explicit deny. A matching Deny in any applicable policy (SCPs, permissions boundary, identity policies,
   resource policy) ends evaluation.
2. Service control policies. Every level from the organization root down to the principal's account must
   have an Allow for the action. The management account is not affected by SCPs.
3. Resource policy. Required for KMS keys and for role trust (sts:AssumeRole). A grant that names the
   principal directly can allow on its own within one account; a grant to the whole account delegates to
   the account's identity policies.
4. Identity policies (attached, inline, and group policies), unioned with the resource policy within one
   account. Across accounts both sides must allow.
5. Permissions boundary. Caps identity grants. Within one account it does not cap a resource policy grant
   that names an IAM user directly, but it does cap one that names a role.

Simplifications are listed in the README: no session policies, no resource control policies, no
service-linked role exemptions, no aws:SourceArn style confused-deputy keys beyond what conditions express.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .matching import account_of, split_arn
from .model import Environment, Principal
from .policy import Caller, Policy, StatementHit, evaluate_policy

RESOURCE_POLICY_REQUIRED = {"trust", "kms_key"}


@dataclass
class Step:
    stage: str
    outcome: str  # allow | deny | pass | fail | no match | not applicable
    detail: str
    statements: list[StatementHit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "outcome": self.outcome,
            "detail": self.detail,
            "statements": [s.to_dict() for s in self.statements],
        }


@dataclass
class Decision:
    allowed: bool
    decision: str  # Allow | ExplicitDeny | ImplicitDeny
    reason: str
    steps: list[Step]
    principal: str
    action: str
    resource: str
    context: dict

    def to_dict(self) -> dict:
        return {
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "allowed": self.allowed,
            "decision": self.decision,
            "reason": self.reason,
            "context": self.context,
            "path": [s.to_dict() for s in self.steps],
        }


def build_context(env: Environment, p: Principal, extra: dict | None, resource: str = "*") -> dict:
    parts = split_arn(resource)
    region = parts[3] if parts and parts[3] else "us-east-1"
    ctx: dict = {
        "aws:requestedregion": region,
        "aws:principalarn": p.arn,
        "aws:principalaccount": p.account,
        "aws:principaltype": "User" if p.type == "user" else "AssumedRole",
    }
    if env.in_org(p.account) or p.account == env.management_account:
        ctx["aws:principalorgid"] = env.org_id
    if p.type == "user":
        ctx["aws:username"] = p.name
    for k, v in (p.tags or {}).items():
        ctx[f"aws:principaltag/{k}".lower()] = v
    for k, v in (extra or {}).items():
        ctx[k.lower()] = str(v).lower() if isinstance(v, bool) else v
    return ctx


def _names(hits: list[StatementHit]) -> str:
    return ", ".join(f"{h.policy_name} [{h.sid}]" for h in hits)


def evaluate(
    env: Environment,
    principal: Principal | str,
    action: str,
    resource: str,
    context: dict | None = None,
    identity_override: list[Policy] | None = None,
) -> Decision:
    p = env.principals[principal] if isinstance(principal, str) else principal
    ctx = build_context(env, p, context, resource)
    caller = Caller(arn=p.arn, account=p.account)
    steps: list[Step] = []

    def done(allowed: bool, decision: str, reason: str) -> Decision:
        steps.append(Step("decision", "allow" if allowed else "deny", reason))
        return Decision(allowed, decision, reason, steps, p.arn, action, resource, dict(ctx))

    scp_levels = env.scp_levels(p.account)
    identity = (
        [("candidate", pol) for pol in identity_override] if identity_override is not None else env.identity_policies(p)
    )
    boundary = env.boundary(p)
    rp_kind, rp = env.resource_policy(resource, action)
    res_account = env.resource_account(resource) or account_of(resource)
    cross = res_account is not None and res_account != p.account

    # 1. explicit deny anywhere
    scp_results = [
        (label, [evaluate_policy(pol, action, resource, ctx) for pol in pols], pols) for label, pols in scp_levels
    ]
    id_results = [(src, pol, evaluate_policy(pol, action, resource, ctx)) for src, pol in identity]
    b_result = evaluate_policy(boundary, action, resource, ctx) if boundary else None
    rp_result = evaluate_policy(rp, action, resource, ctx, caller) if rp else None

    denies: list[StatementHit] = []
    for _, results, _ in scp_results:
        for _, d in results:
            denies += d
    for _, _, (_, d) in id_results:
        denies += d
    if b_result:
        denies += b_result[1]
    if rp_result:
        denies += rp_result[1]
    if denies:
        steps.append(Step("explicit deny", "deny", f"Deny statement matched: {_names(denies)}.", denies))
        return done(False, "ExplicitDeny", f"Explicitly denied by {_names(denies[:1])}.")
    steps.append(Step("explicit deny", "pass", "No Deny statement matched in any applicable policy."))

    # 2. SCPs: every level must allow
    if not scp_levels:
        why = (
            "management account, SCPs do not apply"
            if p.account == env.management_account
            else "principal is outside the organization, no SCPs"
        )
        steps.append(Step("service control policies", "not applicable", why.capitalize() + "."))
    else:
        for label, results, pols in scp_results:
            allows = [a for res in results for a in res[0]]
            if not allows:
                names = ", ".join(pol.name for pol in pols) or "no SCPs attached"
                steps.append(Step("service control policies", "fail", f"No SCP at {label} allows {action} ({names})."))
                return done(False, "ImplicitDeny", f"Outside the SCP boundary at {label}.")
            steps.append(Step("service control policies", "pass", f"Allowed at {label}.", allows))

    # 3 to 5: resource policy, identity policies, boundary
    id_allows = [a for _, _, (al, _) in id_results for a in al]
    rp_allows = rp_result[0] if rp_result else []
    rp_direct = [a for a in rp_allows if a.principal_match in ("direct", "public")]
    rp_account = [a for a in rp_allows if a.principal_match == "account"]
    b_allows = b_result[0] if b_result else []
    b_ok = boundary is None or bool(b_allows)

    if rp_kind is None:
        steps.append(Step("resource policy", "not applicable", "Resource type has no resource-based policy."))
    elif rp is None:
        steps.append(Step("resource policy", "no match", f"The {rp_kind} has no resource-based policy."))
    elif rp_allows:
        steps.append(Step("resource policy", "allow", f"{rp.name} allows it.", rp_allows))
    else:
        steps.append(Step("resource policy", "no match", f"{rp.name} has no matching Allow for this principal."))

    if id_allows:
        steps.append(Step("identity policies", "allow", f"Allowed by {_names(id_allows)}.", id_allows))
    else:
        n = len(identity)
        steps.append(Step("identity policies", "no match", f"None of the {n} identity policies allow it."))

    if boundary is None:
        steps.append(Step("permissions boundary", "not applicable", "No permissions boundary set."))
    elif b_allows:
        steps.append(Step("permissions boundary", "pass", f"Boundary {boundary.name} allows it.", b_allows))
    else:
        steps.append(Step("permissions boundary", "fail", f"Boundary {boundary.name} does not allow it."))

    required = rp_kind in RESOURCE_POLICY_REQUIRED
    if required and not rp_allows:
        return done(False, "ImplicitDeny", f"The {rp_kind} policy must allow this request and it does not.")

    if cross:
        acct = env.account_name(res_account)
        if not rp_allows:
            return done(
                False, "ImplicitDeny", f"Cross-account request into {acct}: the resource policy does not grant it."
            )
        if not id_allows:
            return done(
                False,
                "ImplicitDeny",
                "Cross-account request: the resource policy allows it but no identity policy does.",
            )
        if not b_ok:
            return done(False, "ImplicitDeny", "Cross-account request: the permissions boundary caps it.")
        return done(
            True,
            "Allow",
            f"Cross-account request into {acct}: both the resource policy and an identity policy allow it.",
        )

    # same account: union of a direct resource grant and identity grants
    if rp_direct:
        boundary_applies = p.type == "role"
        if not boundary_applies or b_ok:
            note = (
                ""
                if boundary is None
                else (
                    " The boundary does not cap a grant that names a user."
                    if not boundary_applies
                    else " The boundary also allows it."
                )
            )
            return done(True, "Allow", f"The resource policy grants it to this principal directly.{note}")
    if id_allows and b_ok:
        if required and not rp_account and not rp_direct:
            return done(False, "ImplicitDeny", f"The {rp_kind} policy does not delegate to this account.")
        tail = " and the permissions boundary" if boundary else ""
        return done(True, "Allow", f"Allowed by an identity policy{tail}.")
    if id_allows and not b_ok:
        return done(False, "ImplicitDeny", "An identity policy allows it but the permissions boundary does not.")
    return done(False, "ImplicitDeny", "No policy allows it (implicit deny).")


def is_allowed(
    env: Environment,
    principal,
    action: str,
    resource: str,
    context: dict | None = None,
    identity_override: list[Policy] | None = None,
) -> bool:
    return evaluate(env, principal, action, resource, context, identity_override).allowed
