"""Seeded synthetic environment for Cobaltline Retail, a made-up online retailer.

Account ids are fictional placeholders in the style of the provider's documentation (`111122223333`,
`111100013333`, ...). IP addresses come from the documentation ranges (203.0.113.0/24, 198.51.100.0/24,
192.0.2.0/24) and private 10.0.0.0/8 space. Nothing here refers to a real account or company.
"""

from __future__ import annotations

import gzip
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

COMPANY = "Cobaltline Retail"
AS_OF = date(2026, 11, 7)
DAYS = 90
ORG_ID = "o-c0ba1t1ine"
MGMT = "111122223333"
PREFIX = "cobaltline"
CORP_IPS = ["203.0.113.", "198.51.100."]
HOME_IPS = ["192.0.2."]

TEAMS = ["orders", "payments", "catalog", "search", "fulfillment", "data", "ml", "web", "support", "billing"]
EXTERNAL = [
    {"id": "444455556666", "name": "Parcelwise (monitoring vendor)"},
    {"id": "777788889999", "name": "Ledgerly (billing vendor)"},
    {"id": "999988887777", "name": "Quillsearch (search vendor)"},
    {"id": "555566667777", "name": "Tapevault (former backup vendor)"},
    {"id": "222233334444", "name": "Costwise (cost vendor)"},
]

FIRST = [
    "Ana",
    "Ben",
    "Chloe",
    "Dev",
    "Elif",
    "Farid",
    "Grace",
    "Hugo",
    "Iris",
    "Jonas",
    "Kira",
    "Liam",
    "Mina",
    "Noah",
    "Omar",
    "Priya",
    "Quinn",
    "Rosa",
    "Sami",
    "Tara",
    "Uma",
    "Viktor",
    "Wen",
    "Xavi",
    "Yara",
    "Zane",
    "Ada",
    "Bruno",
    "Cleo",
    "Dario",
    "Esme",
    "Felix",
    "Gia",
    "Hana",
    "Ivo",
    "Jade",
    "Kofi",
    "Lena",
    "Milo",
    "Nadia",
]
LAST = [
    "Abara",
    "Brandt",
    "Castell",
    "Dorn",
    "Eskel",
    "Fenwick",
    "Galloway",
    "Haldane",
    "Ingram",
    "Jessop",
    "Kovach",
    "Lindqvist",
    "Marlow",
    "Nakai",
    "Oduya",
    "Pellam",
    "Quarry",
    "Rourke",
    "Sallis",
    "Thorne",
    "Ulrich",
    "Varga",
    "Whitlow",
    "Yarrow",
    "Zeller",
    "Ambrose",
    "Becket",
    "Corrin",
    "Delacroix",
    "Everly",
]


def acct_id(i: int) -> str:
    return f"1111{i:04d}3333"


def doc(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def stmt(
    effect, action=None, resource="*", sid=None, not_action=None, condition=None, principal=None, not_resource=None
) -> dict:
    s: dict = {}
    if sid:
        s["Sid"] = sid
    s["Effect"] = effect
    if principal is not None:
        s["Principal"] = principal
    if not_action is not None:
        s["NotAction"] = not_action
    else:
        s["Action"] = action
    if not_resource is not None:
        s["NotResource"] = not_resource
    elif resource is not None:
        s["Resource"] = resource
    if condition:
        s["Condition"] = condition
    return s


class Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.seed = seed
        self.accounts: list[dict] = []
        self.nodes: list[dict] = []
        self.policies: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.principals: list[dict] = []
        self.resources: list[dict] = []
        self.profiles: dict[str, list[tuple[str, str, float]]] = {}  # arn -> (action, resource, weight)
        self.activity: dict[str, float] = {}  # arn -> probability of being active on a day
        self.channel: dict[str, str] = {}  # arn -> console | cli | service
        self.acct_by_name: dict[str, str] = {}
        self.used_names: set[str] = set()

    # ---------- structure ----------
    def policy(
        self, pid: str, document: dict, kind: str = "managed", account: str | None = None, name: str | None = None
    ) -> str:
        self.policies[pid] = {
            "name": name or pid,
            "kind": kind,
            "document": document,
            **({"account": account} if account else {}),
        }
        return pid

    def org(self):
        self.policy("FullAWSAccess", doc(stmt("Allow", "*", sid="FullAWSAccess")), "scp")
        self.policy("DenyLeaveOrg", doc(stmt("Deny", "organizations:LeaveOrganization", sid="NoLeaving")), "scp")
        self.policy(
            "ProtectAuditTrail",
            doc(
                stmt(
                    "Deny",
                    ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"],
                    sid="ProtectTrail",
                    condition={"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/breakglass-admin"}},
                )
            ),
            "scp",
        )
        self.policy(
            "RegionLock",
            doc(
                stmt(
                    "Deny",
                    not_action=["iam:*", "sts:*", "organizations:*", "ce:*", "cloudfront:*"],
                    sid="TwoRegionsOnly",
                    condition={"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
                )
            ),
            "scp",
        )
        self.policy(
            "ProdGuardrails",
            doc(
                stmt(
                    "Deny",
                    ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"],
                    sid="NoNewHumansInProd",
                )
            ),
            "scp",
        )
        self.policy(
            "SandboxAllowlist",
            doc(
                stmt(
                    "Allow",
                    [
                        "ec2:*",
                        "s3:*",
                        "lambda:*",
                        "dynamodb:*",
                        "logs:*",
                        "cloudwatch:*",
                        "sqs:*",
                        "sts:*",
                        "iam:Get*",
                        "iam:List*",
                        "iam:PassRole",
                    ],
                    sid="SandboxServices",
                )
            ),
            "scp",
        )
        self.policy("DenyAll", doc(stmt("Deny", "*", sid="Suspended")), "scp")

        full = ["FullAWSAccess"]
        self.nodes = [
            {"id": "r-root", "name": "Root", "parent": None, "scps": full + ["DenyLeaveOrg", "ProtectAuditTrail"]},
            {"id": "ou-security", "name": "Security", "parent": "r-root", "scps": full},
            {"id": "ou-infra", "name": "Infrastructure", "parent": "r-root", "scps": full},
            {"id": "ou-workloads", "name": "Workloads", "parent": "r-root", "scps": full + ["RegionLock"]},
            {"id": "ou-prod", "name": "Prod", "parent": "ou-workloads", "scps": full + ["ProdGuardrails"]},
            {"id": "ou-staging", "name": "Staging", "parent": "ou-workloads", "scps": full},
            {"id": "ou-dev", "name": "Dev", "parent": "ou-workloads", "scps": full},
            {"id": "ou-sandbox", "name": "Sandbox", "parent": "r-root", "scps": ["SandboxAllowlist"]},
            {"id": "ou-suspended", "name": "Suspended", "parent": "r-root", "scps": ["DenyAll"]},
        ]
        names = [("management", "r-root", "mgmt")]
        names += [(n, "ou-security", "security") for n in ("log-archive", "audit", "security-tooling")]
        names += [(n, "ou-infra", "infra") for n in ("network", "shared-services", "tooling-ci", "identity")]
        names += [(f"{t}-prod", "ou-prod", "prod") for t in TEAMS]
        names += [(f"{t}-staging", "ou-staging", "staging") for t in TEAMS]
        names += [(f"{t}-dev", "ou-dev", "dev") for t in TEAMS[:6]]
        names += [(f"sandbox-{i}", "ou-sandbox", "sandbox") for i in range(1, 6)]
        names += [("legacy-retired", "ou-suspended", "suspended")]
        for i, (name, parent, env) in enumerate(names):
            aid = MGMT if name == "management" else acct_id(i)
            scps = [] if parent == "r-root" or env in ("sandbox", "suspended") else ["FullAWSAccess"]
            if env == "sandbox":
                scps = ["SandboxAllowlist"]
            self.accounts.append({"id": aid, "name": name, "parent": parent, "env": env, "scps": scps})
            self.acct_by_name[name] = aid

    # ---------- principals ----------
    def add(self, **p) -> dict:
        p.setdefault("groups", [])
        p.setdefault("policies", [])
        p.setdefault("access_keys", [])
        self.principals.append(p)
        self.profiles[p["arn"]] = []
        return p

    def role(
        self, account: str, name: str, kind: str, trust: dict, policies=(), boundary=None, team="", created=None
    ) -> dict:
        return self.add(
            arn=f"arn:aws:iam::{account}:role/{name}",
            name=name,
            type="role",
            account=account,
            kind=kind,
            team=team,
            trust_policy=trust,
            policies=list(policies),
            boundary=boundary,
            created=created or self.past_date(200, 900),
        )

    def past_date(self, lo: int, hi: int) -> str:
        return (AS_OF - timedelta(days=self.rng.randint(lo, hi))).isoformat()

    def person_name(self) -> tuple[str, str]:
        while True:
            f, last = self.rng.choice(FIRST), self.rng.choice(LAST)
            u = f"{f.lower()}.{last.lower()}"
            if u not in self.used_names:
                self.used_names.add(u)
                return u, f"{f} {last}"

    def keys(self, p: dict, n_old: float = 0.3):
        if self.rng.random() < n_old:
            created = AS_OF - timedelta(days=self.rng.choice([40, 120, 200, 400, 520, 800, 1100]))
            last = AS_OF - timedelta(days=self.rng.choice([1, 2, 5, 30, 150]))
            p["access_keys"].append(
                {
                    "id": f"key-{len(self.principals):04d}a",
                    "status": "Active",
                    "created": created.isoformat(),
                    "last_used": max(last, created).isoformat(),
                }
            )

    def resource(self, **r) -> dict:
        self.resources.append(r)
        return r

    def build(self):
        rng = self.rng
        self.org()
        A = self.acct_by_name

        # Managed policies modeled on common provider-managed ones.
        self.policy("AdministratorAccess", doc(stmt("Allow", "*", sid="Admin")))
        self.policy(
            "PowerUserAccess",
            doc(
                stmt("Allow", not_action=["iam:*", "organizations:*"], sid="AllButIam"),
                stmt("Allow", ["iam:Get*", "iam:List*", "iam:CreateServiceLinkedRole"], sid="IamRead"),
            ),
        )
        self.policy(
            "ReadOnlyAccess",
            doc(
                stmt(
                    "Allow",
                    [
                        "s3:Get*",
                        "s3:List*",
                        "ec2:Describe*",
                        "iam:Get*",
                        "iam:List*",
                        "kms:Describe*",
                        "kms:List*",
                        "lambda:Get*",
                        "lambda:List*",
                        "dynamodb:Describe*",
                        "dynamodb:List*",
                        "logs:Describe*",
                        "logs:Get*",
                        "logs:FilterLogEvents",
                        "cloudwatch:Get*",
                        "cloudwatch:List*",
                        "cloudwatch:Describe*",
                        "sqs:Get*",
                        "sqs:List*",
                        "ecs:Describe*",
                        "ecs:List*",
                        "rds:Describe*",
                        "cloudtrail:Describe*",
                        "cloudtrail:Get*",
                        "cloudtrail:LookupEvents",
                    ],
                    sid="ReadOnly",
                )
            ),
        )
        self.policy(
            "SecurityAudit",
            doc(
                stmt(
                    "Allow",
                    [
                        "iam:Get*",
                        "iam:List*",
                        "s3:GetBucketPolicy",
                        "s3:GetBucketAcl",
                        "s3:ListAllMyBuckets",
                        "s3:GetEncryptionConfiguration",
                        "kms:GetKeyPolicy",
                        "kms:ListKeys",
                        "kms:DescribeKey",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeInstances",
                        "cloudtrail:DescribeTrails",
                        "cloudtrail:GetTrailStatus",
                        "lambda:GetFunction",
                        "lambda:ListFunctions",
                        "secretsmanager:GetResourcePolicy",
                        "organizations:Describe*",
                        "organizations:List*",
                    ],
                    sid="Audit",
                )
            ),
        )
        self.policy(
            "ForceMFA",
            doc(
                stmt(
                    "Allow",
                    [
                        "iam:ChangePassword",
                        "iam:CreateVirtualMFADevice",
                        "iam:EnableMFADevice",
                        "iam:ListMFADevices",
                        "iam:ResyncMFADevice",
                        "iam:GetUser",
                    ],
                    "arn:aws:iam::*:user/${aws:username}",
                    sid="SelfServiceMFA",
                ),
                stmt(
                    "Deny",
                    not_action=[
                        "iam:ChangePassword",
                        "iam:CreateVirtualMFADevice",
                        "iam:EnableMFADevice",
                        "iam:ListMFADevices",
                        "iam:ResyncMFADevice",
                        "iam:GetUser",
                        "sts:GetSessionToken",
                    ],
                    sid="DenyWithoutMFA",
                    condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
                ),
            ),
        )
        self.policy(
            "CorpNetworkOnly",
            doc(
                stmt(
                    "Deny",
                    "*",
                    sid="OffNetwork",
                    condition={
                        "NotIpAddress": {"aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]},
                        "Bool": {"aws:ViaAWSService": "false"},
                    },
                )
            ),
        )
        self.policy(
            "PlatformBoundary",
            doc(
                stmt(
                    "Allow",
                    not_action=[
                        "iam:CreateUser",
                        "iam:CreateAccessKey",
                        "iam:CreateLoginProfile",
                        "iam:UpdateLoginProfile",
                        "iam:AttachUserPolicy",
                        "iam:PutUserPolicy",
                        "iam:AttachRolePolicy",
                        "iam:PutRolePolicy",
                        "iam:CreatePolicyVersion",
                        "iam:SetDefaultPolicyVersion",
                        "iam:AddUserToGroup",
                        "iam:UpdateAssumeRolePolicy",
                        "organizations:*",
                    ],
                    sid="NoIdentityAdmin",
                ),
            ),
            "boundary",
        )
        self.policy(
            "DevBoundary",
            doc(
                stmt(
                    "Allow",
                    [
                        "s3:*",
                        "dynamodb:*",
                        "logs:*",
                        "lambda:*",
                        "sqs:*",
                        "sns:*",
                        "cloudwatch:*",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "ec2:Describe*",
                        "ecs:*",
                        "ecr:*",
                        "secretsmanager:GetSecretValue",
                        "sts:GetCallerIdentity",
                    ],
                    sid="AppServices",
                ),
                stmt("Allow", "iam:PassRole", "arn:aws:iam::*:role/app-*", sid="PassAppRoles"),
            ),
            "boundary",
        )

        org_cond = {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}}

        # ---------- workload resources and service roles ----------
        team_res: dict[str, dict] = {}
        for t in TEAMS:
            for env in ("prod", "staging", "dev"):
                name = f"{t}-{env}"
                if name not in A:
                    continue
                acct = A[name]
                region = "us-east-1" if t not in ("search", "ml") else "us-west-2"
                bucket = f"arn:aws:s3:::{PREFIX}-{name}-data"
                key = f"arn:aws:kms:{region}:{acct}:key/{t}-{env}-{rng.randrange(16**6):06x}"
                table = f"arn:aws:dynamodb:{region}:{acct}:table/{t}-{env}"
                queue = f"arn:aws:sqs:{region}:{acct}:{t}-{env}-events"
                secret = f"arn:aws:secretsmanager:{region}:{acct}:secret:{t}-{env}/db"
                loggroup = f"arn:aws:logs:{region}:{acct}:log-group:/app/{t}-{env}"
                key_policy = doc(
                    stmt(
                        "Allow", "kms:*", "*", sid="EnableIamPolicies", principal={"AWS": f"arn:aws:iam::{acct}:root"}
                    ),
                )
                bucket_policy = doc(
                    stmt(
                        "Deny",
                        "s3:*",
                        [bucket, bucket + "/*"],
                        sid="TlsOnly",
                        principal="*",
                        condition={"Bool": {"aws:SecureTransport": "false"}},
                    )
                )
                roles = {}
                for svc in ("api", "worker"):
                    rname = f"app-{t}-{svc}"
                    scoped = rng.random() < 0.45
                    if scoped:
                        pol = doc(
                            stmt(
                                "Allow",
                                ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                                [bucket, bucket + "/*"],
                                sid="Data",
                            ),
                            stmt(
                                "Allow",
                                ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem"],
                                table,
                                sid="Table",
                            ),
                            stmt("Allow", ["kms:Decrypt", "kms:GenerateDataKey"], key, sid="Key"),
                            stmt(
                                "Allow",
                                ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"],
                                queue,
                                sid="Queue",
                            ),
                            stmt("Allow", ["logs:CreateLogStream", "logs:PutLogEvents"], loggroup + ":*", sid="Logs"),
                            stmt("Allow", "secretsmanager:GetSecretValue", secret, sid="Secret"),
                        )
                    else:
                        pol = doc(
                            stmt(
                                "Allow",
                                [
                                    "s3:*",
                                    "dynamodb:*",
                                    "sqs:*",
                                    "sns:*",
                                    "logs:*",
                                    "kms:*",
                                    "secretsmanager:*",
                                    "cloudwatch:*",
                                ],
                                "*",
                                sid="Broad",
                            ),
                        )
                    pid = self.policy(f"{name}-{svc}", pol, "managed", acct)
                    trust = doc(
                        stmt(
                            "Allow",
                            "sts:AssumeRole",
                            None,
                            principal={
                                "Service": "lambda.amazonaws.com" if svc == "api" else "ecs-tasks.amazonaws.com"
                            },
                        )
                    )
                    r = self.role(acct, rname, "service", trust, [pid], "DevBoundary" if env == "dev" else None, t)
                    roles[svc] = r
                    if env != "dev" and rng.random() < 0.12 and svc == "worker":
                        continue  # legacy worker that no longer runs: unused principal
                    prof = self.profiles[r["arn"]]
                    obj = f"{bucket}/{svc}/batch-{rng.randint(1, 9)}.json"
                    prof += [
                        ("s3:GetObject", obj, 6),
                        ("s3:PutObject", f"{bucket}/{svc}/out.json", 3),
                        ("dynamodb:GetItem", table, 8),
                        ("dynamodb:Query", table, 5),
                        ("dynamodb:PutItem", table, 3),
                        ("kms:Decrypt", key, 4),
                        ("kms:GenerateDataKey", key, 2),
                        ("logs:PutLogEvents", f"{loggroup}:log-stream:{svc}", 6),
                        ("logs:CreateLogStream", f"{loggroup}:log-stream:{svc}", 1),
                        ("secretsmanager:GetSecretValue", secret, 0.4),
                    ]
                    prof += (
                        [("sqs:SendMessage", queue, 3)]
                        if svc == "api"
                        else [("sqs:ReceiveMessage", queue, 5), ("sqs:DeleteMessage", queue, 4)]
                    )
                    self.activity[r["arn"]] = 0.97
                    self.channel[r["arn"]] = "service"
                    if svc == "worker" and rng.random() < 0.5:
                        prof.append(("s3:ListBucket", bucket, 0.03))  # rare: shows up once or twice a quarter
                for svc in ("api", "worker"):
                    self.resource(
                        arn=f"arn:aws:lambda:{region}:{acct}:function:{t}-{env}-{svc}",
                        type="lambda_function",
                        account=acct,
                        name=f"{t}-{env}-{svc}",
                        role=roles[svc]["arn"],
                    )
                self.resource(
                    arn=bucket, type="s3_bucket", account=acct, name=f"{PREFIX}-{name}-data", policy=bucket_policy
                )
                self.resource(arn=key, type="kms_key", account=acct, name=f"{t}-{env} key", policy=key_policy)
                self.resource(arn=table, type="dynamodb_table", account=acct, name=f"{t}-{env}")
                self.resource(arn=queue, type="sqs_queue", account=acct, name=f"{t}-{env}-events")
                self.resource(arn=secret, type="secret", account=acct, name=f"{t}-{env}/db")
                team_res[name] = {
                    "acct": acct,
                    "bucket": bucket,
                    "key": key,
                    "table": table,
                    "queue": queue,
                    "secret": secret,
                    "logs": loggroup,
                    "region": region,
                }

        # Data lake shared with ml-prod across accounts, restricted to the organization.
        dp, mp = A["data-prod"], A["ml-prod"]
        lake = f"arn:aws:s3:::{PREFIX}-data-lake"
        self.resource(
            arn=lake,
            type="s3_bucket",
            account=dp,
            name=f"{PREFIX}-data-lake",
            policy=doc(
                stmt(
                    "Allow",
                    ["s3:GetObject", "s3:ListBucket"],
                    [lake, lake + "/*"],
                    sid="MlReadsCurated",
                    principal={"AWS": f"arn:aws:iam::{mp}:role/app-ml-worker"},
                ),
                stmt(
                    "Allow", "s3:GetObject", lake + "/shared/*", sid="OrgReadsShared", principal="*", condition=org_cond
                ),
            ),
        )
        team_res["data-prod"]["lake"] = lake
        # ml-prod worker gets the matching identity grant, so the cross-account read works.
        ml_worker = next(p for p in self.principals if p["arn"] == f"arn:aws:iam::{mp}:role/app-ml-worker")
        self.policy(
            "ml-prod-lake-read",
            doc(stmt("Allow", ["s3:GetObject", "s3:ListBucket"], [lake, lake + "/*"], sid="LakeRead")),
            "managed",
            mp,
        )
        ml_worker["policies"].append("ml-prod-lake-read")
        self.profiles[ml_worker["arn"]] += [
            ("s3:GetObject", f"{lake}/curated/features-2026.parquet", 6),
            ("s3:ListBucket", lake, 2),
        ]
        self.activity[ml_worker["arn"]] = 0.97
        self.channel[ml_worker["arn"]] = "service"

        # Public resource policies: static assets (intended), an export bucket (mistake), a key policy (mistake).
        wp, cs = A["web-prod"], A["catalog-staging"]
        assets = f"arn:aws:s3:::{PREFIX}-web-prod-assets"
        self.resource(
            arn=assets,
            type="s3_bucket",
            account=wp,
            name=f"{PREFIX}-web-prod-assets",
            policy=doc(stmt("Allow", "s3:GetObject", assets + "/*", sid="PublicAssets", principal="*")),
        )
        exports = f"arn:aws:s3:::{PREFIX}-catalog-staging-exports"
        self.resource(
            arn=exports,
            type="s3_bucket",
            account=cs,
            name=f"{PREFIX}-catalog-staging-exports",
            policy=doc(
                stmt(
                    "Allow",
                    ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    [exports, exports + "/*"],
                    sid="PartnerUpload",
                    principal={"AWS": "*"},
                )
            ),
        )
        drop = f"arn:aws:s3:::{PREFIX}-partner-drop"
        self.resource(
            arn=drop,
            type="s3_bucket",
            account=A["shared-services"],
            name=f"{PREFIX}-partner-drop",
            policy=doc(stmt("Allow", "s3:PutObject", drop + "/*", sid="OrgOnly", principal="*", condition=org_cond)),
        )
        bkey = f"arn:aws:kms:us-east-1:{A['billing-staging']}:key/billing-export-7c1f2a"
        self.resource(
            arn=bkey,
            type="kms_key",
            account=A["billing-staging"],
            name="billing export key",
            policy=doc(
                stmt(
                    "Allow",
                    "kms:*",
                    "*",
                    sid="EnableIamPolicies",
                    principal={"AWS": f"arn:aws:iam::{A['billing-staging']}:root"},
                ),
                stmt("Allow", ["kms:Decrypt", "kms:DescribeKey"], "*", sid="AnyoneDecrypt", principal={"AWS": "*"}),
            ),
        )

        # ---------- humans ----------
        ss = A["shared-services"]
        vp, _ = self.person_name()
        cto_u, cto_n = self.person_name()
        cto = self.add(
            arn=f"arn:aws:iam::{ss}:user/{cto_u}",
            name=cto_u,
            display_name=cto_n,
            type="user",
            account=ss,
            kind="human",
            team="leadership",
            console=True,
            mfa=True,
            manager=None,
            title="CTO",
            created=self.past_date(900, 1400),
            groups=[],
        )
        vpe_u, vpe_n = self.person_name()
        vpe = self.add(
            arn=f"arn:aws:iam::{ss}:user/{vpe_u}",
            name=vpe_u,
            display_name=vpe_n,
            type="user",
            account=ss,
            kind="human",
            team="leadership",
            console=True,
            mfa=True,
            manager=cto["arn"],
            title="VP Engineering",
            created=self.past_date(700, 1200),
        )
        self.groups["all-staff-mfa"] = {"name": "all-staff-mfa", "account": "*", "policies": ["ForceMFA"]}
        enforce_mfa_teams = {
            "orders",
            "payments",
            "catalog",
            "data",
            "ml",
            "billing",
            "platform",
            "security",
            "finance",
            "leadership",
        }

        def human(acct, team, title, manager, groups, profile, active=0.7, mfa_p=0.88):
            u, n = self.person_name()
            p = self.add(
                arn=f"arn:aws:iam::{acct}:user/{u}",
                name=u,
                display_name=n,
                type="user",
                account=acct,
                kind="human",
                team=team,
                title=title,
                manager=manager,
                console=rng.random() < 0.93,
                mfa=rng.random() < (0.98 if team in enforce_mfa_teams else mfa_p),
                groups=list(groups),
                created=self.past_date(60, 1300),
                tags={"team": team},
            )
            if team in enforce_mfa_teams:
                p["groups"].append("all-staff-mfa")
            self.keys(p)
            self.profiles[p["arn"]] = list(profile)
            gone = rng.random() < 0.07
            self.activity[p["arn"]] = 0.0 if gone else active
            self.channel[p["arn"]] = "console" if p["console"] else "cli"
            return p

        for u in (cto, vpe):
            u["groups"].append("all-staff-mfa")
            self.activity[u["arn"]] = 0.3
            self.channel[u["arn"]] = "console"
            self.profiles[u["arn"]] = [("ce:GetCostAndUsage", "*", 2), ("cloudwatch:GetMetricData", "*", 1)]
        self.policy(
            "LeadershipReadOnly",
            doc(
                stmt(
                    "Allow",
                    [
                        "ce:Get*",
                        "cloudwatch:Get*",
                        "cloudwatch:List*",
                        "organizations:Describe*",
                        "organizations:List*",
                    ],
                    sid="Leadership",
                )
            ),
        )
        self.groups["leadership"] = {"name": "leadership", "account": ss, "policies": ["LeadershipReadOnly"]}
        for u in (cto, vpe):
            u["groups"].append("leadership")
        _ = vp

        for t in TEAMS:
            name = f"{t}-prod"
            acct = A[name]
            r = team_res[name]
            broad = t in ("search", "fulfillment", "web", "support", "ml")
            gname = f"eng-{t}"
            if broad:
                gpols = ["PowerUserAccess"]
            else:
                pid = self.policy(
                    f"{t}-developer",
                    doc(
                        stmt(
                            "Allow",
                            ["s3:Get*", "s3:List*", "s3:PutObject"],
                            [r["bucket"], r["bucket"] + "/*"],
                            sid="TeamData",
                        ),
                        stmt("Allow", ["dynamodb:*"], r["table"], sid="TeamTable"),
                        stmt(
                            "Allow",
                            ["logs:*", "cloudwatch:*", "ec2:Describe*", "ecs:*", "lambda:*", "sqs:*"],
                            "*",
                            sid="Operate",
                        ),
                        stmt("Allow", ["kms:Decrypt", "kms:DescribeKey"], r["key"], sid="TeamKey"),
                        *([stmt("Allow", ["athena:*", "glue:Get*"], "*", sid="Analytics")] if t == "data" else []),
                    ),
                    "managed",
                    acct,
                )
                gpols = [pid]
            self.groups[gname] = {"name": gname, "account": acct, "policies": gpols}
            prof = [
                ("logs:GetLogEvents", r["logs"] + ":log-stream:api", 5),
                ("logs:FilterLogEvents", r["logs"], 3),
                ("cloudwatch:GetMetricData", "*", 4),
                ("ec2:DescribeInstances", "*", 1.5),
                ("s3:GetObject", r["bucket"] + "/api/batch-1.json", 2),
                ("s3:ListBucket", r["bucket"], 2),
                ("dynamodb:GetItem", r["table"], 2.5),
                ("dynamodb:Query", r["table"], 1.5),
                ("dynamodb:DescribeTable", r["table"], 0.6),
                ("lambda:GetFunction", f"arn:aws:lambda:{r['region']}:{acct}:function:{t}-prod-api", 1),
                ("kms:Decrypt", r["key"], 1),
                ("sqs:GetQueueAttributes", r["queue"], 0.6),
                (
                    "lambda:UpdateFunctionConfiguration",
                    f"arn:aws:lambda:{r['region']}:{acct}:function:{t}-prod-api",
                    0.03,
                ),
            ]
            if t == "data":
                prof += [
                    ("athena:StartQueryExecution", f"arn:aws:athena:us-east-1:{acct}:workgroup/analysts", 4),
                    ("athena:GetQueryResults", f"arn:aws:athena:us-east-1:{acct}:workgroup/analysts", 4),
                    ("glue:GetTable", f"arn:aws:glue:us-east-1:{acct}:table/curated/orders", 2),
                ]
            mgr_u, mgr_n = self.person_name()
            mgr = self.add(
                arn=f"arn:aws:iam::{acct}:user/{mgr_u}",
                name=mgr_u,
                display_name=mgr_n,
                type="user",
                account=acct,
                kind="human",
                team=t,
                title=f"{t.title()} engineering manager",
                manager=vpe["arn"],
                console=True,
                mfa=True,
                groups=[gname],
                created=self.past_date(300, 1300),
                tags={"team": t},
            )
            if t in enforce_mfa_teams:
                mgr["groups"].append("all-staff-mfa")
            self.profiles[mgr["arn"]] = prof[:5]
            self.activity[mgr["arn"]] = 0.4
            self.channel[mgr["arn"]] = "console"
            n = rng.randint(10, 14)
            for _ in range(n):
                human(acct, t, "Engineer", mgr["arn"], [gname], prof, active=rng.choice([0.5, 0.65, 0.8]))
            if t == "orders":
                # A shared ops role any orders engineer can assume, which can attach policies to roles.
                self.policy(
                    "orders-prod-ops",
                    doc(
                        stmt("Allow", ["ecs:*", "lambda:*", "logs:*"], "*", sid="Ops"),
                        stmt(
                            "Allow",
                            ["iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies"],
                            f"arn:aws:iam::{acct}:role/*",
                            sid="ManageRolePolicies",
                        ),
                    ),
                    "managed",
                    acct,
                )
                self.role(
                    acct,
                    "orders-prod-ops",
                    "automation",
                    doc(stmt("Allow", "sts:AssumeRole", None, principal={"AWS": f"arn:aws:iam::{acct}:root"})),
                    ["orders-prod-ops"],
                    team=t,
                )
                self.policy(
                    "orders-assume-ops",
                    doc(stmt("Allow", "sts:AssumeRole", f"arn:aws:iam::{acct}:role/orders-prod-ops", sid="AssumeOps")),
                    "managed",
                    acct,
                )
                self.groups[gname]["policies"].append("orders-assume-ops")
            if t == "payments":
                self.policy("payments-prod-maintenance", doc(stmt("Allow", "*", sid="Maintenance")), "managed", acct)
                self.role(
                    acct,
                    "payments-prod-maintenance",
                    "automation",
                    doc(stmt("Allow", "sts:AssumeRole", None, principal={"Service": "lambda.amazonaws.com"})),
                    ["AdministratorAccess"],
                    team=t,
                )

        # Platform, security, IT helpdesk, finance in shared-services.
        def team_lead(team, title):
            u, n = self.person_name()
            p = self.add(
                arn=f"arn:aws:iam::{ss}:user/{u}",
                name=u,
                display_name=n,
                type="user",
                account=ss,
                kind="human",
                team=team,
                title=title,
                manager=vpe["arn"] if team != "finance" else cto["arn"],
                console=True,
                mfa=True,
                groups=["all-staff-mfa"],
                created=self.past_date(300, 1300),
                tags={"team": team},
            )
            self.activity[p["arn"]] = 0.5
            self.channel[p["arn"]] = "console"
            return p

        self.groups["platform-admins"] = {"name": "platform-admins", "account": ss, "policies": ["AdministratorAccess"]}
        self.policy(
            "platform-engineer",
            doc(
                stmt(
                    "Allow",
                    [
                        "ec2:*",
                        "ecs:*",
                        "ecr:*",
                        "lambda:*",
                        "cloudformation:*",
                        "logs:*",
                        "cloudwatch:*",
                        "s3:*",
                        "kms:*",
                        "iam:*",
                    ],
                    "*",
                    sid="PlatformOps",
                ),
            ),
            "managed",
            ss,
        )
        self.groups["platform-eng"] = {"name": "platform-eng", "account": ss, "policies": ["platform-engineer"]}
        plat = team_lead("platform", "Platform lead")
        plat["groups"].append("platform-admins")
        plat_prof = [
            ("ec2:DescribeInstances", "*", 3),
            ("ecs:DescribeServices", f"arn:aws:ecs:us-east-1:{ss}:service/core/gateway", 2),
            ("cloudformation:DescribeStacks", "*", 3),
            ("logs:FilterLogEvents", f"arn:aws:logs:us-east-1:{ss}:log-group:/platform/gateway", 2),
            ("iam:GetRole", f"arn:aws:iam::{ss}:role/ops-automation", 0.5),
            ("cloudformation:UpdateStack", f"arn:aws:cloudformation:us-east-1:{ss}:stack/core-network/1", 0.3),
            ("lambda:UpdateFunctionCode", f"arn:aws:lambda:us-east-1:{ss}:function:ops-automation-runner", 0.05),
        ]
        self.profiles[plat["arn"]] = plat_prof
        for i in range(12):
            p = human(ss, "platform", "Platform engineer", plat["arn"], ["platform-eng"], plat_prof, active=0.75)
            if i < 3:
                p["groups"] = ["platform-admins", "all-staff-mfa"]
            else:
                p["boundary"] = "PlatformBoundary"
        sec = team_lead("security", "Security lead")
        self.policy(
            "security-ops",
            doc(
                stmt(
                    "Allow",
                    ["iam:*", "kms:Describe*", "kms:GetKeyPolicy", "cloudtrail:*", "s3:GetBucketPolicy", "guardduty:*"],
                    "*",
                    sid="SecOps",
                ),
            ),
            "managed",
            ss,
        )
        self.groups["security-ops"] = {
            "name": "security-ops",
            "account": ss,
            "policies": ["SecurityAudit", "security-ops"],
        }
        sec["groups"].append("security-ops")
        sec_prof = [
            ("iam:ListRoles", "*", 3),
            ("iam:GetRole", f"arn:aws:iam::{ss}:role/breakglass-admin", 1),
            ("cloudtrail:LookupEvents", "*", 4),
            ("s3:GetBucketPolicy", drop, 1),
            ("kms:GetKeyPolicy", f"arn:aws:kms:us-east-1:{ss}:key/platform-a1", 0.6),
            ("iam:ListAccessKeys", f"arn:aws:iam::{ss}:user/{plat['name']}", 1),
        ]
        self.profiles[sec["arn"]] = sec_prof
        for _ in range(7):
            human(ss, "security", "Security engineer", sec["arn"], ["security-ops"], sec_prof, active=0.7)
        self.policy(
            "it-helpdesk",
            doc(
                stmt(
                    "Allow",
                    [
                        "iam:CreateLoginProfile",
                        "iam:UpdateLoginProfile",
                        "iam:CreateAccessKey",
                        "iam:ListAccessKeys",
                        "iam:GetUser",
                        "iam:ListUsers",
                    ],
                    f"arn:aws:iam::{ss}:user/*",
                    sid="ResetCredentials",
                ),
            ),
            "managed",
            ss,
        )
        self.groups["it-helpdesk"] = {"name": "it-helpdesk", "account": ss, "policies": ["it-helpdesk"]}
        hd_prof = [
            ("iam:ListUsers", "*", 3),
            ("iam:GetUser", f"arn:aws:iam::{ss}:user/{sec['name']}", 2),
            ("iam:UpdateLoginProfile", f"arn:aws:iam::{ss}:user/{plat['name']}", 0.2),
        ]
        for _ in range(3):
            human(ss, "it", "IT helpdesk", vpe["arn"], ["it-helpdesk"], hd_prof, active=0.8, mfa_p=0.6)
        fin = team_lead("finance", "Finance lead")
        self.policy(
            "finance-reporting",
            doc(
                stmt("Allow", ["ce:*", "s3:GetObject", "s3:ListBucket"], "*", sid="Costs"),
            ),
            "managed",
            ss,
        )
        self.groups["finance"] = {
            "name": "finance",
            "account": ss,
            "policies": ["finance-reporting", "CorpNetworkOnly"],
        }
        fin["groups"].append("finance")
        fin_prof = [
            ("ce:GetCostAndUsage", "*", 5),
            ("ce:GetCostForecast", "*", 1),
            ("s3:GetObject", f"arn:aws:s3:::{PREFIX}-billing-prod-data/cur/2026-10.csv", 1),
        ]
        self.profiles[fin["arn"]] = fin_prof
        for _ in range(6):
            human(ss, "finance", "Financial analyst", fin["arn"], ["finance"], fin_prof, active=0.6)
        rm = human(
            ss,
            "platform",
            "Release manager",
            plat["arn"],
            [],
            [("iam:GetRole", f"arn:aws:iam::{ss}:role/breakglass-admin", 0.3)],
            active=0.5,
        )
        self.policy(
            "release-manager",
            doc(
                stmt(
                    "Allow",
                    ["iam:GetRole", "iam:UpdateAssumeRolePolicy"],
                    f"arn:aws:iam::{ss}:role/*",
                    sid="ManageTrust",
                )
            ),
            "managed",
            ss,
        )
        rm["policies"].append("release-manager")
        self.activity[rm["arn"]] = 0.5

        # Shared-services resources used in escalation paths.
        auto = self.role(
            ss,
            "ops-automation",
            "automation",
            doc(stmt("Allow", "sts:AssumeRole", None, principal={"Service": "lambda.amazonaws.com"})),
            ["AdministratorAccess"],
            team="platform",
        )
        self.resource(
            arn=f"arn:aws:lambda:us-east-1:{ss}:function:ops-automation-runner",
            type="lambda_function",
            account=ss,
            name="ops-automation-runner",
            role=auto["arn"],
        )
        self.profiles[auto["arn"]] = [
            ("ec2:DescribeInstances", "*", 2),
            ("ec2:CreateSnapshot", f"arn:aws:ec2:us-east-1:{ss}:volume/vol-0a1", 1),
            ("rds:CreateDBSnapshot", f"arn:aws:rds:us-east-1:{ss}:db:core", 0.2),
        ]
        self.activity[auto["arn"]] = 0.9
        self.channel[auto["arn"]] = "service"
        bg_trust = doc(
            stmt(
                "Allow",
                "sts:AssumeRole",
                None,
                principal={"AWS": [plat["arn"], sec["arn"]]},
                condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                sid="TwoPeopleWithMFA",
            )
        )
        self.role(ss, "breakglass-admin", "breakglass", bg_trust, ["AdministratorAccess"], team="security")

        # Machine users with long-lived keys (the legacy pattern).
        for acct_name, uname, pols in (
            ("billing-prod", "svc-invoice-export", ["billing-developer"]),
            ("fulfillment-prod", "svc-carrier-sync", ["PowerUserAccess"]),
            ("shared-services", "svc-legacy-backup", ["AdministratorAccess"]),
            ("catalog-prod", "svc-feed-publisher", ["catalog-developer"]),
        ):
            acct = A[acct_name]
            p = self.add(
                arn=f"arn:aws:iam::{acct}:user/{uname}",
                name=uname,
                display_name=uname,
                type="user",
                account=acct,
                kind="service",
                team=acct_name.split("-")[0],
                console=False,
                mfa=False,
                policies=list(pols),
                created=self.past_date(900, 1500),
            )
            created = AS_OF - timedelta(days=rng.choice([420, 610, 980]))
            p["access_keys"].append(
                {
                    "id": f"key-{len(self.principals):04d}m",
                    "status": "Active",
                    "created": created.isoformat(),
                    "last_used": (AS_OF - timedelta(days=1)).isoformat(),
                }
            )
            r = team_res.get(acct_name)
            if r:
                self.profiles[p["arn"]] = [
                    ("s3:PutObject", r["bucket"] + "/export/daily.csv", 3),
                    ("dynamodb:Scan", r["table"], 1),
                ]
                self.activity[p["arn"]] = 0.95
            else:
                self.activity[p["arn"]] = 0.0
            self.channel[p["arn"]] = "cli"

        # ---------- CI ----------
        tc = A["tooling-ci"]
        runner = self.role(
            tc,
            "ci-runner",
            "ci",
            doc(stmt("Allow", "sts:AssumeRole", None, principal={"Service": "ec2.amazonaws.com"})),
            [
                self.policy(
                    "ci-runner-assume",
                    doc(stmt("Allow", "sts:AssumeRole", "arn:aws:iam::*:role/ci-deploy", sid="Deploy")),
                    "managed",
                    tc,
                )
            ],
            team="platform",
        )
        self.activity[runner["arn"]] = 0.95
        self.channel[runner["arn"]] = "service"
        for name, r in team_res.items():
            acct = r["acct"]
            env = name.rsplit("-", 1)[1]
            fn = f"arn:aws:lambda:{r['region']}:{acct}:function:{name}-api"
            if env == "prod" and rng.random() < 0.5:
                pols = ["AdministratorAccess"]
            else:
                pols = [
                    self.policy(
                        f"{name}-ci-deploy",
                        doc(
                            stmt(
                                "Allow",
                                [
                                    "lambda:UpdateFunctionCode",
                                    "lambda:GetFunction",
                                    "lambda:PublishVersion",
                                    "lambda:CreateFunction",
                                    "lambda:InvokeFunction",
                                ],
                                "*",
                                sid="Lambda",
                            ),
                            stmt(
                                "Allow", ["s3:PutObject", "s3:GetObject"], r["bucket"] + "/releases/*", sid="Artifacts"
                            ),
                            stmt("Allow", "iam:PassRole", "*", sid="PassAnyRole"),
                            stmt(
                                "Allow",
                                ["ecr:*", "ecs:UpdateService", "ecs:DescribeServices", "ecs:RegisterTaskDefinition"],
                                "*",
                                sid="Containers",
                            ),
                        ),
                        "managed",
                        acct,
                    )
                ]
            ci = self.role(
                acct,
                "ci-deploy",
                "ci",
                doc(
                    stmt(
                        "Allow",
                        "sts:AssumeRole",
                        None,
                        principal={"AWS": runner["arn"]},
                        condition=org_cond,
                        sid="FromRunner",
                    )
                ),
                pols,
                team=name.split("-")[0],
            )
            self.profiles[ci["arn"]] = [
                ("lambda:UpdateFunctionCode", fn, 2),
                ("lambda:GetFunction", fn, 2),
                ("lambda:PublishVersion", fn, 1),
                ("s3:PutObject", r["bucket"] + "/releases/build.zip", 2),
                ("ecr:GetAuthorizationToken", "*", 1),
            ]
            self.activity[ci["arn"]] = 0.6
            self.channel[ci["arn"]] = "service"
            self.profiles[runner["arn"]].append(("sts:AssumeRole", ci["arn"], 1))

        # ---------- vendors ----------
        def vendor(acct_name, name, ext, external_id, policies, prof, active):
            trust_cond = {"StringEquals": {"sts:ExternalId": external_id}} if external_id else None
            p = self.role(
                A[acct_name],
                name,
                "vendor",
                doc(
                    stmt(
                        "Allow",
                        "sts:AssumeRole",
                        None,
                        principal={"AWS": f"arn:aws:iam::{ext}:root"},
                        condition=trust_cond,
                        sid="Vendor",
                    )
                ),
                policies,
                team="vendors",
            )
            self.profiles[p["arn"]] = prof
            self.activity[p["arn"]] = active
            self.channel[p["arn"]] = "service"

        self.policy(
            "vendor-monitoring",
            doc(
                stmt(
                    "Allow",
                    ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics", "ec2:DescribeInstances", "ecs:Describe*"],
                    "*",
                    sid="Metrics",
                )
            ),
        )
        vendor(
            "shared-services",
            "vendor-parcelwise-monitoring",
            "444455556666",
            "pw-7f3a91",
            ["vendor-monitoring"],
            [("cloudwatch:GetMetricData", "*", 6), ("cloudwatch:ListMetrics", "*", 1)],
            0.98,
        )
        vendor(
            "billing-prod",
            "vendor-ledgerly-billing",
            "777788889999",
            "ldg-20931",
            [
                self.policy(
                    "vendor-ledgerly",
                    doc(
                        stmt(
                            "Allow",
                            ["s3:GetObject", "s3:ListBucket"],
                            [team_res["billing-prod"]["bucket"], team_res["billing-prod"]["bucket"] + "/invoices/*"],
                            sid="Invoices",
                        )
                    ),
                    "managed",
                    A["billing-prod"],
                )
            ],
            [("s3:GetObject", team_res["billing-prod"]["bucket"] + "/invoices/2026-10.pdf", 3)],
            0.6,
        )
        vendor(
            "search-prod",
            "vendor-quillsearch-indexer",
            "999988887777",
            None,
            ["PowerUserAccess"],
            [
                ("dynamodb:Scan", team_res["search-prod"]["table"], 4),
                ("s3:GetObject", team_res["search-prod"]["bucket"] + "/index/latest.json", 2),
            ],
            0.9,
        )
        vendor("shared-services", "vendor-tapevault-backup", "555566667777", None, ["ReadOnlyAccess"], [], 0.0)
        vendor(
            "management",
            "vendor-costwise",
            "222233334444",
            "cw-55120",
            [self.policy("vendor-cost", doc(stmt("Allow", ["ce:*", "organizations:ListAccounts"], "*", sid="Costs")))],
            [("ce:GetCostAndUsage", "*", 3), ("organizations:ListAccounts", "*", 1)],
            0.5,
        )

        # ---------- security audit role in every account ----------
        st = A["security-tooling"]
        scanner = self.role(
            st,
            "security-scanner",
            "audit",
            doc(stmt("Allow", "sts:AssumeRole", None, principal={"Service": "ecs-tasks.amazonaws.com"})),
            [
                self.policy(
                    "scanner-assume",
                    doc(stmt("Allow", "sts:AssumeRole", "arn:aws:iam::*:role/security-audit", sid="Audit")),
                    "managed",
                    st,
                )
            ],
            team="security",
        )
        self.activity[scanner["arn"]] = 0.14
        self.channel[scanner["arn"]] = "service"
        for a in self.accounts:
            if a["env"] == "suspended":
                continue
            r = self.role(
                a["id"],
                "security-audit",
                "audit",
                doc(stmt("Allow", "sts:AssumeRole", None, principal={"AWS": scanner["arn"]}, sid="Scanner")),
                ["SecurityAudit"],
                team="security",
            )
            active = 0.14 if a["env"] != "sandbox" or rng.random() < 0.4 else 0.0
            self.activity[r["arn"]] = active
            self.channel[r["arn"]] = "service"
            self.profiles[r["arn"]] = [
                ("iam:ListRoles", "*", 2),
                ("s3:ListAllMyBuckets", "*", 1),
                ("ec2:DescribeSecurityGroups", "*", 1),
                ("cloudtrail:DescribeTrails", "*", 1),
                ("kms:ListKeys", "*", 1),
            ]
            if active:
                self.profiles[scanner["arn"]].append(("sts:AssumeRole", r["arn"], 0.3))
        # Sandbox experimenters: admin by policy, cut down by the sandbox SCP.
        for i in range(1, 4):
            acct = A[f"sandbox-{i}"]
            r = self.role(
                acct,
                "sandbox-admin",
                "automation",
                doc(stmt("Allow", "sts:AssumeRole", None, principal={"Service": "lambda.amazonaws.com"})),
                ["AdministratorAccess"],
                team="platform",
            )
            self.profiles[r["arn"]] = [
                ("ec2:RunInstances", "*", 1),
                ("s3:PutObject", f"arn:aws:s3:::{PREFIX}-sandbox-{i}/tmp/x", 2),
                ("iam:CreateRole", f"arn:aws:iam::{acct}:role/experiment", 0.2),
            ]
            self.activity[r["arn"]] = 0.3
            self.channel[r["arn"]] = "service"
        # Org admin role in the management account (SCPs do not apply there).
        self.role(
            MGMT,
            "org-admin",
            "breakglass",
            doc(
                stmt(
                    "Allow",
                    "sts:AssumeRole",
                    None,
                    principal={"AWS": cto["arn"]},
                    condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                )
            ),
            ["AdministratorAccess"],
            team="leadership",
        )

    # ---------- logs ----------
    def ip_for(self, arn: str) -> str:
        ch = self.channel.get(arn, "console")
        if ch == "service":
            return f"10.{self.rng.randint(20, 60)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        pool = CORP_IPS if self.rng.random() < 0.8 else HOME_IPS
        return f"{self.rng.choice(pool)}{self.rng.randint(2, 250)}"

    def events(self, env) -> list[dict]:
        from .engine import is_allowed

        rng = self.rng
        start = AS_OF - timedelta(days=DAYS)
        out = []
        cache: dict[tuple, bool] = {}
        by_arn = {p["arn"]: p for p in self.principals}
        for day in range(DAYS):
            d = start + timedelta(days=day)
            weekday = d.weekday() < 5
            for arn, prof in self.profiles.items():
                if not prof:
                    continue
                p = by_arn[arn]
                act = self.activity.get(arn, 0.0)
                if p["kind"] == "human" and not weekday:
                    act *= 0.1
                if rng.random() >= act:
                    continue
                total = sum(w for _, _, w in prof)
                n = 1 + min(6, int(rng.expovariate(1 / 2.5)))
                ch = self.channel.get(arn, "console")
                for _ in range(n):
                    x = rng.random() * total
                    pick = prof[-1]
                    for item in prof:
                        x -= item[2]
                        if x <= 0:
                            pick = item
                            break
                    action, res, w = pick
                    if w < 0.1 and rng.random() > w * 4:
                        continue
                    ip = self.ip_for(arn)
                    mfa = p.get("mfa", False) and ch == "console"
                    ctx = {"aws:SourceIp": ip}
                    if p["type"] == "user":
                        ctx["aws:MultiFactorAuthPresent"] = "true" if mfa else "false"
                        ctx["aws:ViaAWSService"] = "false"
                    key = (arn, action, res, mfa, ip.split(".")[0] + ip.split(".")[1])
                    if key not in cache:
                        cache[key] = is_allowed(env, arn, action, res, ctx)
                    ts = datetime(
                        d.year,
                        d.month,
                        d.day,
                        rng.randint(6, 21) if ch != "service" else rng.randint(0, 23),
                        rng.randint(0, 59),
                        rng.randint(0, 59),
                    )
                    ev = {
                        "t": ts.isoformat() + "Z",
                        "p": arn,
                        "a": action,
                        "r": res,
                        "ip": ip,
                        "res": "allowed" if cache[key] else "denied",
                    }
                    if p["type"] == "user":
                        ev["mfa"] = mfa
                    out.append(ev)
        out.sort(key=lambda e: e["t"])
        return out


def build(seed: int = 7) -> tuple[dict, list[dict]]:
    from .model import Environment

    b = Builder(seed)
    b.build()
    data = {
        "company": COMPANY,
        "as_of": AS_OF.isoformat(),
        "seed": seed,
        "note": "Synthetic. Account ids are placeholders in the style of provider documentation, not real accounts.",
        "organization": {"id": ORG_ID, "management_account": MGMT, "nodes": b.nodes},
        "accounts": b.accounts,
        "external_accounts": EXTERNAL,
        "policies": b.policies,
        "groups": list(b.groups.values()),
        "principals": b.principals,
        "resources": b.resources,
    }
    env = Environment(data)
    return data, b.events(env)


def write(out: Path, seed: int = 7) -> dict:
    data, events = build(seed)
    out.mkdir(parents=True, exist_ok=True)
    (out / "environment.json").write_text(json.dumps(data, indent=1) + "\n")
    with gzip.GzipFile(out / "access_logs.jsonl.gz", "wb", mtime=0) as f:
        for e in events:
            f.write((json.dumps(e, separators=(",", ":")) + "\n").encode())
    return {
        "principals": len(data["principals"]),
        "accounts": len(data["accounts"]),
        "events": len(events),
        "policies": len(data["policies"]),
        "resources": len(data["resources"]),
    }
