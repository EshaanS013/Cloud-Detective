"""Repeatable, harmless CloudTrail-shaped stories for the presentation workspace.

This module only builds JSON. It never invokes an AWS API or changes a resource.
All identities use the non-existent account 000000000000 and all addresses use
documentation-only IP ranges. Event IDs are stable, so ingestion is idempotent.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

ACCOUNT = "000000000000"
REGION = "ap-southeast-2"

SCENARIOS = {
    "CD-DEMO-101": (
        "Password guessing followed by a login without MFA",
        "Five failed console sign-ins from one address precede a successful sign-in without MFA.",
    ),
    "CD-DEMO-102": (
        "New identity gains administrator privileges",
        "An operator creates a user and key, attaches AdministratorAccess, then broadens access.",
    ),
    "CD-DEMO-103": (
        "Storage protections removed",
        "Public-access blocking, encryption and policy controls change on an example bucket.",
    ),
    "CD-DEMO-104": (
        "Audit and encryption safeguards changed",
        "CloudTrail logging is stopped and an example KMS key is scheduled for deletion.",
    ),
    "CD-DEMO-105": (
        "Compute and database exposure",
        "An example database is made public while a sandbox-style CPU alarm fires.",
    ),
    "CD-DEMO-106": (
        "Permission-denied API enumeration",
        "One identity receives fifteen AccessDenied responses in five minutes.",
    ),
    "CD-DEMO-107": (
        "Distributed password guessing",
        "Ten failed sign-ins for one identity arrive from different documentation IP addresses.",
    ),
    "CD-DEMO-108": (
        "Root identity used",
        "The example root identity makes an API call that merits human review.",
    ),
    "CD-DEMO-109": (
        "Routine activity for comparison",
        "Successful read-only calls provide contrast with the suspicious stories.",
    ),
}


def _identity(name: str, *, root: bool = False, mfa: bool = True) -> dict:
    return {
        "type": "Root" if root else "IAMUser",
        "arn": f"arn:aws:iam::{ACCOUNT}:root" if root else f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "userName": "root" if root else name,
        "sessionContext": {"attributes": {"mfaAuthenticated": str(mfa).lower()}},
    }


def _event(
    case_id: str,
    step: int,
    when: datetime,
    name: str,
    service: str,
    actor: str,
    address: str,
    *,
    params: dict | None = None,
    resources: list[str] | None = None,
    error: str | None = None,
    error_message: str | None = None,
    root: bool = False,
    mfa: bool = True,
    read_only: bool = False,
) -> dict:
    title, summary = SCENARIOS[case_id]
    item = {
        "eventID": str(uuid5(NAMESPACE_URL, f"cloud-detective-presentation-v2:{case_id}:{step}")),
        "eventTime": when.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "eventName": name,
        "eventSource": service,
        "awsRegion": REGION,
        "sourceIPAddress": address,
        "userAgent": "CloudDetectivePresentation/2.0 (synthetic)",
        "readOnly": read_only,
        "userIdentity": _identity(actor, root=root, mfa=mfa),
        "requestParameters": params or {},
        "resources": [{"ARN": arn} for arn in (resources or [])],
        "additionalEventData": {
            "simulation": True,
            "presentationScenario": case_id,
            "scenarioTitle": title,
            "scenarioSummary": summary,
        },
    }
    if error:
        item["errorCode"] = error
    if error_message:
        item["errorMessage"] = error_message
    return item


def presentation_events(now: datetime | None = None) -> list[dict]:
    """Build 50 recent, deterministic-ID events in nine labelled case stories."""
    anchor = (now or datetime.now(UTC)).astimezone(UTC) - timedelta(minutes=48)
    events: list[dict] = []

    def add(
        case: str,
        step: int,
        minute: int,
        name: str,
        service: str,
        actor: str,
        ip: str,
        **kw: object,
    ) -> None:
        events.append(
            _event(
                case,
                step,
                anchor + timedelta(minutes=minute, seconds=step * 4),
                name,
                service,
                actor,
                ip,
                **kw,
            )
        )

    for step in range(5):
        add(
            "CD-DEMO-101",
            step,
            0,
            "ConsoleLogin",
            "signin.amazonaws.com",
            "demo-analyst-101",
            "203.0.113.41",
            error="Failed authentication",
            error_message="Invalid username or password (synthetic example)",
            mfa=False,
        )
    add(
        "CD-DEMO-101",
        5,
        0,
        "ConsoleLogin",
        "signin.amazonaws.com",
        "demo-analyst-101",
        "203.0.113.41",
        mfa=False,
    )

    actor = "demo-operator-102"
    identity_resource = f"arn:aws:iam::{ACCOUNT}:user/demo-new-user-102"
    role_resource = f"arn:aws:iam::{ACCOUNT}:role/demo-audit-role-102"
    add(
        "CD-DEMO-102",
        0,
        5,
        "CreateUser",
        "iam.amazonaws.com",
        actor,
        "198.51.100.21",
        params={"userName": "demo-new-user-102"},
        resources=[identity_resource],
    )
    add(
        "CD-DEMO-102",
        1,
        5,
        "CreateAccessKey",
        "iam.amazonaws.com",
        actor,
        "198.51.100.21",
        params={"userName": "demo-new-user-102"},
        resources=[identity_resource],
    )
    add(
        "CD-DEMO-102",
        2,
        5,
        "AttachUserPolicy",
        "iam.amazonaws.com",
        actor,
        "198.51.100.21",
        params={
            "userName": "demo-new-user-102",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        resources=[identity_resource],
    )
    add(
        "CD-DEMO-102",
        3,
        5,
        "PutRolePolicy",
        "iam.amazonaws.com",
        actor,
        "198.51.100.21",
        params={
            "roleName": "demo-audit-role-102",
            "policyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        },
        resources=[role_resource],
    )
    add(
        "CD-DEMO-102",
        4,
        5,
        "UpdateAssumeRolePolicy",
        "iam.amazonaws.com",
        actor,
        "198.51.100.21",
        params={"roleName": "demo-audit-role-102"},
        resources=[role_resource],
    )
    add(
        "CD-DEMO-102",
        5,
        5,
        "CreatePolicyVersion",
        "iam.amazonaws.com",
        actor,
        "198.51.100.21",
        params={"setAsDefault": True},
        resources=[role_resource],
    )

    bucket = "cloud-detective-demo-bucket-103-never-created"
    bucket_arn = f"arn:aws:s3:::{bucket}"
    actor = "demo-storage-admin-103"
    add(
        "CD-DEMO-103",
        0,
        11,
        "DeletePublicAccessBlock",
        "s3.amazonaws.com",
        actor,
        "203.0.113.103",
        params={"bucketName": bucket},
        resources=[bucket_arn],
    )
    add(
        "CD-DEMO-103",
        1,
        11,
        "PutBucketPolicy",
        "s3.amazonaws.com",
        actor,
        "203.0.113.103",
        params={
            "bucketName": bucket,
            "policyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"{bucket_arn}/*",
                    }
                ]
            },
        },
        resources=[bucket_arn],
    )
    add(
        "CD-DEMO-103",
        2,
        11,
        "PutBucketAcl",
        "s3.amazonaws.com",
        actor,
        "203.0.113.103",
        params={"bucketName": bucket, "grantee": "AllUsers"},
        resources=[bucket_arn],
    )
    add(
        "CD-DEMO-103",
        3,
        11,
        "DeleteBucketEncryption",
        "s3.amazonaws.com",
        actor,
        "203.0.113.103",
        params={"bucketName": bucket},
        resources=[bucket_arn],
    )

    add(
        "CD-DEMO-104",
        0,
        17,
        "StopLogging",
        "cloudtrail.amazonaws.com",
        "demo-audit-operator-104",
        "198.51.100.104",
        params={"name": "demo-trail-never-created"},
        resources=[f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/demo-trail-never-created"],
    )
    add(
        "CD-DEMO-104",
        1,
        17,
        "ScheduleKeyDeletion",
        "kms.amazonaws.com",
        "demo-audit-operator-104",
        "198.51.100.104",
        params={"pendingWindowInDays": 30},
        resources=[f"arn:aws:kms:{REGION}:{ACCOUNT}:key/00000000-0000-0000-0000-000000000104"],
    )

    add(
        "CD-DEMO-105",
        0,
        23,
        "ModifyDBInstance",
        "rds.amazonaws.com",
        "demo-platform-operator-105",
        "203.0.113.105",
        params={"dBInstanceIdentifier": "demo-db-never-created", "publiclyAccessible": True},
        resources=[f"arn:aws:rds:{REGION}:{ACCOUNT}:db:demo-db-never-created"],
    )
    add(
        "CD-DEMO-105",
        1,
        23,
        "CloudWatchAlarmStateChange",
        "cloudwatch.amazonaws.com",
        "demo-platform-operator-105",
        "203.0.113.105",
        params={"metricName": "CPUUtilization", "state": {"value": "ALARM"}},
        resources=[f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-00000000000000105"],
    )

    for step in range(15):
        add(
            "CD-DEMO-106",
            step,
            29,
            ["ListRoles", "GetRole", "ListUsers"][step % 3],
            "iam.amazonaws.com",
            "demo-prober-106",
            "198.51.100.106",
            error="AccessDeniedException",
            error_message="User is not authorized to perform this operation (synthetic example)",
        )

    for step in range(10):
        add(
            "CD-DEMO-107",
            step,
            35,
            "ConsoleLogin",
            "signin.amazonaws.com",
            "demo-target-107",
            f"198.51.100.{120 + step}",
            error="Failed authentication",
            error_message="Invalid username or password (synthetic example)",
        )

    add(
        "CD-DEMO-108",
        0,
        41,
        "ListBuckets",
        "s3.amazonaws.com",
        "root",
        "203.0.113.108",
        root=True,
        read_only=True,
    )
    for step, (name, source) in enumerate(
        [
            ("ListBuckets", "s3.amazonaws.com"),
            ("DescribeInstances", "ec2.amazonaws.com"),
            ("ListRoles", "iam.amazonaws.com"),
            ("DescribeDBInstances", "rds.amazonaws.com"),
        ]
    ):
        add(
            "CD-DEMO-109",
            step,
            44,
            name,
            source,
            "demo-routine-user-109",
            "203.0.113.109",
            read_only=True,
            mfa=True,
        )

    return events


def main() -> None:
    print(json.dumps(presentation_events(), separators=(",", ":")))


if __name__ == "__main__":
    main()
