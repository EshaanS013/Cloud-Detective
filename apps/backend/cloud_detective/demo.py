"""Seed explicitly synthetic presentation evidence without changing AWS resources.

Run once as an ECS task after migrations: ``python -m cloud_detective.demo``.
Event IDs are deterministic, so repeating the task is safe.
"""

from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from cloud_detective.config import get_settings
from cloud_detective.db.session import get_engine
from cloud_detective.detection.engine import DetectionEngine
from cloud_detective.detection.loader import load_rules
from cloud_detective.detection.models import EventContext, RuleDefinition
from cloud_detective.detection.persistence import persist_event, persist_finding, sync_rule_catalog
from cloud_detective.schemas.events import normalize_cloudtrail_event

FAKE_ACCOUNT = "000000000000"
FAKE_USER = f"arn:aws:iam::{FAKE_ACCOUNT}:user/presentation-analyst"
FAKE_BUCKET = "cloud-detective-presentation-example"


def demo_events(rule_id: str, now: datetime) -> list[dict]:
    """Return synthetic CloudTrail-shaped records satisfying one catalogue rule."""
    count = {
        "console-brute-force": 5,
        "failed-login-distributed": 10,
        "access-denied-burst": 15,
        "privilege-escalation-chain": 3,
    }.get(rule_id, 1)
    events = []
    for index in range(count):
        sequence_name = ["CreateUser", "CreateAccessKey", "AttachUserPolicy"][
            index if rule_id == "privilege-escalation-chain" else 0
        ]
        event_name = {
            "console-brute-force": "ConsoleLogin",
            "failed-login-distributed": "ConsoleLogin",
            "root-account-used": "ListBuckets",
            "login-without-mfa": "ConsoleLogin",
            "access-denied-burst": "ListRoles",
            "admin-policy-attached": "AttachUserPolicy",
            "privilege-escalation-chain": sequence_name,
            "inline-policy-with-wildcard": "PutUserPolicy",
            "new-policy-version-set": "CreatePolicyVersion",
            "role-trust-policy-modified": "UpdateAssumeRolePolicy",
            "s3-public-policy": "PutBucketPolicy",
            "s3-public-access-block-removed": "DeletePublicAccessBlock",
            "s3-public-acl": "PutBucketAcl",
            "s3-encryption-removed": "DeleteBucketEncryption",
            "rds-made-public": "ModifyDBInstance",
            "cloudtrail-tampering": "StopLogging",
            "kms-key-scheduled-deletion": "ScheduleKeyDeletion",
            "ec2-unusual-region": "RunInstances",
            "ec2-cpu-sustained-high": "CloudWatchAlarmStateChange",
            "unusual-origin-country": "StopInstances",
            "first-time-api-call": "GetSecretValue",
        }[rule_id]
        event_source = {
            "s3": "s3.amazonaws.com",
            "rds": "rds.amazonaws.com",
            "cloudtrail": "cloudtrail.amazonaws.com",
            "kms": "kms.amazonaws.com",
            "ec2": "ec2.amazonaws.com",
        }
        service = rule_id.split("-", 1)[0]
        if rule_id == "ec2-cpu-sustained-high":
            event_source = "cloudwatch.amazonaws.com"
        else:
            event_source = event_source.get(service, "iam.amazonaws.com")
        params: dict = {}
        if (
            rule_id in {"admin-policy-attached", "privilege-escalation-chain"}
            and event_name == "AttachUserPolicy"
        ):
            params = {
                "userName": "presentation-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            }
        elif rule_id == "inline-policy-with-wildcard":
            params = {
                "policyDocument": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
            }
        elif rule_id == "new-policy-version-set":
            params = {"setAsDefault": True}
        elif rule_id == "s3-public-policy":
            params = {
                "bucketName": FAKE_BUCKET,
                "policyDocument": {
                    "Statement": {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{FAKE_BUCKET}/*",
                    }
                },
            }
        elif rule_id == "s3-public-acl":
            params = {"bucketName": FAKE_BUCKET, "grantee": "AllUsers"}
        elif rule_id == "rds-made-public":
            params = {"dBInstanceIdentifier": "presentation-only", "publiclyAccessible": True}
        elif rule_id == "ec2-cpu-sustained-high":
            params = {"metricName": "CPUUtilization", "state": {"value": "ALARM"}}

        is_root = rule_id == "root-account-used"
        is_failed_login = rule_id in {"console-brute-force", "failed-login-distributed"}
        source_ip = (
            f"198.51.100.{10 + index}" if rule_id == "failed-login-distributed" else "203.0.113.10"
        )
        detail = {
            "eventID": str(uuid5(NAMESPACE_URL, f"cloud-detective-demo-v1:{rule_id}:{index}")),
            "eventTime": (now + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
            "eventName": event_name,
            "eventSource": event_source,
            "awsRegion": "ap-southeast-2",
            "sourceIPAddress": source_ip,
            "readOnly": False,
            "userIdentity": {
                "type": "Root" if is_root else "IAMUser",
                "arn": f"arn:aws:iam::{FAKE_ACCOUNT}:root" if is_root else FAKE_USER,
                "userName": "presentation-analyst",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "false" if rule_id == "login-without-mfa" else "true"
                    }
                },
            },
            "requestParameters": params,
            "resources": [{"ARN": f"arn:aws:s3:::{FAKE_BUCKET}"}],
            "additionalEventData": {"simulation": True, "presentationScenario": rule_id},
        }
        if is_failed_login:
            detail["errorCode"] = "Failed authentication"
            detail["errorMessage"] = "Synthetic failed sign-in"
        if rule_id == "access-denied-burst":
            detail["errorCode"] = "AccessDeniedException"
        events.append(detail)
    return events


def demo_context(rule_id: str) -> EventContext:
    if rule_id == "ec2-unusual-region":
        return EventContext(baseline_warmed=True, region_seen=False)
    if rule_id == "unusual-origin-country":
        return EventContext(baseline_warmed=True, country="DE", country_seen=False)
    if rule_id == "first-time-api-call":
        return EventContext(baseline_warmed=True, api_seen=False)
    return EventContext()


def seed(session: Session, rules: list[RuleDefinition], now: datetime) -> tuple[int, int]:
    """Persist one explainable finding per rule; never call the underlying AWS APIs."""
    sync_rule_catalog(session, rules)
    added_events = 0
    added_findings = 0
    for rule in rules:
        engine = DetectionEngine([rule])
        for raw in demo_events(rule.id, now):
            event = normalize_cloudtrail_event(raw)
            if not persist_event(session, event):
                continue
            added_events += 1
            for candidate in engine.process(event, demo_context(rule.id)):
                if persist_finding(session, candidate):
                    added_findings += 1
    session.commit()
    return added_events, added_findings


def main() -> None:
    settings = get_settings()
    rules = load_rules(settings.rules_path)
    with Session(get_engine()) as session:
        events, findings = seed(session, rules, datetime.now(UTC) - timedelta(minutes=8))
    print(f"Synthetic presentation data: {events} events, {findings} findings added.")


if __name__ == "__main__":
    main()
