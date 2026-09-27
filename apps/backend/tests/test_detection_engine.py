from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from cloud_detective.detection.engine import DetectionEngine
from cloud_detective.detection.loader import load_rules
from cloud_detective.detection.models import EventContext, RuleDefinition, RuleType
from cloud_detective.schemas.events import CanonicalEvent, PrincipalType, SourceKind

RULES_PATH = Path(__file__).parents[3] / "rules" / "catalog.yaml"
RULES = load_rules(RULES_PATH)
RULES_BY_ID = {rule.id: rule for rule in RULES}


def event(**overrides: Any) -> CanonicalEvent:
    values: dict[str, Any] = {
        "event_id": uuid4(),
        "event_time": datetime(2026, 9, 28, 6, 0, tzinfo=UTC),
        "event_name": "ListBuckets",
        "event_source": "s3.amazonaws.com",
        "aws_region": "ap-south-1",
        "principal_arn": "arn:aws:iam::111122223333:user/alice",
        "principal_type": PrincipalType.IAM_USER,
        "principal_name": "alice",
        "source_address": "203.0.113.10",
        "source_ip": "203.0.113.10",
        "source_kind": SourceKind.IP,
        "request_params": {},
        "raw": {},
    }
    values.update(overrides)
    return CanonicalEvent(**values)


def positive_event(rule_id: str, index: int = 0) -> CanonicalEvent:
    overrides: dict[str, Any] = {}
    if rule_id in {"console-brute-force", "failed-login-distributed"}:
        overrides = {
            "event_name": "ConsoleLogin",
            "error_message": "Failed authentication",
            "source_address": (
                f"203.0.113.{10 + index}"
                if rule_id == "failed-login-distributed"
                else "203.0.113.10"
            ),
            "source_ip": (
                f"203.0.113.{10 + index}"
                if rule_id == "failed-login-distributed"
                else "203.0.113.10"
            ),
        }
    elif rule_id == "root-account-used":
        overrides = {"principal_type": PrincipalType.ROOT}
    elif rule_id == "login-without-mfa":
        overrides = {"event_name": "ConsoleLogin", "mfa_authenticated": False}
    elif rule_id == "access-denied-burst":
        overrides = {"error_code": "AccessDeniedException"}
    elif rule_id == "admin-policy-attached":
        overrides = {
            "event_name": "AttachUserPolicy",
            "request_params": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        }
    elif rule_id == "inline-policy-with-wildcard":
        overrides = {
            "event_name": "PutUserPolicy",
            "request_params": {
                "policyDocument": {
                    "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
                }
            },
        }
    elif rule_id == "new-policy-version-set":
        overrides = {
            "event_name": "CreatePolicyVersion",
            "request_params": {"setAsDefault": True},
        }
    elif rule_id == "role-trust-policy-modified":
        overrides = {"event_name": "UpdateAssumeRolePolicy"}
    elif rule_id == "s3-public-policy":
        overrides = {
            "event_name": "PutBucketPolicy",
            "request_params": {
                "policyDocument": {
                    "Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
                }
            },
        }
    elif rule_id == "s3-public-access-block-removed":
        overrides = {"event_name": "DeletePublicAccessBlock"}
    elif rule_id == "s3-public-acl":
        overrides = {
            "event_name": "PutBucketAcl",
            "request_params": {"grantee": "AllUsers"},
        }
    elif rule_id == "s3-encryption-removed":
        overrides = {"event_name": "DeleteBucketEncryption"}
    elif rule_id == "rds-made-public":
        overrides = {
            "event_name": "ModifyDBInstance",
            "request_params": {"publiclyAccessible": True},
        }
    elif rule_id == "cloudtrail-tampering":
        overrides = {"event_name": "StopLogging"}
    elif rule_id == "kms-key-scheduled-deletion":
        overrides = {"event_name": "ScheduleKeyDeletion"}
    elif rule_id == "ec2-unusual-region":
        overrides = {"event_name": "RunInstances", "aws_region": "eu-west-3"}
    elif rule_id == "ec2-cpu-sustained-high":
        overrides = {
            "event_name": "CloudWatchAlarmStateChange",
            "request_params": {"metricName": "CPUUtilization", "state": {"value": "ALARM"}},
        }
    return event(**overrides)


def context_for(rule_id: str, positive: bool = True) -> EventContext:
    if rule_id == "ec2-unusual-region":
        return EventContext(baseline_warmed=True, region_seen=not positive)
    if rule_id == "unusual-origin-country":
        return EventContext(
            baseline_warmed=True, country="DE", country_seen=not positive
        )
    if rule_id == "first-time-api-call":
        return EventContext(baseline_warmed=True, api_seen=not positive)
    return EventContext()


def run_positive(rule: RuleDefinition) -> list:
    engine = DetectionEngine([rule])
    if rule.type is RuleType.THRESHOLD:
        findings = []
        for index in range(rule.threshold or 0):
            current = positive_event(rule.id, index)
            current.event_time += timedelta(seconds=index)
            findings = engine.process(current)
        return findings
    if rule.type is RuleType.SEQUENCE:
        events = [
            event(event_name="CreateUser"),
            event(event_name="CreateAccessKey"),
            event(
                event_name="AttachUserPolicy",
                request_params={"policyArn": "AdministratorAccess"},
            ),
        ]
        findings = []
        for index, current in enumerate(events):
            current.event_time += timedelta(seconds=index)
            findings = engine.process(current)
        return findings
    return engine.process(positive_event(rule.id), context_for(rule.id))


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_every_catalog_rule_has_a_positive_match(rule: RuleDefinition) -> None:
    findings = run_positive(rule)
    assert [finding.rule_id for finding in findings] == [rule.id]


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_every_catalog_rule_has_a_negative_or_boundary_case(rule: RuleDefinition) -> None:
    engine = DetectionEngine([rule])
    if rule.type is RuleType.THRESHOLD:
        for index in range((rule.threshold or 1) - 1):
            assert engine.process(positive_event(rule.id, index)) == []
    elif rule.type is RuleType.SEQUENCE:
        assert engine.process(event(event_name="AttachUserPolicy")) == []
        assert engine.process(event(event_name="CreateAccessKey")) == []
        assert engine.process(event(event_name="CreateUser")) == []
    elif rule.type is RuleType.CONTEXTUAL:
        assert engine.process(positive_event(rule.id), context_for(rule.id, positive=False)) == []
    else:
        negative = event()
        if rule.id == "root-account-used":
            negative.principal_type = PrincipalType.IAM_USER
        assert engine.process(negative) == []


def test_catalog_is_unique_and_covers_all_rule_types() -> None:
    # The specification says 18 rules, but its catalogue tables enumerate 21.
    # We implement every listed rule instead of silently dropping three.
    assert len(RULES) == 21
    assert len(RULES_BY_ID) == len(RULES)
    assert {rule.type for rule in RULES} == set(RuleType)


def test_duplicate_delivery_is_ignored() -> None:
    rule = RULES_BY_ID["root-account-used"]
    engine = DetectionEngine([rule])
    duplicate = positive_event(rule.id)

    assert len(engine.process(duplicate)) == 1
    assert engine.process(duplicate) == []


def test_sequence_requires_order_and_window() -> None:
    rule = RULES_BY_ID["privilege-escalation-chain"]
    engine = DetectionEngine([rule])
    start = datetime(2026, 9, 28, 6, 0, tzinfo=UTC)

    assert engine.process(event(event_name="CreateUser", event_time=start)) == []
    assert (
        engine.process(
            event(event_name="CreateAccessKey", event_time=start + timedelta(seconds=60))
        )
        == []
    )
    assert (
        engine.process(
            event(
                event_name="AttachUserPolicy",
                event_time=start + timedelta(seconds=301),
                request_params={"policyArn": "AdministratorAccess"},
            )
        )
        == []
    )


def test_contextual_rules_are_suppressed_during_warmup() -> None:
    rule = RULES_BY_ID["first-time-api-call"]
    engine = DetectionEngine([rule])
    context = EventContext(baseline_warmed=False, api_seen=False)
    assert engine.process(event(), context) == []

