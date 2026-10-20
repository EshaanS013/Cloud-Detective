from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from uuid import UUID

from cloud_detective.detection.engine import DetectionEngine
from cloud_detective.detection.loader import load_rules
from cloud_detective.presentation_scenarios import SCENARIOS, presentation_events
from cloud_detective.schemas.events import normalize_cloudtrail_event

RULES_PATH = Path(__file__).parents[3] / "rules" / "catalog.yaml"
DOC_NETWORKS = [
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
]


def test_presentation_events_are_idempotent_and_cannot_target_real_aws_resources() -> None:
    now = datetime(2026, 10, 20, 10, 0, tzinfo=UTC)
    first = presentation_events(now)
    assert first == presentation_events(now)
    assert len(first) == 50
    assert len({UUID(event["eventID"]) for event in first}) == len(first)
    assert {event["additionalEventData"]["presentationScenario"] for event in first} == set(
        SCENARIOS
    )
    for event in first:
        assert event["additionalEventData"]["simulation"] is True
        assert "::000000000000:" in event["userIdentity"]["arn"]
        assert any(ip_address(event["sourceIPAddress"]) in network for network in DOC_NETWORKS)
        assert all(
            "000000000000" in resource["ARN"] or "never-created" in resource["ARN"]
            for resource in event["resources"]
        )
        assert not normalize_cloudtrail_event(event).partially_parsed


def test_presentation_stories_generate_explainable_findings() -> None:
    engine = DetectionEngine(load_rules(RULES_PATH))
    rules_by_case: dict[str, set[str]] = defaultdict(set)
    for raw in presentation_events(datetime(2026, 10, 20, 10, 0, tzinfo=UTC)):
        event = normalize_cloudtrail_event(raw)
        for candidate in engine.process(event):
            rules_by_case[raw["additionalEventData"]["presentationScenario"]].add(candidate.rule_id)

    assert {"console-brute-force", "login-without-mfa"} <= rules_by_case["CD-DEMO-101"]
    assert {
        "privilege-escalation-chain",
        "admin-policy-attached",
        "inline-policy-with-wildcard",
        "role-trust-policy-modified",
        "new-policy-version-set",
    } <= rules_by_case["CD-DEMO-102"]
    assert {
        "s3-public-policy",
        "s3-public-access-block-removed",
        "s3-public-acl",
        "s3-encryption-removed",
    } <= rules_by_case["CD-DEMO-103"]
    assert {"cloudtrail-tampering", "kms-key-scheduled-deletion"} <= rules_by_case["CD-DEMO-104"]
    assert {"rds-made-public", "ec2-cpu-sustained-high"} <= rules_by_case["CD-DEMO-105"]
    assert "access-denied-burst" in rules_by_case["CD-DEMO-106"]
    assert "failed-login-distributed" in rules_by_case["CD-DEMO-107"]
    assert "root-account-used" in rules_by_case["CD-DEMO-108"]
    assert "CD-DEMO-109" not in rules_by_case
