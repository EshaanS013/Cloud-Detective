from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import ip_address
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from cloud_detective.api import _is_simulated_event
from cloud_detective.db.session import get_session
from cloud_detective.main import app


def test_explanation_links_scoring_rule_and_synthetic_evidence() -> None:
    finding_id = uuid4()
    event_id = uuid4()
    when = datetime(2026, 10, 4, tzinfo=UTC)
    finding = SimpleNamespace(
        id=finding_id,
        rule_id="root-account-used",
        severity="CRITICAL",
        risk_score=Decimal("100.00"),
        score_breakdown={"base": 80.0, "principal": 2.0, "resource": 1.0, "time": 1.0,
                         "origin": 1.0, "mfa": 1.0},
        title="Root account used",
        description="Root activity was detected.",
        principal_arn="arn:aws:iam::000000000000:root",
        source_ip=ip_address("192.0.2.10"),
        affected_resources=[],
        status="OPEN",
        assigned_to=None,
        notes=None,
        created_at=when,
        window_start=when,
        window_end=when,
    )
    rule = SimpleNamespace(
        name="Root account used",
        rule_type="signature",
        definition={"description": "Detect root principal activity."},
        category="identity",
        mitre_technique="T1078.004",
    )
    event = SimpleNamespace(
        event_id=event_id,
        event_time=when,
        event_name="DeleteTrail",
        event_source="cloudtrail.amazonaws.com",
        aws_region="ap-southeast-2",
        principal_arn=finding.principal_arn,
        source_address="192.0.2.10",
        mfa_authenticated=False,
        error_code=None,
        raw={"additionalEventData": {"simulation": True}},
    )
    session = MagicMock()
    session.get.side_effect = [finding, rule]
    session.scalar.return_value = 1
    session.scalars.return_value.all.return_value = [event]
    app.dependency_overrides[get_session] = lambda: session
    try:
        result = TestClient(app).get(f"/api/v1/findings/{finding_id}/explanation")
    finally:
        app.dependency_overrides.clear()

    assert result.status_code == 200
    payload = result.json()
    assert payload["finding"]["source_ip"] == "192.0.2.10"
    assert payload["score_factors"]["principal"] == 2.0
    assert payload["rule_description"] == "Detect root principal activity."
    assert payload["event_count"] == 1
    assert payload["evidence_truncated"] is False
    assert payload["evidence"][0]["event_id"] == str(event_id)
    assert payload["evidence"][0]["simulated"] is True


def test_explanation_returns_404_for_missing_finding() -> None:
    session = MagicMock()
    session.get.return_value = None
    app.dependency_overrides[get_session] = lambda: session
    try:
        result = TestClient(app).get(f"/api/v1/findings/{uuid4()}/explanation")
    finally:
        app.dependency_overrides.clear()

    assert result.status_code == 404
    assert result.json()["detail"] == "Finding not found"


def test_unstructured_cloudtrail_metadata_is_not_a_simulation() -> None:
    event = SimpleNamespace(raw={"additionalEventData": "unstructured"})
    assert _is_simulated_event(event) is False
