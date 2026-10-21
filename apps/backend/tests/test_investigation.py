from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from cloud_detective.db.session import get_session
from cloud_detective.detection.loader import load_rules
from cloud_detective.explainability import describe_rule, evidence_summary, explain_aws_error
from cloud_detective.main import app


def _finding() -> SimpleNamespace:
    now = datetime(2026, 10, 20, tzinfo=UTC)
    return SimpleNamespace(
        id=uuid4(),
        rule_id="root-account-used",
        severity="HIGH",
        risk_score=Decimal("80"),
        title="Root account used",
        description="Root activity was detected.",
        principal_arn="arn:aws:iam::000000000000:root",
        source_ip=None,
        affected_resources=[],
        status="OPEN",
        assigned_to=None,
        notes=None,
        created_at=now,
        resolved_at=None,
    )


def test_every_catalog_rule_has_readable_trigger_and_checks() -> None:
    catalog = Path(__file__).resolve().parents[3] / "rules" / "catalog.yaml"
    rules = load_rules(catalog)
    assert len(rules) == 21
    for rule in rules:
        summary, checks = describe_rule(rule.model_dump(mode="json"))
        assert summary
        assert checks, rule.id


def test_evidence_summary_distinguishes_error_from_detection() -> None:
    event = SimpleNamespace(event_name="StopLogging", error_code=None, error_message=None)
    assert "not an application error" in evidence_summary([event], 1)
    event.error_code = "AccessDenied"
    assert "reported an AWS error" in evidence_summary([event], 1)
    assert "unauthorized" in explain_aws_error("AccessDenied").lower()
    assert explain_aws_error(None) is None


def test_rules_endpoint_exposes_description_and_trigger_logic() -> None:
    catalog = Path(__file__).resolve().parents[3] / "rules" / "catalog.yaml"
    definition = next(rule for rule in load_rules(catalog) if rule.id == "console-brute-force")
    rule = SimpleNamespace(
        id=definition.id,
        name=definition.name,
        rule_type=definition.type.value,
        category=definition.category,
        base_score=definition.base_score,
        enabled=True,
        playbook_id=None,
        mitre_technique=definition.mitre_technique,
        definition=definition.model_dump(mode="json"),
    )
    session = MagicMock()
    session.scalars.return_value = [rule]
    app.dependency_overrides[get_session] = lambda: session
    try:
        result = TestClient(app).get("/api/v1/rules")
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 200
    detail = result.json()[0]
    assert detail["description"] == definition.description
    assert "5 matching events" in detail["trigger_summary"]
    assert any("ConsoleLogin" in check for check in detail["trigger_checks"])


def test_start_assigns_case_without_overwriting_existing_note() -> None:
    finding = _finding()
    finding.notes = "Earlier observation"
    session = MagicMock()
    session.get.return_value = finding
    app.dependency_overrides[get_session] = lambda: session
    try:
        result = TestClient(app).patch(
            f"/api/v1/findings/{finding.id}", json={"status": "INVESTIGATING"}
        )
    finally:
        app.dependency_overrides.clear()
    assert result.status_code == 200
    assert result.json()["status"] == "INVESTIGATING"
    assert result.json()["assigned_to"] == "local-developer"
    assert result.json()["notes"] == "Earlier observation"
    session.commit.assert_called_once()


def test_resolution_requires_note_and_records_closure() -> None:
    finding = _finding()
    session = MagicMock()
    session.get.return_value = finding
    app.dependency_overrides[get_session] = lambda: session
    try:
        client = TestClient(app)
        missing = client.patch(f"/api/v1/findings/{finding.id}", json={"status": "RESOLVED"})
        saved = client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"status": "RESOLVED", "notes": "Confirmed approved exercise."},
        )
    finally:
        app.dependency_overrides.clear()
    assert missing.status_code == 422
    assert saved.status_code == 200
    assert saved.json()["status"] == "RESOLVED"
    assert saved.json()["notes"] == "Confirmed approved exercise."
    assert saved.json()["resolved_at"] is not None
    session.commit.assert_called_once()


def test_response_rejects_targets_not_linked_to_the_s3_finding() -> None:
    finding = _finding()
    finding.rule_id = "s3-public-access-block-removed"
    finding.affected_resources = ["arn:aws:s3:::cloud-detective-demo"]
    session = MagicMock()
    session.get.return_value = finding
    app.dependency_overrides[get_session] = lambda: session
    try:
        result = TestClient(app).post(
            f"/api/v1/findings/{finding.id}/responses",
            json={
                "playbook_id": "block-public-s3",
                "target_arn": "arn:aws:s3:::unrelated-bucket",
                "confirmation": "DRY_RUN",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert result.status_code == 422
    session.add.assert_not_called()
