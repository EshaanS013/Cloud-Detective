from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import ip_address
from uuid import uuid4

from cloud_detective.schemas.api import FindingView


def test_finding_view_accepts_database_inet_values() -> None:
    finding = FindingView.model_validate(
        {
            "id": uuid4(),
            "rule_id": "root-account-used",
            "severity": "CRITICAL",
            "risk_score": Decimal("95.00"),
            "title": "Root account activity",
            "description": "The root principal was used.",
            "principal_arn": "arn:aws:iam::000000000000:root",
            "source_ip": ip_address("192.0.2.10"),
            "affected_resources": [],
            "status": "OPEN",
            "assigned_to": None,
            "notes": None,
            "created_at": datetime.now(UTC),
        }
    )

    assert finding.model_dump(mode="json")["source_ip"] == "192.0.2.10"
