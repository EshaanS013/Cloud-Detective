import json
from pathlib import Path

import pytest

from cloud_detective.schemas.events import PrincipalType, SourceKind, normalize_cloudtrail_event

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_normalizes_iam_user_event() -> None:
    event = normalize_cloudtrail_event(load_fixture("iam_user_event.json"))

    assert event.event_name == "AttachUserPolicy"
    assert event.principal_type is PrincipalType.IAM_USER
    assert event.principal_name == "cd-test-alice"
    assert event.source_ip == "203.0.113.10"
    assert event.source_kind is SourceKind.IP
    assert event.mfa_authenticated is True
    assert event.partially_parsed is False


def test_normalizes_assumed_role_and_resources() -> None:
    event = normalize_cloudtrail_event(load_fixture("assumed_role_event.json"))

    assert event.principal_type is PrincipalType.ASSUMED_ROLE
    assert event.principal_name == "Developer"
    assert event.mfa_authenticated is False
    assert event.resources == [
        "arn:aws:ec2:ap-south-1:111122223333:instance/i-0123456789abcdef0"
    ]


def test_accepts_service_principal_as_non_ip_source() -> None:
    event = normalize_cloudtrail_event(load_fixture("service_event.json"))

    assert event.principal_type is PrincipalType.AWS_SERVICE
    assert event.source_address == "cloudtrail.amazonaws.com"
    assert event.source_ip is None
    assert event.source_kind is SourceKind.SERVICE
    assert event.request_params == {}


def test_malformed_event_is_stable_and_does_not_raise() -> None:
    malformed = {"detail": {"requestParameters": "not-an-object", "resources": "bad"}}

    first = normalize_cloudtrail_event(malformed)
    second = normalize_cloudtrail_event(malformed)

    assert first.event_id == second.event_id
    assert first.event_name == "UnknownEvent"
    assert first.event_source == "unknown"
    assert first.source_kind is SourceKind.UNKNOWN
    assert first.partially_parsed is True
    assert len(first.parse_warnings) >= 4


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [(True, True), (False, False), ("true", True), ("false", False), ("unexpected", None)],
)
def test_mfa_values_are_tri_state(raw_value: object, expected: bool | None) -> None:
    payload = load_fixture("iam_user_event.json")
    payload["detail"]["userIdentity"]["sessionContext"]["attributes"][
        "mfaAuthenticated"
    ] = raw_value

    assert normalize_cloudtrail_event(payload).mfa_authenticated is expected


def test_raw_cloudtrail_event_without_eventbridge_envelope() -> None:
    raw = load_fixture("iam_user_event.json")["detail"]
    event = normalize_cloudtrail_event(raw)
    assert event.event_name == "AttachUserPolicy"


def test_tolerates_malformed_nested_identity_and_text_fields() -> None:
    payload = load_fixture("iam_user_event.json")
    payload["detail"].update(
        {
            "userIdentity": {
                "type": "AssumedRole",
                "arn": 12345,
                "sessionContext": "not-an-object",
            },
            "userAgent": {"unexpected": "object"},
            "errorCode": 403,
            "readOnly": "false",
        }
    )

    event = normalize_cloudtrail_event(payload)

    assert event.principal_arn == "12345"
    assert event.principal_name == "12345"
    assert event.user_agent == "{'unexpected': 'object'}"
    assert event.error_code == "403"
    assert event.read_only is False


def test_s3_bucket_is_derived_when_cloudtrail_omits_resources() -> None:
    payload = load_fixture("iam_user_event.json")
    payload["detail"].update(
        {
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeletePublicAccessBlock",
            "requestParameters": {"bucketName": "cloud-detective-demo-bucket"},
            "resources": [],
        }
    )

    event = normalize_cloudtrail_event(payload)

    assert event.resources == ["arn:aws:s3:::cloud-detective-demo-bucket"]
