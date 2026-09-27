import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class PrincipalType(StrEnum):
    IAM_USER = "IAMUser"
    ASSUMED_ROLE = "AssumedRole"
    ROOT = "Root"
    AWS_SERVICE = "AWSService"
    FEDERATED_USER = "FederatedUser"
    UNKNOWN = "Unknown"


class SourceKind(StrEnum):
    IP = "ip"
    SERVICE = "service"
    UNKNOWN = "unknown"


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    event_id: UUID
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    principal_arn: str | None = None
    principal_type: PrincipalType = PrincipalType.UNKNOWN
    principal_name: str | None = None
    source_address: str | None = None
    source_ip: str | None = None
    source_kind: SourceKind = SourceKind.UNKNOWN
    user_agent: str | None = None
    resources: list[str] = Field(default_factory=list)
    request_params: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    read_only: bool = False
    mfa_authenticated: bool | None = None
    raw: dict[str, Any]
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    partially_parsed: bool = False
    parse_warnings: list[str] = Field(default_factory=list)


def _stable_event_id(event: dict[str, Any]) -> UUID:
    serialized = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).digest()[:16]
    return UUID(bytes=digest, version=4)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _optional_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _parse_time(value: Any, warnings: list[str]) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            warnings.append("invalid eventTime; ingestion time used")
            return datetime.now(UTC)
    else:
        warnings.append("missing eventTime; ingestion time used")
        return datetime.now(UTC)

    if parsed.tzinfo is None:
        warnings.append("eventTime missing timezone; assumed UTC")
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _principal_type(value: Any) -> PrincipalType:
    try:
        return PrincipalType(str(value))
    except ValueError:
        return PrincipalType.UNKNOWN


def _principal_details(identity: dict[str, Any]) -> tuple[PrincipalType, str | None, str | None]:
    principal_type = _principal_type(identity.get("type"))
    session_context = _as_dict(identity.get("sessionContext"))
    session_issuer = _as_dict(session_context.get("sessionIssuer"))
    arn = identity.get("arn") or session_issuer.get("arn")
    name = identity.get("userName") or session_issuer.get("userName")
    if not name and arn:
        name = str(arn).rsplit("/", 1)[-1]
    if not arn:
        arn = identity.get("principalId")
    return principal_type, _optional_text(arn), _optional_text(name)


def _source_details(value: Any) -> tuple[str | None, str | None, SourceKind]:
    if value is None:
        return None, None, SourceKind.UNKNOWN
    address = str(value)
    try:
        parsed = ipaddress.ip_address(address)
        return address, str(parsed), SourceKind.IP
    except ValueError:
        return address, None, SourceKind.SERVICE


def _resource_arns(resources: Any) -> list[str]:
    if not isinstance(resources, list):
        return []
    arns: list[str] = []
    for resource in resources:
        if isinstance(resource, dict):
            arn = resource.get("ARN") or resource.get("arn")
            if arn:
                arns.append(str(arn))
        elif isinstance(resource, str):
            arns.append(resource)
    return arns


def _parse_mfa(identity: dict[str, Any]) -> bool | None:
    session_context = _as_dict(identity.get("sessionContext"))
    attributes = _as_dict(session_context.get("attributes"))
    value = attributes.get("mfaAuthenticated")
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return None


def _parse_boolean(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return default


def normalize_cloudtrail_event(event: dict[str, Any]) -> CanonicalEvent:
    """Normalize an EventBridge-wrapped or raw CloudTrail event without raising on field drift."""
    warnings: list[str] = []
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else event
    identity = _as_dict(detail.get("userIdentity"))

    raw_event_id = detail.get("eventID") or event.get("id")
    try:
        event_id = UUID(str(raw_event_id))
    except (TypeError, ValueError):
        warnings.append("missing or invalid eventID; stable fallback generated")
        event_id = _stable_event_id(event)

    principal_type, principal_arn, principal_name = _principal_details(identity)
    source_address, source_ip, source_kind = _source_details(detail.get("sourceIPAddress"))

    request_params = detail.get("requestParameters")
    if not isinstance(request_params, dict):
        if request_params is not None:
            warnings.append("requestParameters was not an object")
        request_params = {}

    event_name = str(detail.get("eventName") or "UnknownEvent")
    event_source = str(detail.get("eventSource") or event.get("source") or "unknown")
    aws_region = str(detail.get("awsRegion") or event.get("region") or "unknown")
    if event_name == "UnknownEvent":
        warnings.append("missing eventName")
    if event_source == "unknown":
        warnings.append("missing eventSource")

    return CanonicalEvent(
        event_id=event_id,
        event_time=_parse_time(detail.get("eventTime") or event.get("time"), warnings),
        event_name=event_name,
        event_source=event_source,
        aws_region=aws_region,
        principal_arn=principal_arn,
        principal_type=principal_type,
        principal_name=principal_name,
        source_address=source_address,
        source_ip=source_ip,
        source_kind=source_kind,
        user_agent=_optional_text(detail.get("userAgent")),
        resources=_resource_arns(detail.get("resources")),
        request_params=request_params,
        error_code=_optional_text(detail.get("errorCode")),
        error_message=_optional_text(detail.get("errorMessage")),
        read_only=_parse_boolean(detail.get("readOnly")),
        mfa_authenticated=_parse_mfa(identity),
        raw=detail,
        partially_parsed=bool(warnings),
        parse_warnings=warnings,
    )
