import json
from typing import Any
from urllib.parse import unquote

from cloud_detective.detection.models import EventContext
from cloud_detective.schemas.events import CanonicalEvent

EVENT_PREDICATES = {
    "event_name",
    "principal_type",
    "error_message_present",
    "error_code_present",
    "error_code_contains",
    "read_only",
    "mfa_authenticated",
    "request_contains",
    "request_equals",
    "policy_grants_all_actions",
    "policy_has_public_principal",
    "public_access_protection_disabled",
    "acl_public",
    "trail_coverage_reduced",
}


def _deep_values(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in _deep_values(child)]
    if isinstance(value, list):
        return [item for child in value for item in _deep_values(child)]
    return [value]


def _path_value(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _policy_document(params: dict[str, Any]) -> Any:
    policy = params.get("policyDocument")
    if isinstance(policy, str):
        try:
            return json.loads(unquote(policy))
        except (json.JSONDecodeError, TypeError):
            return policy
    return policy


def _statements(policy: Any) -> list[dict[str, Any]]:
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [item for item in statements if isinstance(item, dict)]


def _policy_grants_all_actions(params: dict[str, Any]) -> bool:
    for statement in _statements(_policy_document(params)):
        actions = statement.get("Action")
        if statement.get("Effect") == "Allow" and (actions == "*" or "*" in (actions or [])):
            return True
    return False


def _policy_has_public_principal(params: dict[str, Any]) -> bool:
    for statement in _statements(_policy_document(params)):
        principal = statement.get("Principal")
        if statement.get("Effect") != "Allow":
            continue
        if principal == "*" or (isinstance(principal, dict) and "*" in _deep_values(principal)):
            return True
    return False


def _public_access_protection_disabled(params: dict[str, Any]) -> bool:
    config = params.get("PublicAccessBlockConfiguration") or params.get(
        "publicAccessBlockConfiguration"
    )
    if not isinstance(config, dict):
        return False
    protection_keys = {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
        "blockPublicAcls",
        "ignorePublicAcls",
        "blockPublicPolicy",
        "restrictPublicBuckets",
    }
    return any(key in config and config[key] is False for key in protection_keys)


def _acl_public(params: dict[str, Any]) -> bool:
    public_markers = {
        "AllUsers",
        "AuthenticatedUsers",
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    return any(str(value) in public_markers for value in _deep_values(params))


def _trail_coverage_reduced(params: dict[str, Any]) -> bool:
    return (
        params.get("isMultiRegionTrail") is False
        or params.get("includeGlobalServiceEvents") is False
    )


def event_matches(spec: dict[str, Any], event: CanonicalEvent) -> bool:
    if "any_of" in spec:
        alternatives = spec["any_of"]
        return isinstance(alternatives, list) and any(
            event_matches(item, event) for item in alternatives
        )

    unknown = set(spec) - EVENT_PREDICATES
    if unknown:
        raise ValueError(f"unsupported event predicates: {sorted(unknown)}")

    for key, expected in spec.items():
        expected_values = expected if isinstance(expected, list) else [expected]
        if key == "event_name" and event.event_name not in expected_values:
            return False
        if key == "principal_type" and event.principal_type.value not in expected_values:
            return False
        if key == "error_message_present" and bool(event.error_message) is not expected:
            return False
        if key == "error_code_present" and bool(event.error_code) is not expected:
            return False
        if (
            key == "error_code_contains"
            and str(expected).lower() not in (event.error_code or "").lower()
        ):
            return False
        if key == "read_only" and event.read_only is not expected:
            return False
        if key == "mfa_authenticated" and event.mfa_authenticated is not expected:
            return False
        if key == "request_contains":
            haystack = json.dumps(event.request_params, sort_keys=True).lower()
            values = expected if isinstance(expected, list) else [expected]
            if not all(str(value).lower() in haystack for value in values):
                return False
        if key == "request_equals" and (
            not isinstance(expected, dict)
            or any(
                _path_value(event.request_params, path) != value for path, value in expected.items()
            )
        ):
            return False
        if key == "policy_grants_all_actions" and _policy_grants_all_actions(
            event.request_params
        ) is not expected:
            return False
        if key == "policy_has_public_principal" and _policy_has_public_principal(
            event.request_params
        ) is not expected:
            return False
        if key == "public_access_protection_disabled" and _public_access_protection_disabled(
            event.request_params
        ) is not expected:
            return False
        if key == "acl_public" and _acl_public(event.request_params) is not expected:
            return False
        if key == "trail_coverage_reduced" and _trail_coverage_reduced(
            event.request_params
        ) is not expected:
            return False
    return True


def context_matches(conditions: list[dict[str, Any]], context: EventContext) -> bool:
    checks = {
        "country_not_in_baseline": not context.country_seen and context.country is not None,
        "region_not_in_baseline": not context.region_seen,
        "api_not_in_baseline": not context.api_seen,
        "ip_not_in_baseline": not context.ip_seen,
        "rate_anomaly": context.rate_anomaly,
    }
    unknown = {key for condition in conditions for key in condition} - set(checks)
    if unknown:
        raise ValueError(f"unsupported context predicates: {sorted(unknown)}")
    return all(
        checks.get(key) is expected
        for condition in conditions
        for key, expected in condition.items()
    )

