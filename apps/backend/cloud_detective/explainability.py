"""Turn stored detection definitions and evidence into cautious, readable explanations."""

from typing import Any

FIELD_NAMES = {
    "principal_arn": "identity",
    "principal_name": "identity name",
    "source_ip": "source IP address",
}

CONTEXT_CHECKS = {
    "country_not_in_baseline": "The source country was not in this identity's earlier activity.",
    "region_not_in_baseline": "The AWS Region was not in this identity's earlier activity.",
    "api_not_in_baseline": "This identity had not used this API in its earlier activity.",
    "ip_not_in_baseline": "The source IP was not in this identity's earlier activity.",
    "rate_anomaly": "The activity rate was unusual compared with earlier activity.",
}

GUIDANCE = {
    "identity-access": (
        "Confirm who owns this identity, whether the activity was expected, "
        "and whether the source and MFA state match its normal use."
    ),
    "privilege-escalation": (
        "Confirm the change was approved, inspect the affected identity or policy, "
        "and review nearby actions by the same principal."
    ),
    "data-exposure": (
        "Check the named resource's current access settings and whether any data "
        "was actually accessed. An audit event alone does not prove exposure."
    ),
    "defence-evasion": (
        "Check whether the logging or key change was authorized, and review "
        "other activity around the same time."
    ),
    "compute-anomaly": (
        "Confirm the workload, owner, Region, and expected resource usage. "
        "A deviation alone does not prove malicious activity."
    ),
}


def _values(value: Any) -> str:
    if isinstance(value, list):
        return " or ".join(str(item) for item in value)
    return str(value)


def describe_match(match: dict[str, Any]) -> list[str]:
    """Describe rule predicates without claiming a historical baseline can be replayed."""
    if "any_of" in match:
        alternatives = match["any_of"]
        return [
            "Any one of: "
            + " ; or ".join(" and ".join(describe_match(option)) for option in alternatives)
        ]

    checks: list[str] = []
    for key, value in match.items():
        if key == "event_name":
            checks.append(f"AWS action is {_values(value)}.")
        elif key == "principal_type":
            checks.append(f"Identity type is {_values(value)}.")
        elif key == "error_message_present":
            checks.append(
                "AWS recorded an error message." if value else "AWS recorded no error message."
            )
        elif key == "error_code_present":
            checks.append("AWS recorded an error code." if value else "AWS recorded no error code.")
        elif key == "error_code_contains":
            checks.append(f"AWS error code contains '{value}'.")
        elif key == "read_only":
            checks.append(
                "The event is read-only." if value else "The event can change a resource."
            )
        elif key == "mfa_authenticated":
            checks.append("MFA was used." if value else "MFA was not used.")
        elif key == "request_contains":
            checks.append(f"Request contains {_values(value)}.")
        elif key == "request_equals":
            checks.extend(
                f"Request field {path} equals {expected}." for path, expected in value.items()
            )
        elif key == "policy_grants_all_actions":
            checks.append("The submitted policy allows all AWS actions.")
        elif key == "policy_has_public_principal":
            checks.append("The submitted policy allows a wildcard (public) principal.")
        elif key == "public_access_protection_disabled":
            checks.append("At least one S3 public-access protection setting was disabled.")
        elif key == "acl_public":
            checks.append("The submitted ACL grants an AWS public group access.")
        elif key == "trail_coverage_reduced":
            checks.append("The submitted trail settings reduce Region or global-service coverage.")
    return checks


def describe_rule(definition: dict[str, Any]) -> tuple[str, list[str]]:
    kind = definition.get("type", "signature")
    checks = describe_match(definition.get("match") or {})
    if kind == "threshold":
        threshold = definition.get("threshold", "?")
        minutes = (definition.get("window_seconds") or 0) / 60
        group = FIELD_NAMES.get(definition.get("group_by"), definition.get("group_by", "group"))
        return (
            f"At least {threshold} matching events for the same {group} "
            f"within {minutes:g} minutes.",
            checks,
        )
    if kind == "sequence":
        minutes = (definition.get("window_seconds") or 0) / 60
        group = FIELD_NAMES.get(definition.get("group_by"), definition.get("group_by", "group"))
        steps = definition.get("steps") or []
        ordered = [" then ".join(" and ".join(describe_match(step)) for step in steps)]
        return (
            f"These actions occurred in order for the same {group} within {minutes:g} minutes.",
            ordered,
        )
    if kind == "contextual":
        for condition in definition.get("conditions") or []:
            checks.extend(
                CONTEXT_CHECKS[key]
                for key, expected in condition.items()
                if expected and key in CONTEXT_CHECKS
            )
        return (
            "An event matched a pattern and differed from the identity's earlier activity.",
            checks,
        )
    return "A single AWS audit event matched these conditions.", checks


def investigation_guidance(category: str) -> str:
    return GUIDANCE.get(
        category,
        "Check whether the event was expected and inspect related activity "
        "before closing the case.",
    )


def explain_aws_error(code: str | None) -> str | None:
    if not code:
        return None
    lowered = code.lower()
    if "accessdenied" in lowered or "unauthorized" in lowered:
        return (
            "AWS rejected this request as unauthorized. The event does not identify "
            "which permission, resource policy, or project guardrail caused the denial."
        )
    if "throttl" in lowered or "ratelimit" in lowered:
        return (
            "AWS limited the request rate. The event alone does not show "
            "which quota was reached."
        )
    if "invalidclienttoken" in lowered or "expiredtoken" in lowered:
        return "AWS could not accept the credentials for this request; check the recorded message."
    if "nosuch" in lowered or "notfound" in lowered:
        return "AWS could not find the named resource; check the recorded message and resource ID."
    return (
        "AWS reported this code; use its recorded message and the linked action "
        "to investigate why."
    )


def evidence_summary(events: list[Any], event_count: int) -> str:
    if not events:
        return "No linked audit events are currently available; the cause cannot be confirmed here."
    names = list(dict.fromkeys(event.event_name for event in events))
    actions = ", ".join(names[:3]) + (" and other actions" if len(names) > 3 else "")
    errors = sum(bool(event.error_code or event.error_message) for event in events)
    result = (
        f"{event_count} linked AWS audit event{'s' if event_count != 1 else ''} "
        f"recorded: {actions}."
    )
    if errors:
        result += f" {errors} shown event{'s' if errors != 1 else ''} reported an AWS error."
    else:
        result += (
            " No shown event reports an AWS API error; the finding is a rule match, "
            "not an application error."
        )
    return result


def evidence_limitations(rule_type: str, truncated: bool) -> list[str]:
    limits = [
        "The audit events show what was recorded, not the actor's intent "
        "or the confirmed root cause."
    ]
    if rule_type == "contextual":
        limits.append(
            "The historical baseline used at detection time is not stored with this finding, "
            "so its exact comparison cannot be replayed here."
        )
    if truncated:
        limits.append("Only the first 50 linked events are shown; additional evidence exists.")
    return limits
