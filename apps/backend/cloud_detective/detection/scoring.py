from zoneinfo import ZoneInfo

from cloud_detective.detection.models import EventContext, RiskAssessment, Severity
from cloud_detective.schemas.events import CanonicalEvent, PrincipalType

IST = ZoneInfo("Asia/Kolkata")


def severity_for(score: float) -> Severity:
    if score < 20:
        return Severity.NORMAL
    if score < 40:
        return Severity.LOW
    if score < 60:
        return Severity.MEDIUM
    if score < 80:
        return Severity.HIGH
    return Severity.CRITICAL


def assess_risk(base_score: int, event: CanonicalEvent, context: EventContext) -> RiskAssessment:
    principal = {
        PrincipalType.ROOT: 2.0,
        PrincipalType.IAM_USER: 1.3,
        PrincipalType.ASSUMED_ROLE: 1.1,
        PrincipalType.AWS_SERVICE: 0.8,
    }.get(event.principal_type, 1.0)

    if context.security_critical_resource:
        resource = 1.8
    elif context.production_resource:
        resource = 1.4
    else:
        resource = 1.0
    local_hour = event.event_time.astimezone(IST).hour
    time = 1.3 if local_hour < 8 or local_hour >= 22 else 1.0
    if context.known_bad_origin:
        origin = 2.5
    elif not context.country_seen and context.country:
        origin = 1.8
    elif not context.ip_seen and event.source_ip:
        origin = 1.3
    else:
        origin = 1.0
    mfa = 1.4 if event.mfa_authenticated is False else 1.0
    factors = {
        "base": float(base_score),
        "principal": principal,
        "resource": resource,
        "time": time,
        "origin": origin,
        "mfa": mfa,
    }
    score = min(100.0, round(base_score * principal * resource * time * origin * mfa, 2))
    return RiskAssessment(score=score, severity=severity_for(score), factors=factors)

