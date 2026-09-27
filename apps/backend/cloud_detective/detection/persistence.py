from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from cloud_detective.db.models import Event, Finding, FindingEvent, Rule
from cloud_detective.detection.models import FindingCandidate, RuleDefinition
from cloud_detective.schemas.events import CanonicalEvent


def sync_rule_catalog(session: Session, rules: list[RuleDefinition]) -> None:
    for rule in rules:
        values = {
            "id": rule.id,
            "name": rule.name,
            "rule_type": rule.type.value,
            "category": rule.category,
            "definition": rule.model_dump(mode="json"),
            "base_score": rule.base_score,
            "enabled": rule.enabled,
            "suppress_principals": rule.suppress_principals,
            "playbook_id": rule.playbook_id,
            "mitre_technique": rule.mitre_technique,
        }
        statement = insert(Rule).values(**values)
        session.execute(
            statement.on_conflict_do_update(
                index_elements=[Rule.id],
                set_={key: value for key, value in values.items() if key != "id"},
            )
        )


def persist_event(session: Session, event: CanonicalEvent) -> bool:
    values = event.model_dump(mode="json")
    values.pop("ingested_at")
    statement = (
        insert(Event)
        .values(**values)
        .on_conflict_do_nothing(index_elements=[Event.event_id])
        .returning(Event.event_id)
    )
    return session.execute(statement).scalar_one_or_none() is not None


def persist_finding(session: Session, candidate: FindingCandidate) -> UUID | None:
    finding_id = uuid5(NAMESPACE_URL, candidate.dedupe_key)
    statement = (
        insert(Finding)
        .values(
            id=finding_id,
            rule_id=candidate.rule_id,
            group_key=candidate.group_key,
            severity=candidate.risk.severity.value,
            risk_score=candidate.risk.score,
            score_breakdown=candidate.risk.factors,
            title=candidate.title,
            description=candidate.description,
            window_start=candidate.window_start,
            window_end=candidate.window_end,
        )
        .on_conflict_do_nothing(
            index_elements=[Finding.rule_id, Finding.group_key, Finding.window_start]
        )
        .returning(Finding.id)
    )
    inserted_id = session.execute(statement).scalar_one_or_none()
    if inserted_id is None:
        return None

    for event_id in candidate.event_ids:
        session.execute(
            insert(FindingEvent)
            .values(finding_id=inserted_id, event_id=event_id, role="trigger")
            .on_conflict_do_nothing(
                index_elements=[FindingEvent.finding_id, FindingEvent.event_id]
            )
        )
    return inserted_id

