import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from cloud_detective.detection.matching import context_matches, event_matches
from cloud_detective.detection.models import (
    EventContext,
    FindingCandidate,
    RuleDefinition,
    RuleType,
)
from cloud_detective.detection.scoring import assess_risk
from cloud_detective.schemas.events import CanonicalEvent


@dataclass
class SequenceState:
    cursor: int = 0
    started_at: datetime | None = None
    events: list[CanonicalEvent] = field(default_factory=list)


class DetectionEngine:
    def __init__(self, rules: list[RuleDefinition], max_seen_events: int = 100_000) -> None:
        self.rules = [rule for rule in rules if rule.enabled]
        self.max_seen_events = max_seen_events
        self._seen: set[UUID] = set()
        self._seen_order: deque[UUID] = deque()
        self._windows: dict[tuple[str, str], deque[CanonicalEvent]] = defaultdict(deque)
        self._sequences: dict[tuple[str, str], SequenceState] = defaultdict(SequenceState)

    def process(
        self, event: CanonicalEvent, context: EventContext | None = None
    ) -> list[FindingCandidate]:
        if event.event_id in self._seen:
            return []
        self._remember(event.event_id)
        context = context or EventContext()
        matches: list[FindingCandidate] = []

        for rule in self.rules:
            if event.principal_arn in rule.suppress_principals:
                continue
            matched_events = self._evaluate(rule, event, context)
            if matched_events:
                matches.append(self._candidate(rule, matched_events, event, context))
        return matches

    def _remember(self, event_id: UUID) -> None:
        self._seen.add(event_id)
        self._seen_order.append(event_id)
        while len(self._seen_order) > self.max_seen_events:
            self._seen.discard(self._seen_order.popleft())

    def _evaluate(
        self, rule: RuleDefinition, event: CanonicalEvent, context: EventContext
    ) -> list[CanonicalEvent]:
        if rule.type is RuleType.SIGNATURE:
            return [event] if event_matches(rule.match, event) else []
        if rule.type is RuleType.CONTEXTUAL:
            if not context.baseline_warmed:
                return []
            return (
                [event]
                if event_matches(rule.match, event) and context_matches(rule.conditions, context)
                else []
            )
        if rule.type is RuleType.THRESHOLD:
            return self._threshold(rule, event)
        return self._sequence(rule, event)

    def _threshold(self, rule: RuleDefinition, event: CanonicalEvent) -> list[CanonicalEvent]:
        if not event_matches(rule.match, event):
            return []
        group_key = self._group_value(rule.group_by, event)
        if group_key is None:
            return []
        window = self._windows[(rule.id, group_key)]
        cutoff = event.event_time - timedelta(seconds=rule.window_seconds or 0)
        while window and window[0].event_time < cutoff:
            window.popleft()
        window.append(event)
        return list(window) if len(window) >= (rule.threshold or 0) else []

    def _sequence(self, rule: RuleDefinition, event: CanonicalEvent) -> list[CanonicalEvent]:
        group_key = self._group_value(rule.group_by, event)
        if group_key is None:
            return []
        state = self._sequences[(rule.id, group_key)]
        if state.started_at and event.event_time - state.started_at > timedelta(
            seconds=rule.window_seconds or 0
        ):
            state = SequenceState()
            self._sequences[(rule.id, group_key)] = state

        if state.events and event.event_time < state.events[-1].event_time:
            return []

        expected = rule.steps[state.cursor]
        if event_matches(expected, event):
            if state.cursor == 0:
                state.started_at = event.event_time
                state.events = []
            state.events.append(event)
            state.cursor += 1
            if state.cursor == len(rule.steps):
                matched = list(state.events)
                self._sequences[(rule.id, group_key)] = SequenceState()
                return matched
        elif state.cursor and event_matches(rule.steps[0], event):
            self._sequences[(rule.id, group_key)] = SequenceState(
                cursor=1, started_at=event.event_time, events=[event]
            )
        return []

    @staticmethod
    def _group_value(field: str | None, event: CanonicalEvent) -> str | None:
        if not field:
            return "all"
        value: Any = getattr(event, field, None)
        return str(value) if value not in {None, ""} else None

    def _candidate(
        self,
        rule: RuleDefinition,
        events: list[CanonicalEvent],
        trigger: CanonicalEvent,
        context: EventContext,
    ) -> FindingCandidate:
        group_key = self._group_value(rule.group_by, trigger) or trigger.principal_arn or "global"
        event_ids = [event.event_id for event in events]
        digest_source = f"{rule.id}|{group_key}|" + "|".join(str(value) for value in event_ids)
        dedupe_key = hashlib.sha256(digest_source.encode()).hexdigest()
        risk = assess_risk(rule.base_score, trigger, context)
        return FindingCandidate(
            rule_id=rule.id,
            rule_name=rule.name,
            category=rule.category,
            title=rule.name,
            description=rule.description,
            group_key=group_key,
            window_start=events[0].event_time,
            window_end=events[-1].event_time,
            event_ids=event_ids,
            risk=risk,
            dedupe_key=dedupe_key,
            principal_arn=trigger.principal_arn,
            source_ip=trigger.source_ip,
            affected_resources=sorted(
                {resource for matched_event in events for resource in matched_event.resources}
            ),
            playbook_id=rule.playbook_id,
            mitre_technique=rule.mitre_technique,
        )

