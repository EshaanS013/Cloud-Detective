from datetime import UTC, datetime
from functools import lru_cache
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cloud_detective.auth import Principal, require_analyst, require_responder
from cloud_detective.aws import aws_client
from cloud_detective.config import get_settings
from cloud_detective.db.models import Event, Finding, ResponseAction, Rule
from cloud_detective.db.session import get_session
from cloud_detective.detection.engine import DetectionEngine
from cloud_detective.detection.loader import load_rules
from cloud_detective.detection.persistence import persist_event, persist_finding, sync_rule_catalog
from cloud_detective.schemas.api import (
    DashboardSummary,
    EventView,
    FindingUpdate,
    FindingView,
    IngestResult,
    ResponseRequest,
    ResponseResult,
    RuleView,
)
from cloud_detective.schemas.events import normalize_cloudtrail_event

router = APIRouter(prefix="/api/v1")
SessionDep = Annotated[Session, Depends(get_session)]
ResponderDep = Annotated[Principal, Depends(require_responder)]


@lru_cache
def get_detection_engine() -> DetectionEngine:
    return DetectionEngine(load_rules(get_settings().rules_path))


@router.get("/summary", response_model=DashboardSummary, dependencies=[Depends(require_analyst)])
def summary(session: SessionDep) -> DashboardSummary:
    severity_rows = session.execute(
        select(Finding.severity, func.count())
        .where(Finding.status != "RESOLVED")
        .group_by(Finding.severity)
    ).all()
    return DashboardSummary(
        total_events=session.scalar(select(func.count()).select_from(Event)) or 0,
        open_findings=session.scalar(
            select(func.count()).select_from(Finding).where(Finding.status != "RESOLVED")
        )
        or 0,
        enabled_rules=session.scalar(
            select(func.count()).select_from(Rule).where(Rule.enabled.is_(True))
        )
        or 0,
        severity_counts={str(severity): count for severity, count in severity_rows},
        response_mode=get_settings().response_mode,
    )


@router.get("/findings", response_model=list[FindingView], dependencies=[Depends(require_analyst)])
def list_findings(
    session: SessionDep,
    finding_status: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[Finding]:
    query = select(Finding).order_by(Finding.created_at.desc()).limit(limit).offset(offset)
    if finding_status:
        query = query.where(Finding.status == finding_status.upper())
    if severity:
        query = query.where(Finding.severity == severity.upper())
    return list(session.scalars(query))


@router.get(
    "/findings/{finding_id}",
    response_model=FindingView,
    dependencies=[Depends(require_analyst)],
)
def get_finding(finding_id: UUID, session: SessionDep) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingView)
def update_finding(
    finding_id: UUID,
    update: FindingUpdate,
    session: SessionDep,
    _: ResponderDep,
) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.status = update.status
    finding.assigned_to = update.assigned_to
    finding.notes = update.notes
    finding.resolved_at = datetime.now(UTC) if update.status == "RESOLVED" else None
    session.commit()
    session.refresh(finding)
    return finding


@router.get("/events", response_model=list[EventView], dependencies=[Depends(require_analyst)])
def list_events(
    session: SessionDep,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[Event]:
    return list(
        session.scalars(select(Event).order_by(Event.event_time.desc()).limit(limit).offset(offset))
    )


@router.get("/rules", response_model=list[RuleView], dependencies=[Depends(require_analyst)])
def list_rules(session: SessionDep) -> list[Rule]:
    return list(session.scalars(select(Rule).order_by(Rule.category, Rule.name)))


@router.post("/events/ingest", response_model=IngestResult, status_code=status.HTTP_202_ACCEPTED)
def ingest_event(
    payload: dict[str, Any],
    session: SessionDep,
    _: ResponderDep,
) -> IngestResult:
    engine = get_detection_engine()
    rules = engine.rules
    sync_rule_catalog(session, rules)
    event = normalize_cloudtrail_event(payload)
    inserted = persist_event(session, event)
    finding_ids: list[UUID] = []
    if inserted:
        for candidate in engine.process(event):
            finding_id = persist_finding(session, candidate)
            if finding_id:
                finding_ids.append(finding_id)
    session.commit()
    return IngestResult(
        accepted=inserted,
        duplicate=not inserted,
        finding_ids=finding_ids,
        warnings=event.parse_warnings,
    )


@router.post("/findings/{finding_id}/responses", response_model=ResponseResult)
def run_response(
    finding_id: UUID,
    request: ResponseRequest,
    session: SessionDep,
    principal: ResponderDep,
) -> ResponseResult:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    settings = get_settings()
    requested_enforcement = request.confirmation == "ENFORCE"
    enforcement_allowed = settings.response_mode == "enforce"
    if requested_enforcement and not enforcement_allowed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Live response is disabled; use DRY_RUN or enable response mode explicitly",
        )

    idempotency_key = f"{finding_id}:{request.playbook_id}:{request.target_arn}"
    existing = session.scalar(
        select(ResponseAction).where(ResponseAction.idempotency_key == idempotency_key)
    )
    if existing:
        return ResponseResult(
            action_id=existing.id,
            mode=existing.mode,
            decision=existing.decision,
            outcome=existing.outcome or "UNKNOWN",
            preview={"idempotent_replay": True},
        )

    action = ResponseAction(
        finding_id=finding_id,
        idempotency_key=idempotency_key,
        playbook_id=request.playbook_id,
        target_arn=request.target_arn,
        actor=principal.username,
        mode=request.confirmation,
        decision="APPROVED" if requested_enforcement else "PREVIEW",
        outcome="QUEUED" if requested_enforcement else "SIMULATED",
        previous_state=None,
    )
    session.add(action)
    session.commit()
    session.refresh(action)

    if requested_enforcement:
        if not settings.response_queue_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Response queue is not configured",
            )
        import json

        aws_client("sqs").send_message(
            QueueUrl=settings.response_queue_url,
            MessageBody=json.dumps(
                {
                    "action_id": str(action.id),
                    "finding_id": str(finding_id),
                    "playbook_id": request.playbook_id,
                    "target_arn": request.target_arn,
                    "mode": request.confirmation,
                    "actor": principal.username,
                }
            ),
        )
    return ResponseResult(
        action_id=action.id,
        mode=action.mode,
        decision=action.decision,
        outcome=action.outcome or "UNKNOWN",
        preview={
            "playbook": request.playbook_id,
            "target": request.target_arn,
            "tag_scope_required": "CloudDetectiveSandbox=true",
        },
    )
