import json
import logging
import signal
from types import FrameType
from typing import Any

from sqlalchemy.orm import Session

from cloud_detective.api import get_detection_engine
from cloud_detective.aws import aws_client
from cloud_detective.config import get_settings
from cloud_detective.db.session import get_engine
from cloud_detective.detection.persistence import persist_event, persist_finding, sync_rule_catalog
from cloud_detective.schemas.events import normalize_cloudtrail_event

logger = logging.getLogger(__name__)
running = True


def process_payload(session: Session, payload: dict[str, Any]) -> tuple[bool, int]:
    engine = get_detection_engine()
    sync_rule_catalog(session, engine.rules)
    event = normalize_cloudtrail_event(payload)
    if not persist_event(session, event):
        session.commit()
        return False, 0

    finding_count = 0
    for candidate in engine.process(event):
        if persist_finding(session, candidate):
            finding_count += 1
    session.commit()
    return True, finding_count


def _stop(_: int, __: FrameType | None) -> None:
    global running
    running = False


def run() -> None:
    settings = get_settings()
    if not settings.queue_url:
        raise RuntimeError("QUEUE_URL is required for the detector worker")

    logging.basicConfig(level=settings.log_level)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    sqs = aws_client("sqs")

    while running:
        response = sqs.receive_message(
            QueueUrl=settings.queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=settings.poll_wait_seconds,
            VisibilityTimeout=60,
        )
        for message in response.get("Messages", []):
            payload = json.loads(message["Body"])
            with Session(get_engine()) as session:
                accepted, findings = process_payload(session, payload)
            sqs.delete_message(QueueUrl=settings.queue_url, ReceiptHandle=message["ReceiptHandle"])
            logger.info(
                "processed_event",
                extra={"accepted": accepted, "finding_count": findings},
            )


if __name__ == "__main__":
    run()
