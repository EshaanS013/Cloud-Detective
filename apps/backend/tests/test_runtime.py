import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from cloud_detective import worker
from cloud_detective.auth import Principal, current_principal, require_analyst, require_responder
from cloud_detective.db import session as db_session
from cloud_detective.db.session import database_url
from cloud_detective.main import load_balancer_health


def test_local_authentication_has_responder_access() -> None:
    principal = current_principal(None)
    assert principal.username == "local-developer"
    assert require_analyst(principal) is principal
    assert require_responder(principal) is principal


def test_role_guards_reject_unprivileged_principal() -> None:
    principal = Principal(subject="1", username="viewer", groups=frozenset())
    with pytest.raises(HTTPException) as analyst_error:
        require_analyst(principal)
    assert analyst_error.value.status_code == 403
    with pytest.raises(HTTPException) as responder_error:
        require_responder(principal)
    assert responder_error.value.status_code == 403


def test_local_database_url_and_load_balancer_health() -> None:
    database_url.cache_clear()
    assert database_url().startswith("postgresql+psycopg://")
    assert load_balancer_health() == {"status": "ok"}


def test_database_secret_credentials_are_url_encoded(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Mock()
    client.get_secret_value.return_value = {
        "SecretString": json.dumps(
            {
                "username": "cloud_detective",
                "password": "special@password/with spaces",
                "host": "database.internal",
                "port": 5432,
                "dbname": "cloud_detective",
            }
        )
    }
    monkeypatch.setattr(
        db_session,
        "get_settings",
        lambda: SimpleNamespace(database_secret_arn="arn:aws:secretsmanager:test"),
    )
    monkeypatch.setattr(db_session, "aws_client", lambda _: client)

    database_url.cache_clear()
    result = database_url()

    assert "special%40password%2Fwith spaces" in result
    database_url.cache_clear()


def test_worker_commits_new_event_and_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Mock()
    engine = SimpleNamespace(rules=["rule"], process=Mock(return_value=["candidate"]))
    monkeypatch.setattr(worker, "get_detection_engine", lambda: engine)
    monkeypatch.setattr(worker, "sync_rule_catalog", Mock())
    monkeypatch.setattr(worker, "persist_event", Mock(return_value=True))
    monkeypatch.setattr(worker, "persist_finding", Mock(return_value="finding-id"))

    accepted, count = worker.process_payload(
        session,
        {"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com"},
    )

    assert accepted is True
    assert count == 1
    session.commit.assert_called_once()


def test_worker_acknowledges_duplicate_without_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Mock()
    engine = SimpleNamespace(rules=[], process=Mock())
    monkeypatch.setattr(worker, "get_detection_engine", lambda: engine)
    monkeypatch.setattr(worker, "sync_rule_catalog", Mock())
    monkeypatch.setattr(worker, "persist_event", Mock(return_value=False))

    accepted, count = worker.process_payload(session, {"eventName": "ListBuckets"})

    assert accepted is False
    assert count == 0
    engine.process.assert_not_called()
    session.commit.assert_called_once()
