from fastapi.testclient import TestClient

from cloud_detective.main import app


def test_health_endpoint() -> None:
    response = TestClient(app).get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "cloud-detective-api",
        "version": "0.1.0",
        "environment": "local",
        "response_mode": "dry_run",
    }


def test_frontend_origin_is_allowed() -> None:
    response = TestClient(app).options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
