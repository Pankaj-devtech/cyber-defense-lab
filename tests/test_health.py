from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["simulation_mode"] is True


def test_home_page_renders() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Cyber Defense Lab" in response.text
