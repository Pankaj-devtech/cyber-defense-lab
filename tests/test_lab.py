from app.seed import DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD


def _auth_header(client, email: str = DEMO_ADMIN_EMAIL, password: str = DEMO_ADMIN_PASSWORD) -> dict[str, str]:
    response = client.post("/auth/login", data={"username": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_list_rules(client) -> None:
    headers = _auth_header(client)
    response = client.get("/rules", headers=headers)
    assert response.status_code == 200
    rule_ids = {row["rule_id"] for row in response.json()}
    assert {"R001", "R002", "R003", "R004"} <= rule_ids


def test_simulate_brute_force_creates_detections(client) -> None:
    headers = _auth_header(client)
    response = client.post(
        "/simulate",
        headers=headers,
        json={"scenario": "brute_force", "count": 8, "seed": 42},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["events_created"] == 8
    assert body["detections_created"] >= 5
    assert all(d["rule_id"] == "R001" for d in body["detections"])

    events = client.get("/events", headers=headers)
    assert events.status_code == 200
    assert len(events.json()) >= 8

    detections = client.get("/detections", headers=headers)
    assert detections.status_code == 200
    assert len(detections.json()) >= 5


def test_simulate_requires_analyst(client) -> None:
    client.post(
        "/auth/register",
        json={"email": "viewer2@example.com", "password": "password123", "role": "viewer"},
    )
    login = client.post(
        "/auth/login",
        data={"username": "viewer2@example.com", "password": "password123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    response = client.post(
        "/simulate",
        headers=headers,
        json={"scenario": "benign", "count": 3},
    )
    assert response.status_code == 403


def test_sql_injection_rule_fires(client) -> None:
    headers = _auth_header(client)
    response = client.post(
        "/simulate",
        headers=headers,
        json={"scenario": "sql_injection", "count": 4, "seed": 7},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["detections_created"] == 4
    assert all(d["rule_id"] == "R004" for d in body["detections"])
    assert all(d["mitre_technique"] == "T1190" for d in body["detections"])


def test_benign_traffic_has_no_detections(client) -> None:
    headers = _auth_header(client)
    response = client.post(
        "/simulate",
        headers=headers,
        json={"scenario": "benign", "count": 10, "seed": 1},
    )
    assert response.status_code == 201
    assert response.json()["detections_created"] == 0
