from app.seed import DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD


def _login(client, email: str = DEMO_ADMIN_EMAIL, password: str = DEMO_ADMIN_PASSWORD) -> str:
    response = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_demo_admin_login(client) -> None:
    token = _login(client)
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == DEMO_ADMIN_EMAIL
    assert body["role"] == "admin"


def test_login_rejects_bad_password(client) -> None:
    response = client.post(
        "/auth/login",
        data={"username": DEMO_ADMIN_EMAIL, "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_register_and_login(client) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": "analyst@example.com",
            "password": "password123",
            "role": "analyst",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "analyst"

    token = _login(client, "analyst@example.com", "password123")
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "analyst@example.com"


def test_register_cannot_self_assign_admin(client) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": "sneaky@example.com",
            "password": "password123",
            "role": "admin",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "analyst"


def test_audit_requires_admin(client) -> None:
    client.post(
        "/auth/register",
        json={
            "email": "viewer@example.com",
            "password": "password123",
            "role": "viewer",
        },
    )
    viewer_token = _login(client, "viewer@example.com", "password123")
    denied = client.get("/audit", headers={"Authorization": f"Bearer {viewer_token}"})
    assert denied.status_code == 403

    admin_token = _login(client)
    allowed = client.get("/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert allowed.status_code == 200
    actions = {row["action"] for row in allowed.json()}
    assert "auth.seed" in actions
    assert "auth.login" in actions
    assert "auth.register" in actions


def test_me_requires_auth(client) -> None:
    response = client.get("/auth/me")
    assert response.status_code == 401
