# Cyber Defense Lab

Adaptive intrusion response demo for portfolio and campus interviews.

Detect simulated attacks, classify them with a small scikit-learn model, explain decisions, and apply adaptive (ε-greedy) response actions inside a **safe simulation sandbox**.

## Stack (simplified)

- Python 3.12 + FastAPI + Jinja2/HTMX-ready templates
- SQLite
- JWT auth + RBAC + audit log
- Attack simulator + rule-based detection
- scikit-learn (tiny classifier — later milestone)
- Docker Compose

## Quick start (Docker)

```bash
cp .env.example .env
docker compose up --build
```

Open:

- App: http://localhost:8000
- Health: http://localhost:8000/health
- API docs: http://localhost:8000/docs

## Local start (without Docker)

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

## Auth (M1)

Roles (ascending privilege): `viewer` → `analyst` → `admin`.

| Endpoint | Access | Notes |
|---|---|---|
| `POST /auth/register` | public* | Body: `{email, password, role?}`. Cannot self-assign `admin`. |
| `POST /auth/login` | public | OAuth2 password form (`username`=email). Returns JWT. |
| `GET /auth/me` | authenticated | Current user profile. |
| `GET /audit` | admin+ | Recent audit events (login, register, seed, …). |

\* Registration respects `ALLOW_REGISTRATION` in `.env`.

**Dev demo admin** (seeded when the users table is empty, non-production only):

- Email: `admin@example.com`
- Password: `admin123`

```bash
curl -X POST http://localhost:8000/auth/login \
  -d "username=admin@example.com&password=admin123"
```

## Lab simulation (M2)

All traffic is **synthetic** — nothing leaves the sandbox.

| Endpoint | Access | Notes |
|---|---|---|
| `GET /rules` | authenticated | Built-in detection rules (R001–R004). |
| `POST /simulate` | analyst+ | Body: `{scenario, count?, seed?}`. Generates events + runs rules. |
| `GET /events` | authenticated | Recent simulated events. |
| `GET /detections` | authenticated | Rule hits with optional MITRE technique IDs. |

Scenarios: `brute_force`, `port_scan`, `malware_beacon`, `sql_injection`, `mixed`, `benign`.

```bash
TOKEN=... # from /auth/login
curl -X POST http://localhost:8000/simulate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"brute_force\",\"count\":8,\"seed\":42}"
```

## Tests

```bash
pytest -q
```

## Current milestone

**M2 — Attack simulator + detection rules:** synthetic scenarios, rule engine, events/detections APIs.

## Roadmap (next)

1. ~~Auth (JWT + roles + audit)~~
2. ~~Attack simulator + detection rules~~
3. Incidents + risk score + MITRE mapping
4. sklearn classifier + explanations
5. Adaptive response engine
6. Dashboard polish + demo script

## Safety

All responses are simulated. This project does **not** attack real networks.
