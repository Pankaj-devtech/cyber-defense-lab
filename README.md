# Cyber Defense Lab

Adaptive intrusion response demo for portfolio and campus interviews.

Detect simulated attacks, classify them with a small scikit-learn model, explain decisions, and apply adaptive (ε-greedy) response actions inside a **safe simulation sandbox**.

## Stack (simplified)

- Python 3.12 + FastAPI + Jinja2/HTMX-ready templates
- SQLite
- scikit-learn (tiny classifier — later milestone)
- Docker Compose
- JWT auth + RBAC (later milestone)

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

## Tests

```bash
pytest -q
```

## Current milestone

**M0 — Bootstrap:** runnable app shell, health endpoint, Docker Compose, SQLite init, home page.

## Roadmap (next)

1. Auth (JWT + roles + audit)
2. Attack simulator + detection rules
3. Incidents + risk score + MITRE mapping
4. sklearn classifier + explanations
5. Adaptive response engine
6. Dashboard polish + demo script

## Safety

All responses are simulated. This project does **not** attack real networks.
