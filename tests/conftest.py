"""Pytest fixtures — isolate tests on a temporary SQLite database."""

import os
from collections.abc import Generator
from pathlib import Path

import pytest

# Must set env before app modules cache settings / engine.
_TEST_DB = Path(__file__).resolve().parent / "test_cyber_defense.db"
if _TEST_DB.exists():
    _TEST_DB.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB.as_posix()}"
os.environ["APP_ENV"] = "development"
os.environ["ALLOW_REGISTRATION"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-for-jwt"

from app.config import get_settings  # noqa: E402

get_settings.cache_clear()

from app.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed_demo_admin  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_db() -> Generator[None, None, None]:
    Base.metadata.drop_all(bind=engine)
    init_db()
    db = SessionLocal()
    try:
        seed_demo_admin(db)
    finally:
        db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client
