from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Cyber Defense Lab"
    app_env: str = "development"
    secret_key: str = "change-me-to-a-long-random-string"
    access_token_expire_minutes: int = 60
    database_url: str = "sqlite:///./data/cyber_defense.db"
    allow_registration: bool = True
    simulation_mode: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
