import json
from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from cloud_detective.aws import aws_client
from cloud_detective.config import get_settings


@lru_cache
def database_url() -> str:
    settings = get_settings()
    if not settings.database_secret_arn:
        return settings.database_url

    client = aws_client("secretsmanager")
    response = client.get_secret_value(SecretId=settings.database_secret_arn)
    secret = json.loads(response["SecretString"])
    host = secret["host"]
    port = secret.get("port", 5432)
    database = secret.get("dbname", "cloud_detective")
    return (
        f"postgresql+psycopg://{secret['username']}:{secret['password']}@"
        f"{host}:{port}/{database}"
    )


@lru_cache
def get_engine() -> Engine:
    return create_engine(database_url(), pool_pre_ping=True, pool_recycle=300)


def get_session() -> Generator[Session, None, None]:
    factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    with factory() as session:
        yield session
