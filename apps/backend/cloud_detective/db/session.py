import json
from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import URL, Engine, create_engine
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
    host = secret.get("host") or settings.database_host
    if not host:
        raise RuntimeError("DATABASE_HOST is required when the database secret has no host")
    port = secret.get("port", settings.database_port)
    database = secret.get("dbname", settings.database_name)
    return URL.create(
        "postgresql+psycopg",
        username=secret["username"],
        password=secret["password"],
        host=host,
        port=port,
        database=database,
    ).render_as_string(hide_password=False)


@lru_cache
def get_engine() -> Engine:
    return create_engine(database_url(), pool_pre_ping=True, pool_recycle=300)


def get_session() -> Generator[Session, None, None]:
    factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    with factory() as session:
        yield session
