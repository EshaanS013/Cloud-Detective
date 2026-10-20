from functools import lru_cache
from typing import Any

import boto3
from botocore.config import Config

from cloud_detective.config import get_settings


def aws_config() -> Config:
    return Config(
        retries={"total_max_attempts": 3, "mode": "adaptive"},
        connect_timeout=5,
        read_timeout=25,
        user_agent_appid="cloud-detective/0.1",
    )


@lru_cache
def aws_client(service: str) -> Any:
    return boto3.client(
        service,
        region_name=get_settings().aws_region,
        config=aws_config(),
    )
