import json
import os
from typing import Any

import boto3
from botocore.config import Config

QUEUE_URL = os.environ["QUEUE_URL"]
SQS = boto3.client(
    "sqs",
    config=Config(
        retries={"total_max_attempts": 3, "mode": "adaptive"},
        connect_timeout=3,
        read_timeout=10,
        user_agent_appid="cloud-detective-collector/0.1",
    ),
)


def handler(event: dict[str, Any], _: Any) -> dict[str, Any]:
    response = SQS.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(event, default=str))
    return {"accepted": True, "message_id": response["MessageId"]}
