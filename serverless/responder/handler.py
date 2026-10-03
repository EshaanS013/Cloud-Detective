import json
import os
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.config import Config

CONFIG = Config(
    retries={"total_max_attempts": 3, "mode": "adaptive"},
    connect_timeout=3,
    read_timeout=10,
    user_agent_appid="cloud-detective-responder/0.1",
)
EC2 = boto3.client("ec2", config=CONFIG)
S3 = boto3.client("s3", config=CONFIG)
IAM = boto3.client("iam", config=CONFIG)
AUDIT_BUCKET = os.environ["AUDIT_BUCKET"]
RESPONSE_MODE = os.environ.get("RESPONSE_MODE", "dry_run")
SANDBOX_TAG = {"Key": "CloudDetectiveSandbox", "Value": "true"}


def _parse_target(arn: str) -> tuple[str, str]:
    parts = arn.split(":", 5)
    if len(parts) != 6:
        raise ValueError("Target must be an AWS ARN")
    return parts[2], parts[5]


def _is_sandbox_target(service: str, resource: str) -> bool:
    if service == "ec2" and resource.startswith("instance/"):
        instance_id = resource.split("/", 1)[1]
        response = EC2.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": [SANDBOX_TAG["Key"]]},
                {"Name": "value", "Values": [SANDBOX_TAG["Value"]]},
            ]
        )
        return bool(response.get("Tags"))
    if service == "s3":
        try:
            tags = S3.get_bucket_tagging(Bucket=resource)["TagSet"]
        except S3.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchTagSet":
                return False
            raise
        return SANDBOX_TAG in tags
    if service == "iam" and resource.startswith("user/"):
        username = resource.split("/", 1)[1].split("#", 1)[0]
        tags = IAM.list_user_tags(UserName=username).get("Tags", [])
        return SANDBOX_TAG in tags
    return False


def _execute(playbook_id: str, service: str, resource: str) -> dict[str, Any]:
    if playbook_id == "stop-ec2-instance" and service == "ec2":
        return EC2.stop_instances(InstanceIds=[resource.split("/", 1)[1]])
    if playbook_id == "block-s3-public-access" and service == "s3":
        return S3.put_public_access_block(
            Bucket=resource,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    if playbook_id == "disable-access-key" and service == "iam":
        username, access_key_id = resource.split("/", 1)[1].split("#", 1)
        return IAM.update_access_key(
            UserName=username, AccessKeyId=access_key_id, Status="Inactive"
        )
    raise ValueError("Unsupported playbook and target combination")


def _handle_action(action: dict[str, Any]) -> dict[str, Any]:
    service, resource = _parse_target(action["target_arn"])
    if not _is_sandbox_target(service, resource):
        return {**action, "outcome": "DENIED_NOT_SANDBOX_TAGGED"}
    if action.get("mode") != "ENFORCE" or RESPONSE_MODE != "enforce":
        return {**action, "outcome": "SIMULATED"}
    response = _execute(action["playbook_id"], service, resource)
    request_id = response.get("ResponseMetadata", {}).get("RequestId")
    return {**action, "outcome": "SUCCEEDED", "aws_request_id": request_id}


def handler(event: dict[str, Any], _: Any) -> dict[str, Any]:
    results = []
    for record in event.get("Records", []):
        result = _handle_action(json.loads(record["body"]))
        result["executed_at"] = datetime.now(UTC).isoformat()
        key = f"responses/{result['action_id']}.json"
        S3.put_object(
            Bucket=AUDIT_BUCKET,
            Key=key,
            Body=json.dumps(result, default=str).encode(),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
        )
        results.append(result)
    return {"results": results}
