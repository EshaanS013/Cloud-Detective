import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import boto3


def test_s3_response_restores_all_public_access_blocks(monkeypatch) -> None:
    clients = {service: MagicMock() for service in ("s3", "ec2", "iam")}
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: clients[service])
    monkeypatch.setenv("AUDIT_BUCKET", "audit-example")
    monkeypatch.setenv("RESPONSE_MODE", "enforce")
    source = Path(__file__).resolve().parents[3] / "serverless" / "responder" / "handler.py"
    spec = importlib.util.spec_from_file_location("responder_test_module", source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    clients["s3"].get_bucket_tagging.return_value = {
        "TagSet": [{"Key": "CloudDetectiveSandbox", "Value": "true"}]
    }
    clients["s3"].put_public_access_block.return_value = {
        "ResponseMetadata": {"RequestId": "demo-request"}
    }

    result = module._handle_action(
        {
            "target_arn": "arn:aws:s3:::cloud-detective-demo",
            "playbook_id": "block-public-s3",
            "mode": "ENFORCE",
        }
    )

    assert result["outcome"] == "SUCCEEDED"
    assert result["aws_request_id"] == "demo-request"
    clients["s3"].put_public_access_block.assert_called_once_with(
        Bucket="cloud-detective-demo",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
