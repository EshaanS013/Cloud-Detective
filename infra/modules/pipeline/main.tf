data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_sqs_queue" "events_dlq" {
  name                      = "${var.name_prefix}-events-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = var.kms_key_arn
}

resource "aws_sqs_queue" "events" {
  name                       = "${var.name_prefix}-events"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20
  kms_master_key_id          = var.kms_key_arn
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.events_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "events" {
  queue_url = aws_sqs_queue.events_dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.events.arn]
  })
}

resource "aws_sqs_queue" "responses_dlq" {
  name                      = "${var.name_prefix}-responses-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = var.kms_key_arn
}

resource "aws_sqs_queue" "responses" {
  name                       = "${var.name_prefix}-responses"
  visibility_timeout_seconds = 180
  message_retention_seconds  = 345600
  kms_master_key_id          = var.kms_key_arn
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.responses_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "responses" {
  queue_url = aws_sqs_queue.responses_dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.responses.arn]
  })
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.kms_key_arn
}

data "archive_file" "collector" {
  type        = "zip"
  source_file = "${path.root}/../serverless/collector/handler.py"
  output_path = "${path.module}/collector.zip"
}

data "archive_file" "responder" {
  type        = "zip"
  source_file = "${path.root}/../serverless/responder/handler.py"
  output_path = "${path.module}/responder.zip"
}

locals {
  collector_name = "${var.name_prefix}-collector"
  responder_name = "${var.name_prefix}-responder"
}

resource "aws_iam_role" "collector" {
  name = local.collector_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "responder" {
  name = local.responder_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "collector_logs" {
  role       = aws_iam_role.collector.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "responder_logs" {
  role       = aws_iam_role.responder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "responder_sqs" {
  role       = aws_iam_role.responder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
}

data "aws_iam_policy_document" "collector" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]
  }
  statement {
    actions   = ["kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sqs.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "collector" {
  name   = "${local.collector_name}-runtime"
  role   = aws_iam_role.collector.id
  policy = data.aws_iam_policy_document.collector.json
}

data "aws_iam_policy_document" "responder" {
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sqs.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
  statement {
    actions   = ["ec2:DescribeTags"]
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:StopInstances"]
    resources = ["arn:aws:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CloudDetectiveSandbox"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["iam:ListUserTags", "iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:ResourceTag/CloudDetectiveSandbox"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["s3:GetBucketTagging", "s3:PutBucketPublicAccessBlock"]
    resources = ["arn:aws:s3:::*"]
    condition {
      test     = "StringEquals"
      variable = "s3:ResourceTag/CloudDetectiveSandbox"
      values   = ["true"]
    }
  }
  statement {
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectLegalHold",
      "s3:PutObjectRetention",
      "s3:PutObjectTagging"
    ]
    resources = ["${var.evidence_bucket_arn}/responses/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "responder" {
  name   = "${local.responder_name}-runtime"
  role   = aws_iam_role.responder.id
  policy = data.aws_iam_policy_document.responder.json
}

resource "aws_lambda_function" "collector" {
  function_name    = local.collector_name
  role             = aws_iam_role.collector.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.collector.output_path
  source_code_hash = data.archive_file.collector.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = { QUEUE_URL = aws_sqs_queue.events.id }
  }
}

resource "aws_lambda_function" "responder" {
  function_name    = local.responder_name
  role             = aws_iam_role.responder.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      AUDIT_BUCKET  = var.evidence_bucket_id
      RESPONSE_MODE = var.response_mode
    }
  }
}

resource "aws_lambda_event_source_mapping" "responder" {
  event_source_arn = aws_sqs_queue.responses.arn
  function_name    = aws_lambda_function.responder.arn
  batch_size       = 5

}

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "${var.name_prefix}-cloudtrail-events"
  description = "Capture AWS API calls delivered through CloudTrail"
  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "collector" {
  rule = aws_cloudwatch_event_rule.cloudtrail.name
  arn  = aws_lambda_function.collector.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id   = "AllowEventBridgeInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.collector.function_name
  principal      = "events.amazonaws.com"
  source_arn     = aws_cloudwatch_event_rule.cloudtrail.arn
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_cloudtrail" "this" {
  name                          = var.name_prefix
  s3_bucket_name                = var.trail_bucket_id
  kms_key_id                    = var.kms_key_arn
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  enable_logging                = true
}
