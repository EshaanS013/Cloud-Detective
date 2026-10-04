data "archive_file" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/frontend_gateway.zip"
}

resource "aws_cloudwatch_log_group" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-frontend-gateway"
  retention_in_days = 14
}

resource "aws_iam_role" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  name = "${var.name_prefix}-frontend-gateway"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "gateway_logs" {
  count = var.deploy_frontend ? 1 : 0

  role       = aws_iam_role.gateway[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  statement {
    sid       = "ReadDashboardAssets"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.bucket_arn}/*"]
  }

  statement {
    sid       = "DecryptDashboardAssets"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  name   = "${var.name_prefix}-frontend-read"
  role   = aws_iam_role.gateway[0].id
  policy = data.aws_iam_policy_document.gateway[0].json
}

resource "aws_lambda_function" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  function_name    = "${var.name_prefix}-frontend-gateway"
  role             = aws_iam_role.gateway[0].arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.gateway[0].output_path
  source_code_hash = data.archive_file.gateway[0].output_base64sha256
  memory_size      = 256
  timeout          = 30

  environment {
    variables = {
      FRONTEND_BUCKET = var.bucket_id
      API_ORIGIN      = var.deploy_runtime ? "http://${var.api_origin_domain}" : ""
      ORIGIN_SECRET   = var.deploy_runtime ? var.origin_verify_secret : ""
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.gateway,
    aws_iam_role_policy_attachment.gateway_logs,
    aws_iam_role_policy.gateway,
  ]
}

resource "aws_lambda_function_url" "gateway" {
  count = var.deploy_frontend ? 1 : 0

  function_name      = aws_lambda_function.gateway[0].function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "function_url" {
  count = var.deploy_frontend ? 1 : 0

  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.gateway[0].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "public_invoke" {
  count = var.deploy_frontend ? 1 : 0

  statement_id             = "AllowPublicFunctionUrlInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.gateway[0].function_name
  principal                = "*"
  invoked_via_function_url = true
}

data "aws_iam_policy_document" "bucket" {
  count = var.deploy_frontend ? 1 : 0

  statement {
    sid       = "AllowFrontendGatewayRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.bucket_arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.gateway[0].arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [var.bucket_arn, "${var.bucket_arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "frontend" {
  count = var.deploy_frontend ? 1 : 0

  bucket = var.bucket_id
  policy = data.aws_iam_policy_document.bucket[0].json
}
