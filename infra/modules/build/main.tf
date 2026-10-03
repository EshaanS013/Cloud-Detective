locals {
  source_key      = "build/source.zip"
  registry_domain = split("/", var.api_repository_url)[0]
}

resource "aws_cloudwatch_log_group" "build" {
  name              = "/aws/codebuild/${var.name_prefix}-containers"
  retention_in_days = 14
  kms_key_id        = var.kms_key_arn
}

resource "aws_iam_role" "build" {
  name = "${var.name_prefix}-codebuild"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "build" {
  statement {
    sid       = "ReadBuildSource"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${var.source_bucket_arn}/${local.source_key}"]
  }

  statement {
    sid       = "DecryptBuildSource"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "WriteBuildLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.build.arn}:*"]
  }

  statement {
    sid       = "UseEncryptedBuildLogs"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["logs.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AuthenticateToEcr"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PublishApplicationImages"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [var.api_repository_arn, var.worker_repository_arn]
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "${var.name_prefix}-container-publish"
  role   = aws_iam_role.build.id
  policy = data.aws_iam_policy_document.build.json
}

resource "aws_codebuild_project" "containers" {
  name          = "${var.name_prefix}-containers"
  description   = "Build and publish Cloud Detective API and worker images"
  service_role  = aws_iam_role.build.arn
  build_timeout = 30

  artifacts {
    type = "NO_ARTIFACTS"
  }

  source {
    type      = "S3"
    location  = "${var.source_bucket_id}/${local.source_key}"
    buildspec = <<-YAML
      version: 0.2
      phases:
        install:
          on-failure: ABORT
          runtime-versions:
            docker: 25
        pre_build:
          on-failure: ABORT
          commands:
            - test -n "$IMAGE_TAG"
            - aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | docker login --username AWS --password-stdin "${local.registry_domain}"
        build:
          on-failure: ABORT
          commands:
            - docker build --pull -f apps/backend/Dockerfile -t "${var.api_repository_url}:$IMAGE_TAG" .
            - docker tag "${var.api_repository_url}:$IMAGE_TAG" "${var.worker_repository_url}:$IMAGE_TAG"
            - docker push "${var.api_repository_url}:$IMAGE_TAG"
            - docker push "${var.worker_repository_url}:$IMAGE_TAG"
    YAML
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "IMAGE_TAG"
      value = "manual"
      type  = "PLAINTEXT"
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name  = aws_cloudwatch_log_group.build.name
      stream_name = "containers"
      status      = "ENABLED"
    }
  }

  depends_on = [aws_iam_role_policy.build]
}
