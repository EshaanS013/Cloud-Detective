data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["137112412989"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

locals {
  source_key = "build/source.zip"
  status_key = "build/status-${var.image_tag}.json"
  log_key    = "build/log-${var.image_tag}.txt"
}

resource "aws_iam_role" "build" {
  count = var.deploy_builder ? 1 : 0

  name = "${var.name_prefix}-image-builder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "build" {
  count = var.deploy_builder ? 1 : 0

  statement {
    sid       = "ReadBuildSource"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${var.source_bucket_arn}/${local.source_key}"]
  }

  statement {
    sid     = "WriteBuildResult"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${var.source_bucket_arn}/${local.status_key}",
      "${var.source_bucket_arn}/${local.log_key}",
    ]
  }

  statement {
    sid       = "UseEncryptedBuildObjects"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
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
  count = var.deploy_builder ? 1 : 0

  name   = "${var.name_prefix}-image-publish"
  role   = aws_iam_role.build[0].id
  policy = data.aws_iam_policy_document.build[0].json
}

resource "aws_iam_instance_profile" "build" {
  count = var.deploy_builder ? 1 : 0

  name = "${var.name_prefix}-image-builder"
  role = aws_iam_role.build[0].name
}

resource "aws_security_group" "build" {
  count = var.deploy_builder ? 1 : 0

  name_prefix = "${var.name_prefix}-builder-"
  description = "No-ingress security group for the temporary image builder"
  vpc_id      = var.vpc_id

  egress {
    description = "HTTPS for package registries and AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_instance" "build" {
  count = var.deploy_builder ? 1 : 0

  ami                                  = data.aws_ami.amazon_linux.id
  instance_type                        = "t3.small"
  subnet_id                            = var.public_subnet_id
  vpc_security_group_ids               = [aws_security_group.build[0].id]
  associate_public_ip_address          = true
  iam_instance_profile                 = aws_iam_instance_profile.build[0].name
  instance_initiated_shutdown_behavior = "stop"
  user_data_replace_on_change          = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 16
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/builder.sh.tftpl", {
    aws_region            = var.aws_region
    source_bucket_id      = var.source_bucket_id
    source_key            = local.source_key
    status_key            = local.status_key
    log_key               = local.log_key
    api_repository_url    = var.api_repository_url
    worker_repository_url = var.worker_repository_url
    registry_domain       = split("/", var.api_repository_url)[0]
    image_tag             = var.image_tag
  })

  tags = { Name = "${var.name_prefix}-image-builder" }

  lifecycle {
    precondition {
      condition     = var.image_tag != ""
      error_message = "image_tag is required when deploy_builder is true."
    }
  }

  depends_on = [aws_iam_role_policy.build]
}
