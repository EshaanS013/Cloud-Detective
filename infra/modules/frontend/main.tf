resource "aws_cloudfront_origin_access_control" "this" {
  count = var.deploy_frontend ? 1 : 0

  name                              = "${var.name_prefix}-dashboard"
  description                       = "Private access to the Cloud Detective dashboard bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_response_headers_policy" "security" {
  count = var.deploy_frontend ? 1 : 0

  name = "${var.name_prefix}-security-headers"

  security_headers_config {
    content_type_options { override = true }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

resource "aws_cloudfront_function" "spa_rewrite" {
  count = var.deploy_frontend ? 1 : 0

  name    = "${var.name_prefix}-spa-rewrite"
  runtime = "cloudfront-js-2.0"
  comment = "Route dashboard paths to the React application shell"
  publish = true
  code    = <<-EOT
    function handler(event) {
      var request = event.request;
      var leaf = request.uri.split('/').pop();
      if (request.uri.endsWith('/')) {
        request.uri += 'index.html';
      } else if (!leaf.includes('.')) {
        request.uri = '/index.html';
      }
      return request;
    }
  EOT
}

resource "aws_cloudfront_distribution" "this" {
  count = var.deploy_frontend ? 1 : 0

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  comment             = "Cloud Detective dashboard"

  origin {
    domain_name              = var.bucket_domain
    origin_id                = "dashboard-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.this[0].id
  }

  dynamic "origin" {
    for_each = var.deploy_runtime ? [1] : []
    content {
      domain_name = var.api_origin_domain
      origin_id   = "api-alb"

      custom_header {
        name  = "X-CloudDetective-Origin"
        value = var.origin_verify_secret
      }

      custom_origin_config {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "http-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  default_cache_behavior {
    target_origin_id           = "dashboard-s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite[0].arn
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = var.deploy_runtime ? [1] : []
    content {
      path_pattern               = "/api/*"
      target_origin_id           = "api-alb"
      viewer_protocol_policy     = "https-only"
      allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods             = ["GET", "HEAD", "OPTIONS"]
      compress                   = true
      cache_policy_id            = "413f160b-2af4-4fc4-9a5e-e03549dfe081"
      origin_request_policy_id   = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
      response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate { cloudfront_default_certificate = true }
}

data "aws_iam_policy_document" "bucket" {
  count = var.deploy_frontend ? 1 : 0

  statement {
    sid       = "AllowCloudFrontRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.bucket_arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this[0].arn]
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
