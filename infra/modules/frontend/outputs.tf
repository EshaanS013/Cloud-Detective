output "dashboard_url" {
  value = var.deploy_frontend ? "https://${aws_cloudfront_distribution.this[0].domain_name}" : null
}
