output "dashboard_url" {
  value = var.deploy_frontend ? trimsuffix(aws_lambda_function_url.gateway[0].function_url, "/") : null
}
