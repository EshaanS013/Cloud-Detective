output "user_pool_id" { value = aws_cognito_user_pool.this.id }
output "app_client_id" { value = aws_cognito_user_pool_client.spa.id }
output "cognito_domain" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${data.aws_region.current.region}.amazoncognito.com"
}

data "aws_region" "current" {}
