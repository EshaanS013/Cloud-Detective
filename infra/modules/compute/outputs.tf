output "api_repository_url" { value = aws_ecr_repository.api.repository_url }
output "worker_repository_url" { value = aws_ecr_repository.worker.repository_url }
output "api_repository_arn" { value = aws_ecr_repository.api.arn }
output "worker_repository_arn" { value = aws_ecr_repository.worker.arn }
output "api_origin_domain" { value = var.deploy_runtime ? aws_lb.api[0].dns_name : null }
output "origin_verify_secret" {
  value     = var.deploy_runtime ? random_password.origin_verify[0].result : null
  sensitive = true
}
output "ecs_cluster_name" { value = aws_ecs_cluster.this.name }
output "api_log_group_name" { value = aws_cloudwatch_log_group.api.name }
output "worker_log_group_name" { value = aws_cloudwatch_log_group.worker.name }
