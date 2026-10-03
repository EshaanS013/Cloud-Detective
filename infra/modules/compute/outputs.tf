output "api_repository_url" { value = aws_ecr_repository.api.repository_url }
output "worker_repository_url" { value = aws_ecr_repository.worker.repository_url }
output "api_url" { value = var.deploy_runtime ? "https://${aws_lb.api[0].dns_name}" : null }
output "ecs_cluster_name" { value = aws_ecs_cluster.this.name }
output "api_log_group_name" { value = aws_cloudwatch_log_group.api.name }
output "worker_log_group_name" { value = aws_cloudwatch_log_group.worker.name }
