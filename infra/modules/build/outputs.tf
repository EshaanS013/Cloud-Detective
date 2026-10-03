output "instance_id" { value = try(aws_instance.build[0].id, null) }
output "source_key" { value = local.source_key }
output "status_key" { value = var.deploy_builder ? local.status_key : null }
output "log_key" { value = var.deploy_builder ? local.log_key : null }
