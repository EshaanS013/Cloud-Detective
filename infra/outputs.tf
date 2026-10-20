output "deployment_region" {
  description = "Configured selected AWS Region."
  value       = var.aws_region
}

output "vpc_id" {
  value = module.network.vpc_id
}

output "api_repository_url" {
  value = module.compute.api_repository_url
}

output "worker_repository_url" {
  value = module.compute.worker_repository_url
}

output "database_secret_arn" {
  value     = module.data.database_secret_arn
  sensitive = true
}

output "cognito_user_pool_id" {
  value = module.security.user_pool_id
}

output "cognito_app_client_id" {
  value = module.security.app_client_id
}

output "cognito_domain" {
  value = module.security.cognito_domain
}

output "api_url" {
  value = var.deploy_runtime && var.deploy_frontend ? "${module.frontend.dashboard_url}/api/v1" : null
}

output "dashboard_url" {
  value = module.frontend.dashboard_url
}

output "event_queue_url" {
  value = module.pipeline.event_queue_url
}

output "alert_topic_arn" {
  value = module.pipeline.alert_topic_arn
}

output "operations_dashboard_name" {
  value = module.monitoring.dashboard_name
}

output "frontend_bucket_id" {
  value = module.data.frontend_bucket_id
}

output "container_builder_instance_id" {
  value = module.build.instance_id
}

output "container_build_source_key" {
  value = module.build.source_key
}

output "container_build_status_key" {
  value = module.build.status_key
}

output "container_build_log_key" {
  value = module.build.log_key
}
