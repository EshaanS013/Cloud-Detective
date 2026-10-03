provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudDetective"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

module "network" {
  source      = "./modules/network"
  name_prefix = local.name_prefix
}

module "data" {
  source              = "./modules/data"
  name_prefix         = local.name_prefix
  database_subnet_ids = module.network.database_subnet_ids
  database_sg_id      = module.network.database_sg_id
  deploy_database     = var.deploy_database
}

module "security" {
  source        = "./modules/security"
  name_prefix   = local.name_prefix
  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls
}

module "pipeline" {
  source              = "./modules/pipeline"
  name_prefix         = local.name_prefix
  kms_key_arn         = module.data.kms_key_arn
  trail_bucket_id     = module.data.trail_bucket_id
  evidence_bucket_id  = module.data.evidence_bucket_id
  evidence_bucket_arn = module.data.evidence_bucket_arn
  response_mode       = var.response_mode
}

module "compute" {
  source                = "./modules/compute"
  name_prefix           = local.name_prefix
  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnet_ids
  alb_sg_id             = module.network.alb_sg_id
  app_sg_id             = module.network.app_sg_id
  kms_key_arn           = module.data.kms_key_arn
  database_secret_arn   = module.data.database_secret_arn
  event_queue_url       = module.pipeline.event_queue_url
  event_queue_arn       = module.pipeline.event_queue_arn
  response_queue_url    = module.pipeline.response_queue_url
  response_queue_arn    = module.pipeline.response_queue_arn
  cognito_user_pool_id  = module.security.user_pool_id
  cognito_app_client_id = module.security.app_client_id
  deploy_runtime        = var.deploy_runtime
  api_image             = var.api_image
  worker_image          = var.worker_image
  response_mode         = var.response_mode
  aws_region            = var.aws_region
}

module "frontend" {
  source               = "./modules/frontend"
  name_prefix          = local.name_prefix
  bucket_id            = module.data.frontend_bucket_id
  bucket_arn           = module.data.frontend_bucket_arn
  bucket_domain        = module.data.frontend_bucket_domain
  deploy_frontend      = var.deploy_frontend
  deploy_runtime       = var.deploy_runtime
  api_origin_domain    = module.compute.api_origin_domain
  origin_verify_secret = module.compute.origin_verify_secret
}

module "build" {
  source                = "./modules/build"
  name_prefix           = local.name_prefix
  aws_region            = var.aws_region
  source_bucket_id      = module.data.frontend_bucket_id
  source_bucket_arn     = module.data.frontend_bucket_arn
  kms_key_arn           = module.data.kms_key_arn
  api_repository_arn    = module.compute.api_repository_arn
  api_repository_url    = module.compute.api_repository_url
  worker_repository_arn = module.compute.worker_repository_arn
  worker_repository_url = module.compute.worker_repository_url
}

module "monitoring" {
  source                  = "./modules/monitoring"
  name_prefix             = local.name_prefix
  aws_region              = var.aws_region
  collector_function_name = module.pipeline.collector_function_name
  responder_function_name = module.pipeline.responder_function_name
  event_dlq_name          = module.pipeline.event_dlq_name
  response_dlq_name       = module.pipeline.response_dlq_name
  alert_topic_arn         = module.pipeline.alert_topic_arn
  api_log_group_name      = module.compute.api_log_group_name
  worker_log_group_name   = module.compute.worker_log_group_name
}

resource "aws_budgets_budget" "monthly" {
  name         = "${local.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.budget_alert_email == "" ? [] : [var.budget_alert_email]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type             = "PERCENTAGE"
      notification_type          = "FORECASTED"
      subscriber_email_addresses = [notification.value]
    }
  }
}
