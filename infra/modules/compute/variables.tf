variable "name_prefix" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "alb_sg_id" { type = string }
variable "app_sg_id" { type = string }
variable "kms_key_arn" { type = string }
variable "database_secret_arn" {
  type     = string
  nullable = true
}
variable "database_address" {
  type     = string
  nullable = true
}
variable "database_port" {
  type     = number
  nullable = true
}
variable "database_name" {
  type     = string
  nullable = true
}
variable "event_queue_url" { type = string }
variable "event_queue_arn" { type = string }
variable "response_queue_url" { type = string }
variable "response_queue_arn" { type = string }
variable "cognito_user_pool_id" { type = string }
variable "cognito_app_client_id" { type = string }
variable "deploy_runtime" { type = bool }
variable "api_image" { type = string }
variable "worker_image" { type = string }
variable "response_mode" { type = string }
variable "aws_region" { type = string }
