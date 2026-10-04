variable "name_prefix" { type = string }
variable "bucket_id" { type = string }
variable "bucket_arn" { type = string }
variable "bucket_domain" { type = string }
variable "kms_key_arn" { type = string }
variable "aws_region" { type = string }
variable "deploy_frontend" { type = bool }
variable "deploy_runtime" { type = bool }
variable "api_origin_domain" {
  type     = string
  nullable = true
}
variable "origin_verify_secret" {
  type      = string
  nullable  = true
  sensitive = true
}
