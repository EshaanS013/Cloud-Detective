variable "aws_region" {
  description = "Selected AWS Region for Cloud Detective."
  type        = string
  default     = "ap-southeast-2"

  validation {
    condition     = var.aws_region == "ap-southeast-2"
    error_message = "This AWS project only permits Regional resources in ap-southeast-2."
  }
}

variable "project_name" {
  description = "Lowercase name used in resource names."
  type        = string
  default     = "cloud-detective"
}

variable "owner" {
  description = "Owner tag applied to supported resources."
  type        = string
  default     = "cloud-detective-team"
}

variable "deploy_database" {
  description = "Create the billable RDS database."
  type        = bool
  default     = false
}

variable "deploy_runtime" {
  description = "Create the billable ALB and ECS services after images are published."
  type        = bool
  default     = false
}

variable "deploy_frontend" {
  description = "Create the CloudFront distribution."
  type        = bool
  default     = false
}

variable "deploy_builder" {
  description = "Create the temporary no-ingress EC2 container image builder."
  type        = bool
  default     = false
}

variable "builder_image_tag" {
  description = "Immutable image tag published by the temporary builder."
  type        = string
  default     = ""
}

variable "api_image" {
  description = "Immutable API image URI (repository URL plus digest or version tag)."
  type        = string
  default     = ""
}

variable "worker_image" {
  description = "Immutable worker image URI (repository URL plus digest or version tag)."
  type        = string
  default     = ""
}

variable "callback_urls" {
  description = "Exact Cognito OAuth callback URLs."
  type        = list(string)
  default     = ["http://localhost:5173/callback"]
}

variable "logout_urls" {
  description = "Exact Cognito sign-out URLs."
  type        = list(string)
  default     = ["http://localhost:5173/"]
}

variable "response_mode" {
  description = "Response playbook mode. Live mode must be enabled deliberately."
  type        = string
  default     = "dry_run"

  validation {
    condition     = contains(["dry_run", "enforce"], var.response_mode)
    error_message = "response_mode must be dry_run or enforce."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly AWS cost budget in USD."
  type        = number
  default     = 15
}

variable "budget_alert_email" {
  description = "Optional email address for AWS Budget notifications."
  type        = string
  default     = ""
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "demo"], var.environment)
    error_message = "Environment must be dev or demo."
  }
}
