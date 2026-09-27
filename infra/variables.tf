variable "aws_region" {
  description = "Primary AWS region for Cloud Detective."
  type        = string
  default     = "ap-south-1"
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
