provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudDetective"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Infrastructure modules are added on Day 3. This root intentionally contains
# only validated provider configuration during the Day 1 foundation.
