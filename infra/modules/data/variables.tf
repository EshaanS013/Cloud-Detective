variable "name_prefix" { type = string }
variable "database_subnet_ids" { type = list(string) }
variable "database_sg_id" { type = string }
variable "deploy_database" { type = bool }
variable "deletion_protection" {
  type    = bool
  default = false
}
