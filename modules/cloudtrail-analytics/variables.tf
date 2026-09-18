variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "cloudtrail_bucket_name" {
  type = string
}

variable "soc_bucket_name" {
  type = string
}

variable "athena_workgroup_name" {
  type    = string
  default = ""
}

variable "athena_results_bucket" {
  type    = string
  default = ""
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}
