variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "critical_alerts_topic_arn" {
  type = string
}

variable "soc_bucket_name" {
  type = string
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

variable "partition" {
  type    = string
  default = "aws"
}
