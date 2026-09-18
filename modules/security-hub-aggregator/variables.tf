variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "aggregation_region" {
  type    = string
  default = "af-south-1"
}

variable "auto_enable_controls" {
  type    = bool
  default = true
}

variable "member_account_ids" {
  type    = list(string)
  default = []
}

variable "kms_key_arn" {
  type = string
}

variable "soc_bucket_name" {
  type = string
}

variable "critical_alerts_topic_arn" {
  type = string
}

variable "high_alerts_topic_arn" {
  type = string
}

variable "finding_archive_days" {
  type    = number
  default = 90
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

variable "log_retention_days" {
  type    = number
  default = 365
}
