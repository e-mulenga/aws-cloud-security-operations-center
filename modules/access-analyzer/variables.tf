variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "analyzer_type" {
  type    = string
  default = "ORGANIZATION"
}

variable "high_alerts_topic_arn" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "region" {
  type = string
}

variable "account_id" {
  type = string
}
