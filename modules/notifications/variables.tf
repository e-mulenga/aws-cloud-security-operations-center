variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "soc_alert_email" {
  type    = string
  default = ""
}

variable "soc_critical_email" {
  type    = string
  default = ""
}

variable "slack_webhook_secret_arn" {
  type      = string
  default   = ""
  sensitive = true
}

variable "chatbot_slack_workspace_id" {
  type    = string
  default = ""
}

variable "chatbot_slack_channel_id" {
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

variable "partition" {
  type    = string
  default = "aws"
}
