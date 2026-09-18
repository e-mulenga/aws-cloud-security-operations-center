variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "guardduty_detector_id" {
  type    = string
  default = ""
}

variable "high_severity_threshold" {
  type    = number
  default = 7.0
}

variable "auto_remediate" {
  type    = bool
  default = true
}

variable "auto_isolate_ec2_enabled" {
  type    = bool
  default = false
}

variable "auto_disable_iam_enabled" {
  type    = bool
  default = false
}

variable "auto_remediate_s3_enabled" {
  type    = bool
  default = true
}

variable "critical_alerts_topic_arn" {
  type = string
}

variable "high_alerts_topic_arn" {
  type = string
}

variable "incident_response_enabled" {
  type    = bool
  default = true
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

variable "soc_bucket_name" {
  type = string
}
