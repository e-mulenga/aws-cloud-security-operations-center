variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "region" {
  type = string
}

variable "guardduty_detector_id" {
  type    = string
  default = ""
}

variable "cloudtrail_log_group" {
  type    = string
  default = ""
}

variable "critical_alerts_topic_arn" {
  type = string
}

variable "critical_finding_alarm_threshold" {
  type    = number
  default = 1
}

variable "high_finding_alarm_threshold" {
  type    = number
  default = 5
}

variable "guardduty_finding_alarm_threshold" {
  type    = number
  default = 3
}

variable "log_retention_days" {
  type    = number
  default = 365
}
