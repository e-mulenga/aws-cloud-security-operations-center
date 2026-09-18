# ============================================================
# AWS Cloud Security Operations Centre — Variables
# ============================================================
# All configurable values are variables.
# No account IDs, regions, emails, or secrets are hardcoded.
# ============================================================

# ---- Identity & Region -------------------------------------
variable "organization_name" {
  type        = string
  description = "Short organisation name used in all resource naming."
  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.organization_name))
    error_message = "Must be 3-30 lowercase alphanumeric chars or hyphens."
  }
}

variable "aws_region" {
  type        = string
  description = "Primary AWS region for SOC infrastructure."
  default     = "af-south-1"
}

variable "dr_region" {
  type        = string
  description = "Secondary (DR) region for cross-region replication."
  default     = "eu-west-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment: dev | test | prod."
  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "environment must be dev, test, or prod."
  }
}

# ---- Governance & Tagging ----------------------------------
variable "owner" {
  type        = string
  description = "Team responsible for the SOC."
}

variable "cost_center" {
  type        = string
  description = "Cost center code for billing allocation."
}

# ---- Account IDs (from Landing Zone outputs) ---------------
variable "management_account_id" {
  type        = string
  description = "AWS Management account ID (from landing zone output)."
}

variable "security_account_id" {
  type        = string
  description = "Security account ID — where this SOC runs (from landing zone)."
}

variable "logging_account_id" {
  type        = string
  description = "Logging account ID — CloudTrail and Config delivery bucket."
}

variable "organization_id" {
  type        = string
  description = "AWS Organisation ID (from landing zone output)."
}

# ---- Landing Zone Inputs -----------------------------------
variable "kms_key_arn" {
  type        = string
  description = "KMS CMK ARN from landing zone for encrypting SOC data stores."
  sensitive   = true
}

variable "cloudtrail_bucket_name" {
  type        = string
  description = "Centralised CloudTrail S3 bucket name (from landing zone)."
}

variable "cloudtrail_log_group_name" {
  type        = string
  description = "CloudTrail CloudWatch Log Group name (from landing zone)."
  default     = ""
}

variable "guardduty_detector_id" {
  type        = string
  description = "GuardDuty detector ID in the Security account (from landing zone)."
  default     = ""
}

# ---- DevSecOps Pipeline Inputs -----------------------------
variable "pipeline_alerts_topic_arn" {
  type        = string
  description = "SNS topic ARN for pipeline alerts (from aws-devsecops-pipeline output)."
  default     = ""
}

variable "ecr_repository_arns" {
  type        = list(string)
  description = "ECR repository ARNs to monitor for Inspector findings."
  default     = []
}

# ---- Security Hub ------------------------------------------
variable "securityhub_aggregation_region" {
  type        = string
  description = "Region where Security Hub findings are aggregated."
  default     = "af-south-1"
}

variable "securityhub_auto_enable_controls" {
  type        = bool
  description = "Auto-enable new Security Hub controls as they are released."
  default     = true
}

variable "member_account_ids" {
  type        = list(string)
  description = "List of member account IDs to register with Security Hub."
  default     = []
}

# ---- GuardDuty Automation ----------------------------------
variable "guardduty_auto_remediate" {
  type        = bool
  description = "Enable automated remediation for GuardDuty HIGH/CRITICAL findings."
  default     = true
}

variable "guardduty_high_severity_threshold" {
  type        = number
  description = "GuardDuty finding severity score threshold to trigger automation (1-10)."
  default     = 7.0
}

# ---- Amazon Detective --------------------------------------
variable "detective_enabled" {
  type        = bool
  description = "Enable Amazon Detective for investigation of security findings."
  default     = true
}

# ---- Amazon Macie ------------------------------------------
variable "macie_enabled" {
  type        = bool
  description = "Enable Amazon Macie for sensitive data discovery."
  default     = true
}

variable "macie_scan_frequency" {
  type        = string
  description = "Macie classification job frequency: ONE_TIME | SCHEDULED."
  default     = "SCHEDULED"
  validation {
    condition     = contains(["ONE_TIME", "SCHEDULED"], var.macie_scan_frequency)
    error_message = "Must be ONE_TIME or SCHEDULED."
  }
}

variable "macie_bucket_arns" {
  type        = list(string)
  description = "List of S3 bucket ARNs for Macie to scan for sensitive data."
  default     = []
}

# ---- IAM Access Analyzer -----------------------------------
variable "access_analyzer_type" {
  type        = string
  description = "IAM Access Analyzer type: ACCOUNT | ORGANIZATION."
  default     = "ORGANIZATION"
  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.access_analyzer_type)
    error_message = "Must be ACCOUNT or ORGANIZATION."
  }
}

# ---- Incident Response -------------------------------------
variable "incident_response_enabled" {
  type        = bool
  description = "Enable Step Functions automated incident response workflows."
  default     = true
}

variable "auto_isolate_ec2_enabled" {
  type        = bool
  description = "Enable automatic EC2 isolation on high-severity GuardDuty findings."
  default     = false # Requires explicit opt-in — disruptive action
}

variable "auto_disable_iam_enabled" {
  type        = bool
  description = "Enable automatic IAM user disablement on credential compromise findings."
  default     = false # Requires explicit opt-in — disruptive action
}

variable "auto_remediate_s3_enabled" {
  type        = bool
  description = "Enable automatic S3 public access block on public-bucket findings."
  default     = true
}

# ---- CloudTrail Analytics ----------------------------------
variable "athena_workgroup_name" {
  type        = string
  description = "Athena workgroup name for CloudTrail analysis queries."
  default     = ""
}

variable "athena_results_bucket" {
  type        = string
  description = "S3 bucket name for Athena query results."
  default     = ""
}

# ---- Notifications -----------------------------------------
variable "soc_alert_email" {
  type        = string
  description = "Email address for SOC alert notifications."
  default     = ""
}

variable "soc_critical_email" {
  type        = string
  description = "Email address for P1/Critical incident escalations."
  default     = ""
}

variable "slack_webhook_secret_arn" {
  type        = string
  description = "Secrets Manager ARN for Slack webhook URL (optional)."
  default     = ""
  sensitive   = true
}

variable "chatbot_slack_workspace_id" {
  type        = string
  description = "Slack workspace ID for AWS Chatbot integration (optional)."
  default     = ""
}

variable "chatbot_slack_channel_id" {
  type        = string
  description = "Slack channel ID for AWS Chatbot security alerts (optional)."
  default     = ""
}

# ---- Retention & Storage -----------------------------------
variable "log_retention_days" {
  type        = number
  description = "CloudWatch Logs retention period in days."
  default     = 365
}

variable "soc_bucket_name" {
  type        = string
  description = "S3 bucket name for SOC data: SIEM events, IR artefacts, Athena results."
}

variable "finding_archive_days" {
  type        = number
  description = "Days before Security Hub finding exports transition to S3 Glacier."
  default     = 90
}

# ---- Monitoring Thresholds ---------------------------------
variable "critical_finding_alarm_threshold" {
  type        = number
  description = "Number of CRITICAL Security Hub findings per hour to trigger alarm."
  default     = 1
}

variable "high_finding_alarm_threshold" {
  type        = number
  description = "Number of HIGH Security Hub findings per hour to trigger alarm."
  default     = 5
}

variable "guardduty_finding_alarm_threshold" {
  type        = number
  description = "Number of GuardDuty HIGH findings per hour to trigger alarm."
  default     = 3
}
