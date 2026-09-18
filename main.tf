# ============================================================
# AWS Cloud Security Operations Centre — Root Orchestration
# ============================================================
# Consumes telemetry from:
#   - aws-enterprise-landing-zone  (GuardDuty, Security Hub, CloudTrail)
#   - aws-devsecops-pipeline       (ECR findings, pipeline alerts)
#
# Produces:
#   - Unified security dashboard
#   - Automated threat response
#   - Incident response workflows
#   - Security posture exports → multi-cloud-governance
# ============================================================

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "${var.organization_name}-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  region      = data.aws_region.current.name
}

# ---- 1. Notifications (built first — SNS topics used by all modules) ----
module "notifications" {
  source = "./modules/notifications"

  organization_name          = var.organization_name
  environment                = var.environment
  kms_key_arn                = var.kms_key_arn
  soc_alert_email            = var.soc_alert_email
  soc_critical_email         = var.soc_critical_email
  slack_webhook_secret_arn   = var.slack_webhook_secret_arn
  chatbot_slack_workspace_id = var.chatbot_slack_workspace_id
  chatbot_slack_channel_id   = var.chatbot_slack_channel_id
  log_retention_days         = var.log_retention_days
  account_id                 = local.account_id
  region                     = local.region
  partition                  = local.partition
}

# ---- 2. Security Hub Aggregator ----------------------------
module "security_hub_aggregator" {

  providers = {
    aws = aws.securityhub
  }
  source = "./modules/security-hub-aggregator"

  organization_name         = var.organization_name
  environment               = var.environment
  aggregation_region        = var.securityhub_aggregation_region
  auto_enable_controls      = var.securityhub_auto_enable_controls
  member_account_ids        = var.member_account_ids
  kms_key_arn               = var.kms_key_arn
  soc_bucket_name           = var.soc_bucket_name
  critical_alerts_topic_arn = module.notifications.critical_alerts_topic_arn
  high_alerts_topic_arn     = module.notifications.high_alerts_topic_arn
  finding_archive_days      = var.finding_archive_days
  account_id                = local.account_id
  region                    = local.region
  partition                 = local.partition
  log_retention_days        = var.log_retention_days
}

# ---- 3. GuardDuty Automation -------------------------------
module "guardduty_automation" {
  source = "./modules/guardduty-automation"

  organization_name         = var.organization_name
  environment               = var.environment
  kms_key_arn               = var.kms_key_arn
  guardduty_detector_id     = var.guardduty_detector_id
  high_severity_threshold   = var.guardduty_high_severity_threshold
  auto_remediate            = var.guardduty_auto_remediate
  auto_isolate_ec2_enabled  = var.auto_isolate_ec2_enabled
  auto_disable_iam_enabled  = var.auto_disable_iam_enabled
  auto_remediate_s3_enabled = var.auto_remediate_s3_enabled
  critical_alerts_topic_arn = module.notifications.critical_alerts_topic_arn
  high_alerts_topic_arn     = module.notifications.high_alerts_topic_arn
  incident_response_enabled = var.incident_response_enabled
  log_retention_days        = var.log_retention_days
  account_id                = local.account_id
  region                    = local.region
  partition                 = local.partition
  soc_bucket_name           = var.soc_bucket_name

  depends_on = [module.notifications]
}

# ---- 4. CloudTrail Analytics (Athena + Glue) ---------------
module "cloudtrail_analytics" {
  source = "./modules/cloudtrail-analytics"

  providers = { aws.logging = aws.logging }

  organization_name      = var.organization_name
  environment            = var.environment
  kms_key_arn            = var.kms_key_arn
  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  soc_bucket_name        = var.soc_bucket_name
  athena_workgroup_name  = coalesce(var.athena_workgroup_name, "${local.name_prefix}-soc-workgroup")
  athena_results_bucket  = coalesce(var.athena_results_bucket, "${local.name_prefix}-athena-results")
  log_retention_days     = var.log_retention_days
  account_id             = local.account_id
  region                 = local.region
}

# ---- 5. Amazon Detective -----------------------------------
module "detective" {
  source = "./modules/detective"
  count  = var.detective_enabled ? 1 : 0

  organization_name  = var.organization_name
  environment        = var.environment
  member_account_ids = var.member_account_ids
}

# ---- 6. Amazon Macie ---------------------------------------
module "macie" {
  source = "./modules/macie"
  count  = var.macie_enabled ? 1 : 0

  organization_name         = var.organization_name
  environment               = var.environment
  kms_key_arn               = var.kms_key_arn
  scan_frequency            = var.macie_scan_frequency
  bucket_arns               = var.macie_bucket_arns
  critical_alerts_topic_arn = module.notifications.critical_alerts_topic_arn
  log_retention_days        = var.log_retention_days
  account_id                = local.account_id
  region                    = local.region
}

# ---- 7. IAM Access Analyzer --------------------------------
module "access_analyzer" {
  source = "./modules/access-analyzer"

  organization_name     = var.organization_name
  environment           = var.environment
  analyzer_type         = var.access_analyzer_type
  high_alerts_topic_arn = module.notifications.high_alerts_topic_arn
  log_retention_days    = var.log_retention_days
  region                = local.region
  account_id            = local.account_id
}

# ---- 8. Incident Response (Step Functions) -----------------
module "incident_response" {
  source = "./modules/incident-response"
  count  = var.incident_response_enabled ? 1 : 0

  organization_name         = var.organization_name
  environment               = var.environment
  kms_key_arn               = var.kms_key_arn
  critical_alerts_topic_arn = module.notifications.critical_alerts_topic_arn
  soc_bucket_name           = var.soc_bucket_name
  log_retention_days        = var.log_retention_days
  account_id                = local.account_id
  region                    = local.region
  partition                 = local.partition

  depends_on = [module.notifications]
}

# ---- 9. SOC Dashboard (CloudWatch) -------------------------
module "soc_dashboard" {
  source = "./modules/soc-dashboard"

  organization_name                 = var.organization_name
  environment                       = var.environment
  region                            = local.region
  guardduty_detector_id             = var.guardduty_detector_id
  cloudtrail_log_group              = var.cloudtrail_log_group_name
  critical_alerts_topic_arn         = module.notifications.critical_alerts_topic_arn
  critical_finding_alarm_threshold  = var.critical_finding_alarm_threshold
  high_finding_alarm_threshold      = var.high_finding_alarm_threshold
  guardduty_finding_alarm_threshold = var.guardduty_finding_alarm_threshold
  log_retention_days                = var.log_retention_days

  depends_on = [module.security_hub_aggregator, module.guardduty_automation]
}

# ---- 10. SOC Data Store (S3) --------------------------------
resource "aws_s3_bucket" "soc_data" {
  bucket        = var.soc_bucket_name
  force_destroy = var.environment != "prod"
  tags          = { Name = var.soc_bucket_name, Purpose = "soc-data-store" }
}

resource "aws_s3_bucket_versioning" "soc_data" {
  bucket = aws_s3_bucket.soc_data.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "soc_data" {
  bucket = aws_s3_bucket.soc_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "soc_data" {
  bucket                  = aws_s3_bucket.soc_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "soc_data" {
  bucket = aws_s3_bucket.soc_data.id
  rule {
    id     = "soc-tiering"
    status = "Enabled"

    filter {}

    transition {
      days          = var.finding_archive_days
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    expiration { days = 2557 } # 7-year regulatory retention
  }
}

resource "aws_s3_bucket_policy" "soc_data" {
  bucket = aws_s3_bucket.soc_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.soc_data.arn, "${aws_s3_bucket.soc_data.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyDeleteObject"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = "${aws_s3_bucket.soc_data.arn}/*"
      }
    ]
  })
}

# ---- 11. Pipeline Alert Integration ------------------------
resource "aws_sns_topic_subscription" "pipeline_alerts" {
  count     = var.pipeline_alerts_topic_arn != "" ? 1 : 0
  topic_arn = var.pipeline_alerts_topic_arn
  protocol  = "sqs"
  endpoint  = module.notifications.alert_queue_arn
}
