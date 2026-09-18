# ============================================================
# Module: macie — Amazon Macie Sensitive Data Discovery
# ============================================================
# WAF Pillars: Security, Operational Excellence
#
# Provisions Macie with:
#   - Organisation-level delegation to Security account
#   - Scheduled classification jobs for specified S3 buckets
#   - EventBridge → SNS for sensitive data findings
#   - Custom data identifiers for organisation-specific PII

resource "aws_macie2_account" "main" {
  finding_publishing_frequency = "SIX_HOURS"
  status                       = "ENABLED"
}

resource "aws_macie2_classification_job" "scheduled" {
  count      = var.scan_frequency == "SCHEDULED" && length(var.bucket_arns) > 0 ? 1 : 0
  name       = "${var.organization_name}-${var.environment}-macie-scan"
  job_type   = "SCHEDULED"
  job_status = "RUNNING"

  schedule_frequency {
    weekly_schedule = "MONDAY"
  }

  s3_job_definition {
    dynamic "bucket_definitions" {
      for_each = var.bucket_arns
      content {
        account_id = var.account_id
        buckets    = [bucket_definitions.value]
      }
    }
  }

  tags = { Name = "${var.organization_name}-${var.environment}-macie-scan" }

  depends_on = [aws_macie2_account.main]
}

# Custom data identifier: South African ID numbers (POPIA compliance)
resource "aws_macie2_custom_data_identifier" "sa_id_number" {
  name                   = "${var.organization_name}-${var.environment}-sa-id-number"
  description            = "South African ID number pattern for POPIA compliance."
  regex                  = "\\b[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{4}[01][0-9]{2}\\b"
  keywords               = ["ID number", "South African ID", "SA ID"]
  maximum_match_distance = 100
  depends_on             = [aws_macie2_account.main]
}

# EventBridge: Macie findings → SNS
resource "aws_cloudwatch_event_rule" "macie_findings" {
  name        = "${var.organization_name}-${var.environment}-macie-findings"
  description = "Route Macie sensitive data findings to SOC alerts."
  event_pattern = jsonencode({
    source      = ["aws.macie"]
    detail-type = ["Macie Finding"]
    detail      = { severity = { score = [{ numeric = [">=", 75] }] } }
  })
}

resource "aws_cloudwatch_event_target" "macie_sns" {
  rule      = aws_cloudwatch_event_rule.macie_findings.name
  target_id = "MacieFindingsSNS"
  arn       = var.critical_alerts_topic_arn
}

resource "aws_cloudwatch_log_group" "macie" {
  name              = "/aws/macie/${var.organization_name}-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}
