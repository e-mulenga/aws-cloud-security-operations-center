# ============================================================
# Module: security-hub-aggregator
# ============================================================
# WAF Pillars: Security, Operational Excellence
#
# Extends the Landing Zone Security Hub with:
#   - Finding aggregation across all regions
#   - Custom actions → EventBridge → Lambda (enrich, route, remediate)
#   - Automated suppression rules for known false positives
#   - Finding export to S3 for SIEM and audit trail
#   - CloudWatch metrics + alarms for CRITICAL/HIGH findings
# ============================================================

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "${var.organization_name}-${var.environment}"
}

# ---- Security Hub Finding Aggregator (cross-region) --------
resource "aws_securityhub_finding_aggregator" "main" {
  provider     = aws.securityhub # Securityhub service not Full GA in af-south-1
  linking_mode = "ALL_REGIONS"
}

# ---- Custom Actions → EventBridge --------------------------
resource "aws_securityhub_action_target" "send_to_ir" {
  name        = "SendToIR" # Shortened to fit the 20-character limit
  identifier  = "SendToIR"
  description = "Send finding to the Incident Response Step Functions workflow."
}

resource "aws_securityhub_action_target" "suppress_finding" {
  name        = "SuppressFinding"
  identifier  = "SuppressFinding"
  description = "Suppress a reviewed false-positive finding."
}

resource "aws_securityhub_action_target" "enrich_finding" {
  name        = "EnrichFinding"
  identifier  = "EnrichFinding"
  description = "Trigger finding enrichment Lambda (add asset context, owner info)."
}

# ---- EventBridge: CRITICAL findings → IR -------------------
resource "aws_cloudwatch_event_rule" "critical_findings" {
  name        = "${local.name_prefix}-sechub-critical"
  description = "Route Security Hub CRITICAL findings to IR workflow."

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["CRITICAL"] }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "critical_to_ir_sns" {
  rule      = aws_cloudwatch_event_rule.critical_findings.name
  target_id = "CriticalToIRSNS"
  arn       = var.critical_alerts_topic_arn
  input_transformer {
    input_paths = {
      title       = "$.detail.findings[0].Title"
      severity    = "$.detail.findings[0].Severity.Label"
      accountId   = "$.detail.findings[0].AwsAccountId"
      findingId   = "$.detail.findings[0].Id"
      remediation = "$.detail.findings[0].Remediation.Recommendation.Text"
    }
    input_template = "\"🚨 CRITICAL Finding: <title> | Account: <accountId> | Severity: <severity> | Remediation: <remediation> | Finding ID: <findingId>\""
  }
}

# ---- EventBridge: HIGH findings → alert --------------------
resource "aws_cloudwatch_event_rule" "high_findings" {
  name        = "${local.name_prefix}-sechub-high"
  description = "Route Security Hub HIGH findings to alerts topic."
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["HIGH"] }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "high_to_sns" {
  rule      = aws_cloudwatch_event_rule.high_findings.name
  target_id = "HighToSNS"
  arn       = var.high_alerts_topic_arn
}

# ---- Finding Export to S3 (via Kinesis Firehose) -----------
resource "aws_iam_role" "firehose" {
  name = "${local.name_prefix}-sechub-firehose-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "firehose" {
  name = "firehose-s3-delivery"
  role = aws_iam_role.firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"]
        Resource = ["arn:${var.partition}:s3:::${var.soc_bucket_name}", "arn:${var.partition}:s3:::${var.soc_bucket_name}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "findings" {
  name        = "${local.name_prefix}-sechub-findings-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = "arn:${var.partition}:s3:::${var.soc_bucket_name}"
    prefix              = "security-hub-findings/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "security-hub-findings-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/"
    buffering_size      = 64
    buffering_interval  = 300
    compression_format  = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/${local.name_prefix}-sechub-findings"
      log_stream_name = "S3Delivery"
    }

    dynamic_partitioning_configuration { enabled = true }
  }

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = var.kms_key_arn
  }

  tags = { Name = "${local.name_prefix}-sechub-findings-stream" }
}

# ---- EventBridge: All findings → Firehose ------------------
resource "aws_cloudwatch_event_rule" "all_findings_to_firehose" {
  name        = "${local.name_prefix}-sechub-all-to-firehose"
  description = "Export all Security Hub findings to Kinesis Firehose for S3 archival."
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_iam_role" "eventbridge_firehose" {
  name = "${local.name_prefix}-eb-firehose-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_firehose" {
  name = "firehose-put-records"
  role = aws_iam_role.eventbridge_firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
      Resource = [aws_kinesis_firehose_delivery_stream.findings.arn]
    }]
  })
}

resource "aws_cloudwatch_event_target" "all_findings_firehose" {
  rule      = aws_cloudwatch_event_rule.all_findings_to_firehose.name
  target_id = "FindingsToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.findings.arn
  role_arn  = aws_iam_role.eventbridge_firehose.arn
}

# ---- CloudWatch Log Group ----------------------------------
resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${local.name_prefix}-sechub-findings"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}
