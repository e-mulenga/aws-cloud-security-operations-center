# ============================================================
# Module: access-analyzer — IAM Access Analyzer
# ============================================================
# WAF Pillars: Security, Operational Excellence
#
# Creates an organisation-level or account-level IAM Access
# Analyzer that identifies resources shared with external
# principals — S3 buckets, IAM roles, KMS keys, SQS queues,
# Lambda functions, Secrets Manager secrets.

resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.organization_name}-${var.environment}-access-analyzer"
  type          = var.analyzer_type
  tags          = { Name = "${var.organization_name}-${var.environment}-access-analyzer" }
}

# EventBridge: External access findings → SNS
resource "aws_cloudwatch_event_rule" "external_access" {
  name        = "${var.organization_name}-${var.environment}-external-access"
  description = "IAM Access Analyzer findings for external access."
  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
    detail      = { status = ["ACTIVE"] }
  })
}

resource "aws_cloudwatch_event_target" "external_access_sns" {
  rule      = aws_cloudwatch_event_rule.external_access.name
  target_id = "ExternalAccessSNS"
  arn       = var.high_alerts_topic_arn
  input_transformer {
    input_paths = {
      resource     = "$.detail.resource"
      resourceType = "$.detail.resourceType"
      condition    = "$.detail.condition"
      isPublic     = "$.detail.isPublic"
    }
    input_template = "\"🔍 IAM Access Analyzer: External access detected on <resourceType> resource <resource> (public: <isPublic>). Review immediately.\""
  }
}

resource "aws_cloudwatch_log_group" "access_analyzer" {
  name              = "/aws/access-analyzer/${var.organization_name}-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = "alias/aws/logs"
}
