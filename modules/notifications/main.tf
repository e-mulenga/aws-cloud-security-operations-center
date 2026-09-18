# ============================================================
# Module: notifications — SOC Alert Routing
# ============================================================
# Creates:
#   - SNS topic: critical-alerts (P1 — immediate response)
#   - SNS topic: high-alerts (P2 — 30-minute response)
#   - SQS queue: pipeline-alerts (ingests DevSecOps pipeline SNS)
#   - Lambda: Slack notifier (optional)
#   - AWS Chatbot: Slack channel integration (optional)

locals { name_prefix = "${var.organization_name}-${var.environment}" }

resource "aws_sns_topic" "critical_alerts" {
  name              = "${local.name_prefix}-soc-critical-alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = { Name = "${local.name_prefix}-soc-critical-alerts", Severity = "CRITICAL" }
}

resource "aws_sns_topic" "high_alerts" {
  name              = "${local.name_prefix}-soc-high-alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = { Name = "${local.name_prefix}-soc-high-alerts", Severity = "HIGH" }
}

resource "aws_sns_topic_subscription" "critical_email" {
  count     = var.soc_critical_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol  = "email"
  endpoint  = var.soc_critical_email
}

resource "aws_sns_topic_subscription" "high_email" {
  count     = var.soc_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.high_alerts.arn
  protocol  = "email"
  endpoint  = var.soc_alert_email
}

resource "aws_sns_topic_policy" "critical" {
  arn = aws_sns_topic.critical_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = ["events.amazonaws.com", "securityhub.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.critical_alerts.arn
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

resource "aws_sns_topic_policy" "high" {
  arn = aws_sns_topic.high_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = ["events.amazonaws.com", "securityhub.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.high_alerts.arn
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

# SQS queue for pipeline alert ingestion
resource "aws_sqs_queue" "pipeline_alerts" {
  name                       = "${local.name_prefix}-soc-pipeline-alerts"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 300
  kms_master_key_id          = var.kms_key_arn
  tags                       = { Name = "${local.name_prefix}-soc-pipeline-alerts" }
}

resource "aws_sqs_queue_policy" "pipeline_alerts" {
  queue_url = aws_sqs_queue.pipeline_alerts.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNSSubscription"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.pipeline_alerts.arn
    }]
  })
}

resource "aws_cloudwatch_log_group" "soc" {
  name              = "/aws/soc/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}
