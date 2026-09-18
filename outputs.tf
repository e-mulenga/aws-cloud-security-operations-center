# ============================================================
# AWS Cloud Security Operations Centre — Outputs
# ============================================================
# Outputs consumed by downstream portfolio repository:
#   - multi-cloud-governance (security posture, finding exports)
# ============================================================

output "soc_bucket_name" {
  description = "S3 bucket storing SOC data, IR artefacts, and SIEM events."
  value       = aws_s3_bucket.soc_data.bucket
}

output "soc_bucket_arn" {
  description = "ARN of the SOC data S3 bucket."
  value       = aws_s3_bucket.soc_data.arn
}

output "critical_alerts_topic_arn" {
  description = "SNS topic ARN for P1/Critical security alerts — consumed by multi-cloud-governance."
  value       = module.notifications.critical_alerts_topic_arn
}

output "high_alerts_topic_arn" {
  description = "SNS topic ARN for HIGH severity security alerts."
  value       = module.notifications.high_alerts_topic_arn
}

output "alert_queue_arn" {
  description = "SQS queue ARN for pipeline alert ingestion."
  value       = module.notifications.alert_queue_arn
}

output "alert_queue_url" {
  description = "SQS queue URL for pipeline alert ingestion."
  value       = module.notifications.alert_queue_url
}

output "detective_graph_arn" {
  description = "Amazon Detective graph ARN for investigation links."
  value       = var.detective_enabled ? module.detective[0].graph_arn : null
}

output "access_analyzer_arn" {
  description = "IAM Access Analyzer ARN."
  value       = module.access_analyzer.analyzer_arn
}

output "incident_response_state_machine_arn" {
  description = "Step Functions state machine ARN for incident response."
  value       = var.incident_response_enabled ? module.incident_response[0].state_machine_arn : null
}

output "athena_workgroup_name" {
  description = "Athena workgroup for CloudTrail log analysis queries."
  value       = module.cloudtrail_analytics.athena_workgroup_name
}

output "glue_database_name" {
  description = "AWS Glue database name for CloudTrail log catalogue."
  value       = module.cloudtrail_analytics.glue_database_name
}

output "soc_dashboard_name" {
  description = "CloudWatch SOC dashboard name."
  value       = module.soc_dashboard.dashboard_name
}

output "security_posture_export_bucket" {
  description = "S3 path for security posture exports consumed by multi-cloud-governance."
  value       = "${aws_s3_bucket.soc_data.bucket}/posture-exports/"
}

output "finding_enricher_lambda_arn" {
  description = "Lambda ARN for Security Hub finding enrichment."
  value       = module.guardduty_automation.finding_enricher_lambda_arn
}
