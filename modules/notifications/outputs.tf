output "critical_alerts_topic_arn" {
  value = aws_sns_topic.critical_alerts.arn
}

output "critical_alerts_topic_name" {
  value = aws_sns_topic.critical_alerts.name
}

output "high_alerts_topic_arn" {
  value = aws_sns_topic.high_alerts.arn
}

output "alert_queue_arn" {
  value = aws_sqs_queue.pipeline_alerts.arn
}

output "alert_queue_url" {
  value = aws_sqs_queue.pipeline_alerts.id
}
