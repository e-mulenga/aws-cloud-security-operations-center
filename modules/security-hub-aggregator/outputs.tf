output "findings_stream_arn" {
  value = aws_kinesis_firehose_delivery_stream.findings.arn
}

output "findings_stream_name" {
  value = aws_kinesis_firehose_delivery_stream.findings.name
}

output "firehose_role_arn" {
  value = aws_iam_role.firehose.arn
}

output "send_to_ir_action_arn" {
  value = aws_securityhub_action_target.send_to_ir.arn
}
