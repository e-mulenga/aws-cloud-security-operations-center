output "lambda_role_arn" {
  value = aws_iam_role.lambda_remediation.arn
}

output "finding_enricher_lambda_arn" {
  value = aws_lambda_function.finding_enricher.arn
}

output "finding_enricher_lambda_name" {
  value = aws_lambda_function.finding_enricher.function_name
}

output "auto_remediate_s3_lambda_arn" {
  value = var.auto_remediate_s3_enabled ? aws_lambda_function.auto_remediate_s3[0].arn : null
}
