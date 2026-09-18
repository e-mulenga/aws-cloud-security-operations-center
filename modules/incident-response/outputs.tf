output "state_machine_arn" { value = aws_sfn_state_machine.incident_response.arn }
output "state_machine_name" { value = aws_sfn_state_machine.incident_response.name }
output "incident_orchestrator_lambda_arn" { value = aws_lambda_function.incident_orchestrator.arn }
output "sfn_role_arn" { value = aws_iam_role.sfn.arn }
