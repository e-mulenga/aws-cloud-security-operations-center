# ============================================================
# Module: incident-response
# ============================================================
# WAF Pillars: Security, Reliability, Operational Excellence
#
# Provisions a Step Functions state machine for automated
# incident response:
#   Step 1: Classify finding severity
#   Step 2: Create Systems Manager OpsCenter OpsItem
#   Step 3: Notify on-call responders via SNS
#   Step 4: Gather evidence (CloudTrail, VPC Flow Logs)
#   Step 5: Route to remediation Lambda or human approval
#   Step 6: Update Security Hub finding workflow status
#   Step 7: Log incident record to SOC S3 bucket
# ============================================================

data "archive_file" "incident_orchestrator" {
  type        = "zip"
  output_path = "/tmp/incident_orchestrator.zip"
  source_file = "${path.module}/../../lambda/incident-orchestrator/handler.py"
}

locals {
  name_prefix = "${var.organization_name}-${var.environment}"
}

# ---- Step Functions IAM Role --------------------------------
resource "aws_iam_role" "sfn" {
  name = "${local.name_prefix}-ir-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "sfn" {
  name = "ir-sfn-policy"
  role = aws_iam_role.sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeLambda"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = ["arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${local.name_prefix}-*"]
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [var.critical_alerts_topic_arn]
      },
      {
        Sid      = "SSMOpsCenter"
        Effect   = "Allow"
        Action   = ["ssm:CreateOpsItem", "ssm:UpdateOpsItem", "ssm:GetOpsItem"]
        Resource = "*"
      },
      {
        Sid      = "SecurityHubUpdate"
        Effect   = "Allow"
        Action   = ["securityhub:BatchUpdateFindings"]
        Resource = "*"
      },
      {
        Sid      = "S3WriteEvidence"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "arn:${var.partition}:s3:::${var.soc_bucket_name}/incidents/*"
      },
      {
        Sid      = "KMSAccess"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutLogEvents",
        "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"]
        Resource = "*"
      }
    ]
  })
}

# ---- Lambda Execution Role ---------------------------------
resource "aws_iam_role" "ir_lambda" {
  name = "${local.name_prefix}-ir-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ir_lambda" {
  name = "ir-lambda-policy"
  role = aws_iam_role.ir_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "arn:${var.partition}:s3:::${var.soc_bucket_name}/incidents/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["securityhub:BatchUpdateFindings", "securityhub:GetFindings"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:CreateOpsItem", "ssm:UpdateOpsItem"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [var.critical_alerts_topic_arn]
      }
    ]
  })
}

# ---- Incident Orchestrator Lambda --------------------------
resource "aws_cloudwatch_log_group" "ir_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-incident-orchestrator"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "incident_orchestrator" {
  function_name    = "${local.name_prefix}-incident-orchestrator"
  role             = aws_iam_role.ir_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 300
  memory_size      = 512
  kms_key_arn      = var.kms_key_arn
  filename         = data.archive_file.incident_orchestrator.output_path
  source_code_hash = data.archive_file.incident_orchestrator.output_base64sha256

  environment {
    variables = {
      SOC_BUCKET   = var.soc_bucket_name
      ALERTS_TOPIC = var.critical_alerts_topic_arn
      ENVIRONMENT  = var.environment
    }
  }

  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.ir_lambda]
}

# ---- CloudWatch Log Group for SFN --------------------------
resource "aws_cloudwatch_log_group" "sfn_logs" {
  name              = "/aws/states/${local.name_prefix}-incident-response"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# ---- Step Functions State Machine --------------------------
resource "aws_sfn_state_machine" "incident_response" {
  name     = "${local.name_prefix}-incident-response"
  role_arn = aws_iam_role.sfn.arn

  logging_configuration {
    level                  = "ALL"
    include_execution_data = true
    log_destination        = "${aws_cloudwatch_log_group.sfn_logs.arn}:*"
  }

  tracing_configuration { enabled = true }

  definition = jsonencode({
    Comment = "AWS Cloud SOC Incident Response Workflow v1.0"
    StartAt = "ClassifyFinding"
    States = {
      ClassifyFinding = {
        Type     = "Task"
        Resource = "arn:${var.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.incident_orchestrator.arn
          Payload = {
            "action"  = "classify"
            "input.$" = "$"
          }
        }
        ResultPath = "$.classification"
        Next       = "RouteBySeverity"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]
      }

      RouteBySeverity = {
        Type = "Choice"
        Choices = [
          {
            Variable     = "$.classification.Payload.severity"
            StringEquals = "CRITICAL"
            Next         = "HandleCritical"
          },
          {
            Variable     = "$.classification.Payload.severity"
            StringEquals = "HIGH"
            Next         = "HandleHigh"
          }
        ]
        Default = "HandleMediumLow"
      }

      HandleCritical = {
        Type = "Parallel"
        Branches = [
          {
            StartAt = "CreateOpsItem"
            States = {
              CreateOpsItem = {
                Type     = "Task"
                Resource = "arn:${var.partition}:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.incident_orchestrator.arn
                  Payload      = { "action" = "create_ops_item", "input.$" = "$" }
                }
                End = true
              }
            }
          },
          {
            StartAt = "NotifyCritical"
            States = {
              NotifyCritical = {
                Type     = "Task"
                Resource = "arn:${var.partition}:states:::sns:publish"
                Parameters = {
                  TopicArn = var.critical_alerts_topic_arn
                  Message  = "States.Format('P1 CRITICAL Incident: {} — Immediate response required. Execution: {}', $.classification.Payload.title, $$.Execution.Name)"
                  Subject  = "P1 CRITICAL Security Incident — Immediate Action Required"
                }
                End = true
              }
            }
          },
          {
            StartAt = "GatherEvidence"
            States = {
              GatherEvidence = {
                Type     = "Task"
                Resource = "arn:${var.partition}:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.incident_orchestrator.arn
                  Payload      = { "action" = "gather_evidence", "input.$" = "$" }
                }
                End = true
              }
            }
          }
        ]
        Next = "UpdateFindingWorkflow"
      }

      HandleHigh = {
        Type     = "Task"
        Resource = "arn:${var.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.incident_orchestrator.arn
          Payload      = { "action" = "handle_high", "input.$" = "$" }
        }
        Next = "UpdateFindingWorkflow"
      }

      HandleMediumLow = {
        Type     = "Task"
        Resource = "arn:${var.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.incident_orchestrator.arn
          Payload      = { "action" = "log_finding", "input.$" = "$" }
        }
        Next = "UpdateFindingWorkflow"
      }

      UpdateFindingWorkflow = {
        Type     = "Task"
        Resource = "arn:${var.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.incident_orchestrator.arn
          Payload      = { "action" = "update_finding_status", "input.$" = "$" }
        }
        Next = "IncidentComplete"
      }

      IncidentComplete = {
        Type = "Succeed"
      }
    }
  })

  tags = { Name = "${local.name_prefix}-incident-response" }
}

# ---- EventBridge: CRITICAL findings → SFN ------------------
resource "aws_cloudwatch_event_rule" "critical_to_sfn" {
  name        = "${local.name_prefix}-critical-to-ir-sfn"
  description = "Route CRITICAL Security Hub findings to IR Step Functions."
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

resource "aws_iam_role" "eventbridge_sfn" {
  name = "${local.name_prefix}-eb-sfn-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_sfn" {
  name = "sfn-start-execution"
  role = aws_iam_role.eventbridge_sfn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = [aws_sfn_state_machine.incident_response.arn]
    }]
  })
}

resource "aws_cloudwatch_event_target" "critical_to_sfn" {
  rule      = aws_cloudwatch_event_rule.critical_to_sfn.name
  target_id = "CriticalToSFN"
  arn       = aws_sfn_state_machine.incident_response.arn
  role_arn  = aws_iam_role.eventbridge_sfn.arn
}
