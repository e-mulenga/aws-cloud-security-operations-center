# ============================================================
# Module: guardduty-automation
# ============================================================
# WAF Pillars: Security, Operational Excellence, Reliability
#
# Builds automated response on top of the Landing Zone GuardDuty:
#   - EventBridge rules: finding severity → Lambda router
#   - Finding Enricher Lambda: add asset context + owner tags
#   - Auto-Remediate S3: block public access on bucket findings
#   - Auto-Isolate EC2: deny-all SG on instance compromise
#   - Auto-Disable IAM: deny-all policy on credential findings
#   - Forensic Snapshot: EBS snapshot before isolation
#   - All remediation actions logged to SOC S3 bucket
# ============================================================

data "archive_file" "finding_enricher" {
  type        = "zip"
  output_path = "/tmp/finding_enricher.zip"
  source_file = "${path.module}/../../lambda/finding-enricher/handler.py"
}

data "archive_file" "auto_remediate_s3" {
  type        = "zip"
  output_path = "/tmp/auto_remediate_s3.zip"
  source_file = "${path.module}/../../lambda/auto-remediate-public-s3/handler.py"
}

data "archive_file" "auto_isolate_ec2" {
  type        = "zip"
  output_path = "/tmp/auto_isolate_ec2.zip"
  source_file = "${path.module}/../../lambda/auto-isolate-ec2/handler.py"
}

data "archive_file" "auto_disable_iam" {
  type        = "zip"
  output_path = "/tmp/auto_disable_iam.zip"
  source_file = "${path.module}/../../lambda/auto-disable-iam-user/handler.py"
}

locals {
  name_prefix = "${var.organization_name}-${var.environment}"
}

# ---- Lambda Execution Role ---------------------------------
resource "aws_iam_role" "lambda_remediation" {
  name = "${local.name_prefix}-gd-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_remediation" {
  name = "guardduty-remediation-policy"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:${var.partition}:logs:*:${var.account_id}:log-group:/aws/lambda/*"
      },
      {
        Sid      = "S3PublicAccessRemediation"
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicy", "s3:PutBucketPolicy"]
        Resource = "arn:${var.partition}:s3:::*"
      },
      {
        Sid    = "EC2IsolationRemediation"
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup", "ec2:DescribeSecurityGroups",
          "ec2:ModifyInstanceAttribute", "ec2:DescribeInstances",
          "ec2:CreateSnapshot", "ec2:DescribeVolumes",
          "ec2:CreateTags", "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRemediation"
        Effect = "Allow"
        Action = [
          "iam:AttachUserPolicy", "iam:PutUserPolicy",
          "iam:ListAccessKeys", "iam:UpdateAccessKey",
          "iam:GetUser", "iam:TagUser"
        ]
        Resource = "arn:${var.partition}:iam::${var.account_id}:user/*"
      },
      {
        Sid      = "SecurityHubUpdate"
        Effect   = "Allow"
        Action   = ["securityhub:BatchUpdateFindings", "securityhub:BatchImportFindings"]
        Resource = "arn:${var.partition}:securityhub:${var.region}:${var.account_id}:hub/default"
      },
      {
        Sid      = "GuardDutyRead"
        Effect   = "Allow"
        Action   = ["guardduty:GetFinding", "guardduty:ListFindings", "guardduty:ArchiveFindings"]
        Resource = "*"
      },
      {
        Sid      = "SOCBucketWrite"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "arn:${var.partition}:s3:::${var.soc_bucket_name}/remediation-logs/*"
      },
      {
        Sid      = "KMSAccess"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [var.critical_alerts_topic_arn, var.high_alerts_topic_arn]
      },
      {
        Sid      = "ResourceGroupsTagging"
        Effect   = "Allow"
        Action   = ["tag:GetResources", "tag:GetTagValues", "tag:GetTagKeys"]
        Resource = "*"
      }
    ]
  })
}

# ---- CloudWatch Log Groups ---------------------------------
resource "aws_cloudwatch_log_group" "lambdas" {
  for_each = toset(["finding-enricher", "auto-remediate-s3", "auto-isolate-ec2", "auto-disable-iam"])

  name              = "/aws/lambda/${local.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# ---- Finding Enricher Lambda --------------------------------
resource "aws_lambda_function" "finding_enricher" {
  function_name    = "${local.name_prefix}-finding-enricher"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 60
  memory_size      = 256
  kms_key_arn      = var.kms_key_arn
  filename         = data.archive_file.finding_enricher.output_path
  source_code_hash = data.archive_file.finding_enricher.output_base64sha256

  environment {
    variables = {
      SOC_BUCKET   = var.soc_bucket_name
      ENVIRONMENT  = var.environment
      ALERTS_TOPIC = var.high_alerts_topic_arn
    }
  }

  tracing_config { mode = "Active" }

  depends_on = [aws_cloudwatch_log_group.lambdas]
}

# ---- Auto-Remediate Public S3 Lambda -----------------------
resource "aws_lambda_function" "auto_remediate_s3" {
  count            = var.auto_remediate_s3_enabled ? 1 : 0
  function_name    = "${local.name_prefix}-auto-remediate-s3"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 30
  kms_key_arn      = var.kms_key_arn
  filename         = data.archive_file.auto_remediate_s3.output_path
  source_code_hash = data.archive_file.auto_remediate_s3.output_base64sha256

  environment {
    variables = {
      SOC_BUCKET   = var.soc_bucket_name
      ALERTS_TOPIC = var.critical_alerts_topic_arn
      ENVIRONMENT  = var.environment
    }
  }

  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.lambdas]
}

# ---- Auto-Isolate EC2 Lambda --------------------------------
resource "aws_lambda_function" "auto_isolate_ec2" {
  count            = var.auto_isolate_ec2_enabled ? 1 : 0
  function_name    = "${local.name_prefix}-auto-isolate-ec2"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 60
  kms_key_arn      = var.kms_key_arn
  filename         = data.archive_file.auto_isolate_ec2.output_path
  source_code_hash = data.archive_file.auto_isolate_ec2.output_base64sha256

  environment {
    variables = {
      SOC_BUCKET   = var.soc_bucket_name
      ALERTS_TOPIC = var.critical_alerts_topic_arn
      ENVIRONMENT  = var.environment
    }
  }

  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.lambdas]
}

# ---- Auto-Disable IAM User Lambda --------------------------
resource "aws_lambda_function" "auto_disable_iam" {
  count            = var.auto_disable_iam_enabled ? 1 : 0
  function_name    = "${local.name_prefix}-auto-disable-iam"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  architectures    = ["arm64"]
  timeout          = 30
  kms_key_arn      = var.kms_key_arn
  filename         = data.archive_file.auto_disable_iam.output_path
  source_code_hash = data.archive_file.auto_disable_iam.output_base64sha256

  environment {
    variables = {
      SOC_BUCKET   = var.soc_bucket_name
      ALERTS_TOPIC = var.critical_alerts_topic_arn
      ENVIRONMENT  = var.environment
    }
  }

  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.lambdas]
}

# ---- EventBridge: GuardDuty findings → Enricher ____________
resource "aws_cloudwatch_event_rule" "guardduty_all" {
  name        = "${local.name_prefix}-gd-all-findings"
  description = "All GuardDuty findings → finding enricher Lambda."
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_enricher" {
  rule      = aws_cloudwatch_event_rule.guardduty_all.name
  target_id = "EnrichFinding"
  arn       = aws_lambda_function.finding_enricher.arn
}

resource "aws_lambda_permission" "eventbridge_enricher" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.finding_enricher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_all.arn
}

# ---- EventBridge: S3 findings → auto-remediate -------------
resource "aws_cloudwatch_event_rule" "guardduty_s3_public" {
  count       = var.auto_remediate_s3_enabled ? 1 : 0
  name        = "${local.name_prefix}-gd-s3-public"
  description = "GuardDuty S3 public findings → auto-remediate Lambda."
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Policy:S3/BucketPublicAccess" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_s3_remediate" {
  count     = var.auto_remediate_s3_enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_s3_public[0].name
  target_id = "RemediateS3"
  arn       = aws_lambda_function.auto_remediate_s3[0].arn
}

resource "aws_lambda_permission" "eventbridge_s3_remediate" {
  count         = var.auto_remediate_s3_enabled ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_remediate_s3[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_s3_public[0].arn
}

# ---- SNS Alert for HIGH/CRITICAL GuardDuty findings --------
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "${local.name_prefix}-gd-high-severity"
  description = "GuardDuty findings severity >= ${var.high_severity_threshold} → SNS alert."
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.high_severity_threshold] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_high_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "HighSeveritySNS"
  arn       = var.critical_alerts_topic_arn

  input_transformer {
    input_paths = {
      type      = "$.detail.type"
      severity  = "$.detail.severity"
      accountId = "$.detail.accountId"
      region    = "$.detail.region"
      time      = "$.time"
    }
    input_template = "\"🛡️ GuardDuty HIGH Finding: <type> | Severity: <severity> | Account: <accountId> | Region: <region> | Time: <time>\""
  }
}
