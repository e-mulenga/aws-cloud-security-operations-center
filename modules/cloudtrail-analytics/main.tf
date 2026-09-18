# ============================================================
# Module: cloudtrail-analytics
# ============================================================
# WAF Pillars: Security, Operational Excellence
#
# Provisions AWS Glue + Athena infrastructure for querying
# CloudTrail logs stored in the Landing Zone S3 bucket:
#   - Glue Crawler: auto-catalogues CloudTrail Parquet logs
#   - Glue Database: cloudtrail_logs
#   - Athena Workgroup: encrypted results, cost control
#   - Pre-built queries: unauthorized API, root usage, IAM changes
#   - Athena Named Queries: security investigation starting points
#   - Scheduled Glue Crawler: keeps catalogue fresh
# ============================================================

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.logging]
    }
  }
}

locals {
  name_prefix = "${var.organization_name}-${var.environment}"
}

# ---- Athena Results Bucket (in SOC account) ----------------
resource "aws_s3_bucket" "athena_results" {
  bucket        = var.athena_results_bucket != "" ? var.athena_results_bucket : "${local.name_prefix}-athena-results"
  force_destroy = var.environment != "prod"
  tags          = { Name = "${local.name_prefix}-athena-results", Purpose = "athena-query-results" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {}

    expiration { days = 30 }
  }
}

# ---- Athena Workgroup ---------------------------------------
resource "aws_athena_workgroup" "soc" {
  name        = var.athena_workgroup_name != "" ? var.athena_workgroup_name : "${local.name_prefix}-soc-workgroup"
  description = "SOC CloudTrail analysis workgroup — encrypted, cost-controlled."

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = 10737418240 # 10 GB max per query

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/query-results/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = var.kms_key_arn
      }
    }
  }

  tags = { Name = "${local.name_prefix}-soc-workgroup" }
}

# ---- Glue IAM Role -----------------------------------------
resource "aws_iam_role" "glue_crawler" {
  name = "${local.name_prefix}-glue-crawler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "glue_service" {
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_s3_access" {
  name = "glue-cloudtrail-s3-access"
  role = aws_iam_role.glue_crawler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.cloudtrail_bucket_name}",
          "arn:aws:s3:::${var.cloudtrail_bucket_name}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = [var.kms_key_arn]
      }
    ]
  })
}

# ---- Glue Database -----------------------------------------
resource "aws_glue_catalog_database" "cloudtrail" {
  name        = "${local.name_prefix}_cloudtrail_logs"
  description = "AWS CloudTrail logs catalogue for SOC analysis queries."
}

# ---- Glue Crawler ------------------------------------------
resource "aws_glue_crawler" "cloudtrail" {
  name          = "${local.name_prefix}-cloudtrail-crawler"
  role          = aws_iam_role.glue_crawler.arn
  database_name = aws_glue_catalog_database.cloudtrail.name
  description   = "Crawls CloudTrail logs in S3 and updates Glue catalogue."
  schedule      = "cron(0 2 * * ? *)" # 02:00 UTC daily

  s3_target {
    path = "s3://${var.cloudtrail_bucket_name}/AWSLogs/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = { AddOrUpdateBehavior = "InheritFromTable" }
    }
  })

  tags = { Name = "${local.name_prefix}-cloudtrail-crawler" }
}

# ---- Athena Named Queries (security investigation templates) -
resource "aws_athena_named_query" "unauthorized_api" {
  name        = "${local.name_prefix}-unauthorized-api-calls"
  description = "Find all unauthorized API calls in the last 24 hours."
  workgroup   = aws_athena_workgroup.soc.name
  database    = aws_glue_catalog_database.cloudtrail.name

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      eventsource,
      errorcode,
      errormessage,
      useridentity.arn      AS principal_arn,
      useridentity.type     AS principal_type,
      sourceipaddress,
      awsregion,
      recipientaccountid
    FROM "${aws_glue_catalog_database.cloudtrail.name}"."cloudtrail_logs_*"
    WHERE
      errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'AuthFailure')
      AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '24' hour
    ORDER BY eventtime DESC
    LIMIT 1000;
  SQL
}

resource "aws_athena_named_query" "root_account_usage" {
  name        = "${local.name_prefix}-root-account-usage"
  description = "Detect root account activity in the last 7 days."
  workgroup   = aws_athena_workgroup.soc.name
  database    = aws_glue_catalog_database.cloudtrail.name

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      eventsource,
      sourceipaddress,
      awsregion,
      recipientaccountid,
      useridentity.sessioncontext.sessionissuer.arn AS role_arn
    FROM "${aws_glue_catalog_database.cloudtrail.name}"."cloudtrail_logs_*"
    WHERE
      useridentity.type = 'Root'
      AND useridentity.invokedby IS NULL
      AND eventtype != 'AwsServiceEvent'
      AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
    ORDER BY eventtime DESC;
  SQL
}

resource "aws_athena_named_query" "iam_changes" {
  name        = "${local.name_prefix}-iam-changes"
  description = "Track all IAM policy and role changes in the last 24 hours."
  workgroup   = aws_athena_workgroup.soc.name
  database    = aws_glue_catalog_database.cloudtrail.name

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      useridentity.arn AS actor_arn,
      useridentity.type AS actor_type,
      json_extract_scalar(requestparameters, '$.roleName')   AS role_name,
      json_extract_scalar(requestparameters, '$.userName')   AS user_name,
      json_extract_scalar(requestparameters, '$.policyName') AS policy_name,
      json_extract_scalar(requestparameters, '$.policyArn')  AS policy_arn,
      sourceipaddress,
      awsregion,
      recipientaccountid
    FROM "${aws_glue_catalog_database.cloudtrail.name}"."cloudtrail_logs_*"
    WHERE
      eventsource = 'iam.amazonaws.com'
      AND eventname IN (
        'CreateRole','DeleteRole','AttachRolePolicy','DetachRolePolicy',
        'PutRolePolicy','DeleteRolePolicy','CreatePolicy','DeletePolicy',
        'CreatePolicyVersion','SetDefaultPolicyVersion',
        'AttachUserPolicy','DetachUserPolicy','PutUserPolicy','DeleteUserPolicy',
        'CreateUser','DeleteUser','CreateAccessKey','DeleteAccessKey'
      )
      AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '24' hour
    ORDER BY eventtime DESC;
  SQL
}

resource "aws_athena_named_query" "security_group_changes" {
  name        = "${local.name_prefix}-network-changes"
  description = "Detect security group and network ACL changes."
  workgroup   = aws_athena_workgroup.soc.name
  database    = aws_glue_catalog_database.cloudtrail.name

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      useridentity.arn AS actor_arn,
      json_extract_scalar(requestparameters, '$.groupId') AS security_group_id,
      json_extract_scalar(requestparameters, '$.vpcId')   AS vpc_id,
      sourceipaddress,
      awsregion,
      recipientaccountid
    FROM "${aws_glue_catalog_database.cloudtrail.name}"."cloudtrail_logs_*"
    WHERE
      eventsource = 'ec2.amazonaws.com'
      AND eventname IN (
        'AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress',
        'RevokeSecurityGroupIngress','RevokeSecurityGroupEgress',
        'CreateSecurityGroup','DeleteSecurityGroup',
        'CreateNetworkAcl','DeleteNetworkAcl',
        'CreateNetworkAclEntry','DeleteNetworkAclEntry'
      )
      AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '24' hour
    ORDER BY eventtime DESC;
  SQL
}

resource "aws_athena_named_query" "console_logins" {
  name        = "${local.name_prefix}-console-logins"
  description = "List all console logins with MFA status — last 7 days."
  workgroup   = aws_athena_workgroup.soc.name
  database    = aws_glue_catalog_database.cloudtrail.name

  query = <<-SQL
    SELECT
      eventtime,
      useridentity.username         AS username,
      useridentity.arn              AS principal_arn,
      sourceipaddress,
      awsregion,
      recipientaccountid,
      json_extract_scalar(additionaleventdata, '$.MFAUsed')           AS mfa_used,
      json_extract_scalar(additionaleventdata, '$.LoginTo')           AS login_url,
      json_extract_scalar(responseelements, '$.ConsoleLogin')         AS login_result
    FROM "${aws_glue_catalog_database.cloudtrail.name}"."cloudtrail_logs_*"
    WHERE
      eventname = 'ConsoleLogin'
      AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
    ORDER BY eventtime DESC;
  SQL
}
