# ============================================================
# Module: soc-dashboard
# ============================================================
# WAF Pillars: Operational Excellence, Security
#
# Provisions the SOC CloudWatch dashboard and alarms:
#   - Security posture overview (CRITICAL/HIGH counts)
#   - GuardDuty finding trend (7-day rolling)
#   - Security Hub compliance score gauges
#   - Failed login attempts heatmap
#   - IAM change frequency
#   - CloudWatch alarms → SNS for threshold breaches
# ============================================================

locals {
  name_prefix = "${var.organization_name}-${var.environment}"
}

# ---- Security Event Metric Filters (on CloudTrail log group) -
locals {
  metric_filters = var.cloudtrail_log_group != "" ? {
    "unauthorized-api"    = { pattern = "{($.errorCode = \"AccessDenied\") || ($.errorCode = \"UnauthorizedAccess\")}", metric = "UnauthorizedAPICalls" }
    "root-login"          = { pattern = "{$.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS}", metric = "RootAccountUsage" }
    "console-no-mfa"      = { pattern = "{($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\")}", metric = "ConsoleLoginWithoutMFA" }
    "iam-policy-changes"  = { pattern = "{($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy)}", metric = "IAMPolicyChanges" }
    "sg-changes"          = { pattern = "{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress)}", metric = "SecurityGroupChanges" }
    "kms-deletion"        = { pattern = "{($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion))}", metric = "KMSKeyDeletion" }
    "network-acl-changes" = { pattern = "{($.eventName = CreateNetworkAcl) || ($.eventName = DeleteNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAclEntry)}", metric = "NetworkACLChanges" }
    "cloudtrail-changes"  = { pattern = "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StopLogging)}", metric = "CloudTrailChanges" }
    "s3-policy-changes"   = { pattern = "{($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = DeleteBucketPolicy))}", metric = "S3PolicyChanges" }
  } : {}
}

resource "aws_cloudwatch_log_metric_filter" "soc_metrics" {
  for_each       = local.metric_filters
  name           = "${local.name_prefix}-${each.key}"
  pattern        = each.value.pattern
  log_group_name = var.cloudtrail_log_group

  metric_transformation {
    name      = "${local.name_prefix}-${each.value.metric}"
    namespace = "SOC/SecurityEvents"
    value     = "1"
    unit      = "Count"
  }
}

# ---- CloudWatch Alarms -------------------------------------
resource "aws_cloudwatch_metric_alarm" "critical_findings" {
  alarm_name          = "${local.name_prefix}-sechub-critical-findings"
  alarm_description   = "Security Hub CRITICAL finding count exceeded threshold."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CriticalFindingsCount"
  namespace           = "SOC/SecurityHub"
  period              = 3600
  statistic           = "Sum"
  threshold           = var.critical_finding_alarm_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_alerts_topic_arn]
  ok_actions          = [var.critical_alerts_topic_arn]
  tags                = { Severity = "CRITICAL" }
}

resource "aws_cloudwatch_metric_alarm" "guardduty_high" {
  alarm_name          = "${local.name_prefix}-guardduty-high-findings"
  alarm_description   = "GuardDuty HIGH finding count exceeded threshold."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "HighSeverityFindingCount"
  namespace           = "AWS/GuardDuty"
  period              = 3600
  statistic           = "Sum"
  threshold           = var.guardduty_finding_alarm_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_alerts_topic_arn]

  dimensions = {
    DetectorId = var.guardduty_detector_id
  }
}


resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  count               = var.cloudtrail_log_group != "" ? 1 : 0
  alarm_name          = "${local.name_prefix}-unauthorized-api-alarm"
  alarm_description   = "Unauthorized API calls detected."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "${local.name_prefix}-UnauthorizedAPICalls"
  namespace           = "SOC/SecurityEvents"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_alerts_topic_arn]
  tags                = { Severity = "HIGH" }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  count               = var.cloudtrail_log_group != "" ? 1 : 0
  alarm_name          = "${local.name_prefix}-root-login-alarm"
  alarm_description   = "Root account login detected — immediate investigation required."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "${local.name_prefix}-RootAccountUsage"
  namespace           = "SOC/SecurityEvents"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_alerts_topic_arn]
  tags                = { Severity = "CRITICAL" }
}

# ---- SOC CloudWatch Dashboard ------------------------------
resource "aws_cloudwatch_dashboard" "soc" {
  dashboard_name = "${local.name_prefix}-soc-command-centre"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          region   = var.region
          markdown = "# 🛡️ Security Operations Centre — ${upper(var.environment)}\n**Organisation:** ${var.organization_name} | **Region:** ${var.region} | Updated every 5 minutes"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 6
        height = 6
        properties = {
          region  = var.region
          title   = "🚨 Unauthorized API Calls"
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [["SOC/SecurityEvents", "${local.name_prefix}-UnauthorizedAPICalls"]]
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 2
        width  = 6
        height = 6
        properties = {
          region  = var.region
          title   = "👤 Root Account Logins"
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [["SOC/SecurityEvents", "${local.name_prefix}-RootAccountUsage"]]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 6
        height = 6
        properties = {
          region  = var.region
          title   = "🔐 Console Logins Without MFA"
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [["SOC/SecurityEvents", "${local.name_prefix}-ConsoleLoginWithoutMFA"]]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 2
        width  = 6
        height = 6
        properties = {
          region  = var.region
          title   = "📋 IAM Policy Changes"
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [["SOC/SecurityEvents", "${local.name_prefix}-IAMPolicyChanges"]]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 8
        height = 6
        properties = {
          region = var.region
          title  = "🛡️ GuardDuty Findings (7d)"
          period = 86400
          stat   = "Sum"
          view   = "timeSeries"
          metrics = [
            ["AWS/GuardDuty", "HighSeverityFindingCount", { label = "High" }],
            ["AWS/GuardDuty", "MediumSeverityFindingCount", { label = "Medium" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 8
        width  = 8
        height = 6
        properties = {
          region  = var.region
          title   = "🔑 KMS Key Deletions"
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [["SOC/SecurityEvents", "${local.name_prefix}-KMSKeyDeletion"]]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 8
        width  = 8
        height = 6
        properties = {
          region  = var.region
          title   = "🌐 Security Group Changes"
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [["SOC/SecurityEvents", "${local.name_prefix}-SecurityGroupChanges"]]
        }
      },
      {
        type   = "alarm"
        x      = 0
        y      = 14
        width  = 24
        height = 4
        properties = {
          region = var.region
          title  = "Active Security Alarms"
          alarms = [
            aws_cloudwatch_metric_alarm.critical_findings.arn,
            aws_cloudwatch_metric_alarm.guardduty_high.arn
          ]
        }
      }
    ]
  })
}
