"""
Auto-Disable IAM User Lambda
==============================
Triggered by GuardDuty credential-compromise findings.
Disables IAM user access WITHOUT deleting the user (preserves audit trail):
  1. Attach DenyAll managed policy to block all actions
  2. Deactivate all access keys
  3. Tag user with incident metadata
  4. Notify SOC team with context

DISRUPTIVE ACTION — requires explicit opt-in:
  auto_disable_iam_enabled = true
"""

import json
import logging
import os
import boto3
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SOC_BUCKET   = os.environ.get("SOC_BUCKET", "")
ALERTS_TOPIC = os.environ.get("ALERTS_TOPIC", "")
ENVIRONMENT  = os.environ.get("ENVIRONMENT", "unknown")
DENY_ALL_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"

iam = boto3.client("iam")
sns = boto3.client("sns")
s3  = boto3.client("s3")


def lambda_handler(event, context):
    logger.info("Auto-Disable IAM invoked: %s", json.dumps(event, default=str))

    detail       = event.get("detail", {})
    resource     = detail.get("resource", {})
    access_key   = resource.get("accessKeyDetails", {})
    username     = access_key.get("userName", "")
    user_type    = access_key.get("userType", "")
    finding_type = detail.get("type", "")
    finding_id   = detail.get("id", "")
    severity     = detail.get("severity", 0)
    incident_ts  = datetime.now(timezone.utc).isoformat()

    if not username or user_type == "Root":
        logger.warning("No username or root account — skipping automated disable. Username: %s", username)
        return {"statusCode": 200, "action": "skipped", "reason": "no_username_or_root"}

    result = {
        "username"    : username,
        "finding_id"  : finding_id,
        "finding_type": finding_type,
        "severity"    : severity,
        "disable_time": incident_ts,
        "environment" : ENVIRONMENT,
        "actions_taken": [],
        "errors"      : [],
    }

    # Step 1: Attach DenyAll policy
    try:
        iam.attach_user_policy(UserName=username, PolicyArn=DENY_ALL_ARN)
        result["actions_taken"].append(f"Attached AWSDenyAll policy to user: {username}")
        logger.info("✅ DenyAll attached to: %s", username)
    except Exception as exc:
        result["errors"].append(f"DenyAll policy attachment failed: {exc}")

    # Step 2: Deactivate all access keys
    try:
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        for key in keys:
            kid = key["AccessKeyId"]
            iam.update_access_key(UserName=username, AccessKeyId=kid, Status="Inactive")
            result["actions_taken"].append(f"Deactivated access key: {kid}")
        logger.info("✅ Deactivated %d access keys for: %s", len(keys), username)
    except Exception as exc:
        result["errors"].append(f"Access key deactivation failed: {exc}")

    # Step 3: Tag user
    try:
        iam.tag_user(UserName=username, Tags=[
            {"Key": "SOC-Status",      "Value": "DISABLED"},
            {"Key": "SOC-FindingId",   "Value": finding_id[:256]},
            {"Key": "SOC-DisableTime", "Value": incident_ts},
        ])
        result["actions_taken"].append("Tagged user with SOC incident metadata")
    except Exception as exc:
        result["errors"].append(f"User tagging failed: {exc}")

    # Step 4: Notify SOC
    if ALERTS_TOPIC:
        try:
            sns.publish(
                TopicArn=ALERTS_TOPIC,
                Subject =f"[P1 INCIDENT] IAM User Disabled — {username}",
                Message =(
                    f"🔐 IAM USER DISABLED\nUser: {username}\n"
                    f"Finding: {finding_type} (severity: {severity})\n"
                    f"Actions: DenyAll policy attached, all access keys deactivated\n"
                    f"Time: {incident_ts}\nFinding ID: {finding_id}\n\n"
                    f"Investigate and re-enable only after full review."
                )
            )
        except Exception as exc:
            result["errors"].append(f"SNS notification failed: {exc}")

    # Step 5: Log to SOC bucket
    if SOC_BUCKET:
        try:
            now = datetime.now(timezone.utc)
            key = f"incidents/iam-disable/{now.year}/{now.month:02d}/{now.day:02d}/{username}-{finding_id[:8]}.json"
            s3.put_object(Bucket=SOC_BUCKET, Key=key, Body=json.dumps(result, default=str),
                          ContentType="application/json", ServerSideEncryption="aws:kms")
        except Exception as exc:
            result["errors"].append(f"SOC bucket log failed: {exc}")

    logger.info("Disable complete: %s", json.dumps(result, default=str))
    return {"statusCode": 200, "result": result}
