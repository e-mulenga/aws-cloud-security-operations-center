"""
Auto-Remediate Public S3 Lambda
================================
Triggered by EventBridge on GuardDuty Policy:S3/BucketPublicAccess findings.
Automatically re-enables S3 block-public-access and logs the remediation.

SAFE ACTION — does not delete data or change bucket contents.
Requires explicit opt-in via auto_remediate_s3_enabled = true.
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

s3   = boto3.client("s3")
s3c  = boto3.client("s3control")
sns  = boto3.client("sns")
sts  = boto3.client("sts")


def lambda_handler(event, context):
    logger.info("Auto-Remediate S3 invoked: %s", json.dumps(event, default=str))

    detail   = event.get("detail", {})
    resource = detail.get("resource", {})

    bucket_details = resource.get("s3BucketDetails", [])
    if not bucket_details:
        logger.warning("No S3 bucket details in finding — skipping.")
        return {"statusCode": 200, "action": "skipped", "reason": "no_bucket_details"}

    bucket_name = bucket_details[0].get("name", "")
    if not bucket_name:
        logger.warning("Empty bucket name — skipping.")
        return {"statusCode": 200, "action": "skipped", "reason": "empty_bucket_name"}

    account_id  = sts.get_caller_identity()["Account"]
    finding_id  = detail.get("id", "")
    finding_type = detail.get("type", "")
    severity    = detail.get("severity", 0)

    logger.info("Remediating public S3 bucket: %s (finding: %s)", bucket_name, finding_id)

    result = {
        "bucket_name"  : bucket_name,
        "finding_id"   : finding_id,
        "finding_type" : finding_type,
        "severity"     : severity,
        "remediation_time" : datetime.now(timezone.utc).isoformat(),
        "environment"  : ENVIRONMENT,
        "actions_taken": [],
        "errors"       : [],
    }

    # ---- Action 1: Enable S3 block-public-access at bucket level ----
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls"      : True,
                "IgnorePublicAcls"     : True,
                "BlockPublicPolicy"    : True,
                "RestrictPublicBuckets": True,
            }
        )
        result["actions_taken"].append("Enabled S3 block-public-access (all four settings) on bucket")
        logger.info("✅ Block-public-access enabled on: %s", bucket_name)
    except Exception as exc:
        error_msg = f"Failed to enable block-public-access: {exc}"
        result["errors"].append(error_msg)
        logger.error(error_msg)

    # ---- Action 2: Tag bucket with remediation metadata ----
    try:
        existing_tags = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
        new_tags = [t for t in existing_tags if t["Key"] not in ("SOCRemediated", "SOCRemediationTime")]
        new_tags.extend([
            {"Key": "SOCRemediated",     "Value": "true"},
            {"Key": "SOCRemediationTime","Value": datetime.now(timezone.utc).isoformat()},
            {"Key": "SOCFindingId",      "Value": finding_id[:256]},
        ])
        s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": new_tags})
        result["actions_taken"].append("Tagged bucket with SOC remediation metadata")
    except Exception as exc:
        result["errors"].append(f"Tagging failed (non-critical): {exc}")

    # ---- Action 3: Notify SOC of remediation ----
    if ALERTS_TOPIC:
        try:
            message = (
                f"✅ AUTO-REMEDIATED: S3 Public Access\n"
                f"Bucket: {bucket_name}\n"
                f"Account: {account_id}\n"
                f"Finding: {finding_type} (severity: {severity})\n"
                f"Action: Block-public-access re-enabled (all 4 settings)\n"
                f"Time: {result['remediation_time']}\n"
                f"Finding ID: {finding_id}"
            )
            sns.publish(
                TopicArn = ALERTS_TOPIC,
                Subject  = f"[AUTO-REMEDIATED] S3 Public Bucket — {bucket_name}",
                Message  = message,
            )
            result["actions_taken"].append("SNS notification sent to SOC team")
        except Exception as exc:
            result["errors"].append(f"SNS notification failed: {exc}")

    # ---- Action 4: Log remediation record to SOC S3 ----
    if SOC_BUCKET:
        try:
            now = datetime.now(timezone.utc)
            key = f"remediation-logs/s3/{now.year}/{now.month:02d}/{now.day:02d}/{bucket_name}-{finding_id[:8]}.json"
            s3.put_object(
                Bucket=SOC_BUCKET, Key=key,
                Body=json.dumps(result, default=str),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
            )
            result["actions_taken"].append(f"Remediation record saved to SOC bucket: {key}")
        except Exception as exc:
            result["errors"].append(f"SOC bucket logging failed: {exc}")

    logger.info("Remediation complete: %s", json.dumps(result, default=str))
    return {"statusCode": 200, "result": result}
