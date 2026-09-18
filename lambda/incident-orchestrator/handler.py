"""
Incident Orchestrator Lambda
==============================
Called by the Step Functions IR state machine.
Handles: classify, create_ops_item, gather_evidence,
         handle_high, log_finding, update_finding_status.
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

securityhub  = boto3.client("securityhub")
ssm          = boto3.client("ssm")
cloudtrail   = boto3.client("cloudtrail")
s3           = boto3.client("s3")
sns          = boto3.client("sns")


def lambda_handler(event, context):
    action  = event.get("action", "")
    payload = event.get("input", event)
    logger.info("Incident Orchestrator — action: %s", action)

    dispatch = {
        "classify"              : _classify,
        "create_ops_item"       : _create_ops_item,
        "gather_evidence"       : _gather_evidence,
        "handle_high"           : _handle_high,
        "log_finding"           : _log_finding,
        "update_finding_status" : _update_status,
    }
    handler = dispatch.get(action)
    if not handler:
        raise ValueError(f"Unknown action: {action}")

    return handler(payload)


def _classify(payload):
    findings = payload.get("detail", {}).get("findings", [payload.get("detail", {})])
    if not findings:
        return {"severity": "UNKNOWN", "title": "Unknown", "finding_id": ""}

    finding  = findings[0]
    severity = finding.get("Severity", {}).get("Label",
               "HIGH" if finding.get("severity", 0) >= 7 else "MEDIUM")
    return {
        "severity"  : severity,
        "title"     : finding.get("Title", finding.get("type", "Security Finding")),
        "finding_id": finding.get("Id", finding.get("id", "")),
        "account_id": finding.get("AwsAccountId", finding.get("accountId", "")),
    }


def _create_ops_item(payload):
    classification = payload.get("classification", {}).get("Payload", {})
    title     = classification.get("title", "Security Incident")
    severity  = classification.get("severity", "HIGH")
    finding_id = classification.get("finding_id", "")

    priority_map = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    priority = priority_map.get(severity, 2)

    try:
        resp = ssm.create_ops_item(
            Title       = f"[{severity}] {title}",
            Description = f"Security incident created by SOC automation.\nFinding ID: {finding_id}\nSeverity: {severity}\nTime: {datetime.now(timezone.utc).isoformat()}",
            Source      = "aws-cloud-security-operations-center",
            Priority    = priority,
            Tags        = [
                {"Key": "Severity",   "Value": severity},
                {"Key": "FindingId",  "Value": finding_id[:256]},
                {"Key": "Environment","Value": ENVIRONMENT},
            ],
            OpsItemType = "/aws/incident",
        )
        logger.info("OpsItem created: %s", resp.get("OpsItemId"))
        return {"ops_item_id": resp.get("OpsItemId"), "status": "created"}
    except Exception as exc:
        logger.error("OpsItem creation failed: %s", exc)
        return {"ops_item_id": None, "error": str(exc)}


def _gather_evidence(payload):
    """Collect CloudTrail events related to the incident."""
    classification = payload.get("classification", {}).get("Payload", {})
    account_id = classification.get("account_id", "")
    evidence   = {"cloudtrail_events": [], "evidence_time": datetime.now(timezone.utc).isoformat()}

    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
            MaxResults=20,
        )
        events = []
        for event in resp.get("Events", []):
            events.append({
                "EventName": event.get("EventName"),
                "EventTime": str(event.get("EventTime")),
                "Username" : event.get("Username", ""),
            })
        evidence["cloudtrail_events"] = events
    except Exception as exc:
        evidence["error"] = str(exc)

    if SOC_BUCKET:
        try:
            now = datetime.now(timezone.utc)
            key = f"incidents/evidence/{now.year}/{now.month:02d}/{now.day:02d}/evidence-{now.timestamp():.0f}.json"
            s3.put_object(Bucket=SOC_BUCKET, Key=key, Body=json.dumps(evidence, default=str),
                          ContentType="application/json", ServerSideEncryption="aws:kms")
            evidence["evidence_key"] = key
        except Exception as exc:
            evidence["s3_error"] = str(exc)

    return evidence


def _handle_high(payload):
    classification = payload.get("classification", {}).get("Payload", {})
    if ALERTS_TOPIC:
        try:
            sns.publish(
                TopicArn=ALERTS_TOPIC,
                Subject =f"[HIGH] Security Finding: {classification.get('title', 'Unknown')}",
                Message =json.dumps(classification, indent=2, default=str),
            )
        except Exception as exc:
            logger.error("SNS publish failed: %s", exc)
    return {"handled": True, "severity": "HIGH"}


def _log_finding(payload):
    if SOC_BUCKET:
        try:
            now = datetime.now(timezone.utc)
            key = f"incidents/medium-low/{now.year}/{now.month:02d}/{now.day:02d}/finding-{now.timestamp():.0f}.json"
            s3.put_object(Bucket=SOC_BUCKET, Key=key, Body=json.dumps(payload, default=str),
                          ContentType="application/json", ServerSideEncryption="aws:kms")
            return {"logged": True, "key": key}
        except Exception as exc:
            return {"logged": False, "error": str(exc)}
    return {"logged": False, "reason": "no_soc_bucket"}


def _update_status(payload):
    classification = payload.get("classification", {}).get("Payload", {})
    finding_id = classification.get("finding_id", "")
    if not finding_id or not finding_id.startswith("arn:"):
        return {"updated": False, "reason": "not_security_hub_finding"}

    try:
        securityhub.batch_update_findings(
            FindingIdentifiers=[{"Id": finding_id, "ProductArn": ""}],
            Workflow={"Status": "IN_PROGRESS"},
            Note={"Text": f"IR workflow started at {datetime.now(timezone.utc).isoformat()}", "UpdatedBy": "soc-ir-workflow"}
        )
        return {"updated": True, "finding_id": finding_id}
    except Exception as exc:
        return {"updated": False, "error": str(exc)}
