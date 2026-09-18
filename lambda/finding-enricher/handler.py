"""
Finding Enricher Lambda
=======================
Triggered by EventBridge on all GuardDuty findings.
Enriches findings with:
  - Resource owner tags (team, cost-center, environment)
  - Related CloudTrail events (last 15 min)
  - Asset classification (crown-jewel, standard, sandbox)
  - Recommended remediation steps
  - Saves enriched record to SOC S3 bucket
"""

import json
import logging
import os
import boto3
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ENVIRONMENT   = os.environ.get("ENVIRONMENT", "unknown")
SOC_BUCKET    = os.environ.get("SOC_BUCKET", "")
ALERTS_TOPIC  = os.environ.get("ALERTS_TOPIC", "")

session       = boto3.session.Session()
ec2           = session.client("ec2")
iam           = session.client("iam")
cloudtrail    = session.client("cloudtrail")
securityhub   = session.client("securityhub")
s3            = session.client("s3")
sns           = session.client("sns")


def lambda_handler(event, context):
    """Enrich a GuardDuty finding with asset context and save to SOC bucket."""
    logger.info("Finding Enricher invoked: %s", json.dumps(event, default=str))

    try:
        detail   = event.get("detail", {})
        finding  = _extract_finding(detail)

        enriched = {
            "original_finding"   : finding,
            "enrichment_time"    : datetime.now(timezone.utc).isoformat(),
            "environment"        : ENVIRONMENT,
            "resource_tags"      : _get_resource_tags(finding),
            "asset_classification": _classify_asset(finding),
            "recent_cloudtrail"  : _get_related_cloudtrail_events(finding),
            "remediation_steps"  : _get_remediation_steps(finding),
            "severity_score"     : detail.get("severity", 0),
        }

        _save_to_soc_bucket(enriched, finding)
        _update_security_hub_note(finding, enriched)

        logger.info("Finding enriched: %s", finding.get("id", "unknown"))
        return {"statusCode": 200, "enriched": True}

    except Exception as exc:
        logger.error("Enrichment failed: %s", exc, exc_info=True)
        return {"statusCode": 500, "error": str(exc)}


def _extract_finding(detail):
    """Extract normalised finding fields from GuardDuty or Security Hub event."""
    return {
        "id"         : detail.get("id", detail.get("findingId", "")),
        "type"       : detail.get("type", ""),
        "severity"   : detail.get("severity", 0),
        "account_id" : detail.get("accountId", ""),
        "region"     : detail.get("region", ""),
        "resource"   : detail.get("resource", {}),
        "title"      : detail.get("title", ""),
        "description": detail.get("description", ""),
        "time"       : detail.get("updatedAt", datetime.now(timezone.utc).isoformat()),
    }


def _get_resource_tags(finding):
    """Retrieve tags from the affected resource for owner/team attribution."""
    tags = {}
    resource = finding.get("resource", {})
    resource_type = resource.get("resourceType", "")

    try:
        if resource_type == "Instance":
            instance_id = resource.get("instanceDetails", {}).get("instanceId", "")
            if instance_id:
                resp = ec2.describe_instances(InstanceIds=[instance_id])
                for tag in resp["Reservations"][0]["Instances"][0].get("Tags", []):
                    tags[tag["Key"]] = tag["Value"]

        elif resource_type == "S3Bucket":
            bucket_name = resource.get("s3BucketDetails", [{}])[0].get("name", "")
            if bucket_name:
                s3_client = session.client("s3")
                resp = s3_client.get_bucket_tagging(Bucket=bucket_name)
                for tag in resp.get("TagSet", []):
                    tags[tag["Key"]] = tag["Value"]

    except Exception as exc:
        logger.warning("Could not retrieve resource tags: %s", exc)

    return tags


def _classify_asset(finding):
    """Classify asset sensitivity based on tags and resource type."""
    tags = _get_resource_tags(finding)
    resource_type = finding.get("resource", {}).get("resourceType", "")

    if tags.get("Classification") == "crown-jewel":
        return "CROWN_JEWEL"
    if tags.get("Environment") == "prod":
        return "PRODUCTION"
    if tags.get("Environment") == "dev":
        return "DEVELOPMENT"
    if resource_type in ("S3Bucket",) and tags.get("DataClassification") == "sensitive":
        return "SENSITIVE_DATA"

    return "STANDARD"


def _get_related_cloudtrail_events(finding):
    """Fetch related CloudTrail events from the last 15 minutes."""
    events = []
    try:
        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=15)

        resource = finding.get("resource", {})
        instance_id = resource.get("instanceDetails", {}).get("instanceId", "")

        lookup_attr = []
        if instance_id:
            lookup_attr.append({"AttributeKey": "ResourceName", "AttributeValue": instance_id})
        if finding.get("account_id"):
            lookup_attr.append({"AttributeKey": "Username", "AttributeValue": finding["account_id"]})

        if lookup_attr:
            resp = cloudtrail.lookup_events(
                LookupAttributes=[lookup_attr[0]],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=10
            )
            for event in resp.get("Events", []):
                events.append({
                    "EventName"  : event.get("EventName"),
                    "EventTime"  : str(event.get("EventTime")),
                    "Username"   : event.get("Username"),
                    "SourceIP"   : json.loads(event.get("CloudTrailEvent", "{}")).get("sourceIPAddress", ""),
                })
    except Exception as exc:
        logger.warning("CloudTrail lookup failed: %s", exc)

    return events


def _get_remediation_steps(finding):
    """Return remediation guidance based on finding type."""
    finding_type = finding.get("type", "")

    remediation_map = {
        "Policy:S3/BucketPublicAccess":
            "Run: aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B":
            "1. Disable IAM user immediately. 2. Invalidate all active sessions. 3. Rotate credentials. 4. Review CloudTrail for actions taken.",
        "Backdoor:EC2/C&CActivity":
            "1. Capture memory dump if possible. 2. Create forensic EBS snapshot. 3. Isolate instance by replacing security group with deny-all. 4. Preserve logs. 5. Engage IR team.",
        "CryptoCurrency:EC2/BitcoinTool.B":
            "1. Identify the running process (ssm run-command). 2. Isolate instance. 3. Review IAM role for credential abuse. 4. Terminate and replace instance.",
        "Recon:IAMUser/MaliciousIPCaller":
            "1. Identify the IAM principal making reconnaissance calls. 2. Review access keys. 3. Enable MFA. 4. Apply DenyAll policy temporarily.",
    }

    for key, guidance in remediation_map.items():
        if key in finding_type:
            return guidance

    return "Review AWS Security Hub finding and apply recommended remediation from the finding detail."


def _save_to_soc_bucket(enriched, finding):
    """Persist enriched finding to SOC S3 bucket for SIEM and audit."""
    if not SOC_BUCKET:
        return

    now    = datetime.now(timezone.utc)
    key    = (
        f"enriched-findings/"
        f"year={now.year}/month={now.month:02d}/day={now.day:02d}/"
        f"{finding.get('id', 'unknown')}.json"
    )
    s3.put_object(
        Bucket      = SOC_BUCKET,
        Key         = key,
        Body        = json.dumps(enriched, default=str),
        ContentType = "application/json",
        ServerSideEncryption = "aws:kms",
    )
    logger.info("Saved enriched finding to s3://%s/%s", SOC_BUCKET, key)


def _update_security_hub_note(finding, enriched):
    """Add enrichment note to the Security Hub finding if it originated there."""
    finding_id = finding.get("id", "")
    if not finding_id or not finding_id.startswith("arn:"):
        return

    try:
        asset_class = enriched.get("asset_classification", "UNKNOWN")
        owner_tags  = enriched.get("resource_tags", {})
        owner_team  = owner_tags.get("Owner", "Unknown")

        note_text = (
            f"[SOC Enriched] Asset: {asset_class} | Owner: {owner_team} | "
            f"Related CT events: {len(enriched.get('recent_cloudtrail', []))} | "
            f"Enriched: {enriched['enrichment_time']}"
        )

        securityhub.batch_update_findings(
            FindingIdentifiers=[{"Id": finding_id, "ProductArn": ""}],
            Note={"Text": note_text, "UpdatedBy": "soc-finding-enricher"}
        )
    except Exception as exc:
        logger.warning("Could not update Security Hub note: %s", exc)
