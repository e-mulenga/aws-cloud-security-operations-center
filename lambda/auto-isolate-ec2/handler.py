"""
Auto-Isolate EC2 Lambda
========================
Triggered by EventBridge on HIGH/CRITICAL GuardDuty EC2 findings.
Performs forensic isolation WITHOUT destroying evidence:
  Step 1: Create forensic EBS snapshot (preserve evidence)
  Step 2: Create deny-all security group in the instance VPC
  Step 3: Replace instance security groups with deny-all group
  Step 4: Tag instance with incident metadata
  Step 5: Notify SOC with isolation summary

DISRUPTIVE ACTION — requires explicit opt-in:
  auto_isolate_ec2_enabled = true
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

ec2  = boto3.client("ec2")
sns  = boto3.client("sns")
s3   = boto3.client("s3")
sts  = boto3.client("sts")


def lambda_handler(event, context):
    logger.info("Auto-Isolate EC2 invoked: %s", json.dumps(event, default=str))

    detail      = event.get("detail", {})
    resource    = detail.get("resource", {})
    instance_details = resource.get("instanceDetails", {})
    instance_id = instance_details.get("instanceId", "")

    if not instance_id:
        logger.warning("No instance ID found in GuardDuty finding — skipping.")
        return {"statusCode": 200, "action": "skipped", "reason": "no_instance_id"}

    finding_id   = detail.get("id", "")
    finding_type = detail.get("type", "")
    severity     = detail.get("severity", 0)
    account_id   = sts.get_caller_identity()["Account"]
    incident_ts  = datetime.now(timezone.utc).isoformat()

    result = {
        "instance_id"  : instance_id,
        "finding_id"   : finding_id,
        "finding_type" : finding_type,
        "severity"     : severity,
        "isolation_time": incident_ts,
        "environment"  : ENVIRONMENT,
        "actions_taken": [],
        "errors"       : [],
    }

    # ---- Step 1: Describe instance to get VPC and volumes ----
    try:
        resp     = ec2.describe_instances(InstanceIds=[instance_id])
        instance = resp["Reservations"][0]["Instances"][0]
        vpc_id   = instance.get("VpcId", "")
        volumes  = [bdm["Ebs"]["VolumeId"] for bdm in instance.get("BlockDeviceMappings", []) if "Ebs" in bdm]
        result["vpc_id"]  = vpc_id
        result["volumes"] = volumes
        logger.info("Instance %s in VPC %s with volumes: %s", instance_id, vpc_id, volumes)
    except Exception as exc:
        result["errors"].append(f"Failed to describe instance: {exc}")
        logger.error("Cannot describe instance %s: %s", instance_id, exc)
        return {"statusCode": 500, "result": result}

    # ---- Step 2: Forensic EBS snapshots (BEFORE isolation) ----
    snapshot_ids = []
    for volume_id in volumes:
        try:
            snap = ec2.create_snapshot(
                VolumeId    = volume_id,
                Description = f"FORENSIC-{incident_ts}-{instance_id}-{finding_id[:8]}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Purpose",    "Value": "forensic-evidence"},
                        {"Key": "InstanceId", "Value": instance_id},
                        {"Key": "FindingId",  "Value": finding_id[:256]},
                        {"Key": "IsolationTime", "Value": incident_ts},
                    ]
                }]
            )
            snapshot_ids.append(snap["SnapshotId"])
            result["actions_taken"].append(f"Created forensic snapshot {snap['SnapshotId']} of volume {volume_id}")
            logger.info("✅ Forensic snapshot created: %s", snap["SnapshotId"])
        except Exception as exc:
            result["errors"].append(f"Snapshot of {volume_id} failed: {exc}")

    result["forensic_snapshots"] = snapshot_ids

    # ---- Step 3: Create deny-all isolation security group ----
    isolation_sg_id = None
    try:
        sg_name = f"INCIDENT-ISOLATION-{instance_id}-{int(datetime.now(timezone.utc).timestamp())}"
        sg_resp = ec2.create_security_group(
            GroupName   = sg_name,
            Description = f"INCIDENT ISOLATION — no ingress/egress — {incident_ts}",
            VpcId       = vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "Name",     "Value": sg_name},
                    {"Key": "Purpose",  "Value": "incident-isolation"},
                    {"Key": "InstanceId", "Value": instance_id},
                    {"Key": "FindingId",  "Value": finding_id[:256]},
                ]
            }]
        )
        isolation_sg_id = sg_resp["GroupId"]

        # Remove the default outbound rule (allow-all)
        ec2.revoke_security_group_egress(
            GroupId=isolation_sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges"  : [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }]
        )
        result["actions_taken"].append(f"Created deny-all isolation security group: {isolation_sg_id}")
        result["isolation_sg_id"] = isolation_sg_id
        logger.info("✅ Isolation SG created: %s", isolation_sg_id)
    except Exception as exc:
        result["errors"].append(f"Failed to create isolation SG: {exc}")
        logger.error("Cannot create isolation SG: %s", exc)

    # ---- Step 4: Replace instance security groups ----
    if isolation_sg_id:
        try:
            # Preserve original SG IDs for post-IR restoration
            original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
            result["original_security_groups"] = original_sgs

            ec2.modify_instance_attribute(
                InstanceId     = instance_id,
                Groups         = [isolation_sg_id]
            )
            result["actions_taken"].append(
                f"Replaced security groups {original_sgs} with isolation group {isolation_sg_id}"
            )
            logger.info("✅ Instance %s isolated with SG %s", instance_id, isolation_sg_id)
        except Exception as exc:
            result["errors"].append(f"Failed to apply isolation SG: {exc}")

    # ---- Step 5: Tag instance with incident metadata ----
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "SOC-Status",       "Value": "ISOLATED"},
                {"Key": "SOC-FindingId",    "Value": finding_id[:256]},
                {"Key": "SOC-FindingType",  "Value": finding_type},
                {"Key": "SOC-IsolationTime","Value": incident_ts},
                {"Key": "SOC-OriginalSGs",  "Value": json.dumps(result.get("original_security_groups", []))[:256]},
            ]
        )
        result["actions_taken"].append("Tagged instance with incident metadata")
    except Exception as exc:
        result["errors"].append(f"Tagging failed: {exc}")

    # ---- Step 6: Notify SOC ----
    if ALERTS_TOPIC:
        try:
            message = (
                f"🔒 EC2 INSTANCE ISOLATED\n"
                f"Instance: {instance_id} | VPC: {vpc_id}\n"
                f"Account: {account_id} | Environment: {ENVIRONMENT}\n"
                f"Finding: {finding_type} (severity: {severity})\n"
                f"Forensic Snapshots: {', '.join(snapshot_ids) or 'None'}\n"
                f"Isolation SG: {isolation_sg_id or 'Failed'}\n"
                f"Original SGs: {result.get('original_security_groups', [])}\n"
                f"Time: {incident_ts}\n\n"
                f"ACTION REQUIRED: Investigate instance and approve/reject isolation.\n"
                f"To restore: replace SG {isolation_sg_id} with original SGs."
            )
            sns.publish(
                TopicArn=ALERTS_TOPIC,
                Subject =f"[P1 INCIDENT] EC2 Instance Isolated — {instance_id}",
                Message =message,
            )
            result["actions_taken"].append("P1 SNS notification sent to SOC")
        except Exception as exc:
            result["errors"].append(f"SNS notification failed: {exc}")

    # ---- Step 7: Log to SOC bucket ----
    if SOC_BUCKET:
        try:
            now = datetime.now(timezone.utc)
            key = f"incidents/ec2-isolation/{now.year}/{now.month:02d}/{now.day:02d}/{instance_id}-{finding_id[:8]}.json"
            s3.put_object(
                Bucket=SOC_BUCKET, Key=key,
                Body=json.dumps(result, default=str),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
            )
        except Exception as exc:
            result["errors"].append(f"SOC bucket log failed: {exc}")

    logger.info("Isolation complete: %s", json.dumps(result, default=str))
    return {"statusCode": 200, "result": result}
