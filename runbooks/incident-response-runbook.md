# Incident Response Runbook
## AWS Cloud Security Operations Centre

**Portfolio Position 4 of 6 | Owner: Cloud Security Team**

---

## Severity Definitions & SLAs

| Severity | Finding Types | Acknowledge | Contain | Resolve |
|---|---|---|---|---|
| **P1 — Critical** | Root login, credential compromise, C2/backdoor | 15 min | 1 hour | 4 hours |
| **P2 — High** | Public S3, GuardDuty HIGH, Security Hub HIGH | 30 min | 4 hours | 24 hours |
| **P3 — Medium** | Config rule violations, anomalous API calls | 2 hours | 24 hours | 5 days |
| **P4 — Low** | Access Analyzer findings, informational | Next business day | — | 10 days |

---

## P1 Runbook: Credential Compromise (IAMUser/ConsoleLoginSuccess.B)

**Trigger:** GuardDuty `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Severity ≥ 7.0

### Step 1 — Validate finding (0–5 min)
```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region af-south-1)
aws guardduty get-findings --detector-id "${DETECTOR_ID}" \
  --finding-ids "<FINDING_ID>" \
  --query 'Findings[0].{Type:Type,Severity:Severity,User:Resource.AccessKeyDetails.UserName,SourceIP:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4}'
```

### Step 2 — Check auto-remediation status
If `auto_disable_iam_enabled = true`, the Lambda has already:
- Attached `AWSDenyAll` policy to the user
- Deactivated all access keys
Check the SOC bucket: `s3://<soc-bucket>/incidents/iam-disable/`

### Step 3 — Manual disable if auto-remediation not enabled
```bash
USERNAME="<compromised-user>"
# Attach deny-all
aws iam attach-user-policy --user-name "${USERNAME}" \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
# Deactivate all access keys
for KEY_ID in $(aws iam list-access-keys --user-name "${USERNAME}" \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "${USERNAME}" \
    --access-key-id "${KEY_ID}" --status Inactive
  echo "Deactivated: ${KEY_ID}"
done
```

### Step 4 — Investigate using Athena
```sql
-- Run in Athena workgroup: <org>-<env>-soc-workgroup
SELECT eventtime, eventname, sourceipaddress, awsregion
FROM cloudtrail_logs
WHERE useridentity.username = '<USERNAME>'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '2' hour
ORDER BY eventtime DESC;
```

### Step 5 — Check for lateral movement
```bash
# Review what the compromised user did
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="${USERNAME}" \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Name:EventName,Time:EventTime,Source:EventSource}' \
  --output table --region af-south-1
```

### Step 6 — Trigger IR State Machine (if not already triggered)
```bash
aws stepfunctions start-execution \
  --state-machine-arn "<IR_STATE_MACHINE_ARN>" \
  --input "{\"detail\":{\"type\":\"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B\",\"severity\":8,\"id\":\"<FINDING_ID>\"}}" \
  --region af-south-1
```

---

## P1 Runbook: EC2 Instance Compromise (Backdoor/C2)

**Trigger:** GuardDuty `Backdoor:EC2/*` or `Trojan:EC2/*` | Severity ≥ 7.0

### Step 1 — Check auto-isolation status
If `auto_isolate_ec2_enabled = true`, check SOC bucket for isolation record:
```bash
aws s3 ls "s3://<soc-bucket>/incidents/ec2-isolation/" --recursive | sort -r | head -5
aws s3 cp "s3://<soc-bucket>/incidents/ec2-isolation/<latest>.json" - | python3 -m json.tool
```

### Step 2 — Manual isolation if not auto-enabled
```bash
INSTANCE_ID="<compromised-instance>"
VPC_ID=$(aws ec2 describe-instances --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].VpcId' --output text)

# Create forensic snapshots FIRST
for VOL in $(aws ec2 describe-instances --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' \
  --output text); do
  aws ec2 create-snapshot --volume-id "${VOL}" \
    --description "FORENSIC-$(date +%Y%m%d)-${INSTANCE_ID}"
done

# Create deny-all security group
ISO_SG=$(aws ec2 create-security-group \
  --group-name "ISOLATION-$(date +%s)" \
  --description "Incident isolation" \
  --vpc-id "${VPC_ID}" \
  --query 'GroupId' --output text)

# Remove default outbound rule
aws ec2 revoke-security-group-egress --group-id "${ISO_SG}" \
  --ip-permissions IpProtocol=-1,IpRanges='[{CidrIp=0.0.0.0/0}]'

# Apply isolation
aws ec2 modify-instance-attribute \
  --instance-id "${INSTANCE_ID}" --groups "${ISO_SG}"
echo "Instance ${INSTANCE_ID} isolated with SG ${ISO_SG}"
```

### Step 3 — Investigate in Amazon Detective
1. Open AWS Console → Detective → Search for the instance ID
2. Review: activity timeline, peer comparison, DNS lookups, network flows
3. Identify the initial access vector

---

## P2 Runbook: S3 Bucket Made Public

**Trigger:** GuardDuty `Policy:S3/BucketPublicAccess` OR Config rule `s3-bucket-public-read-prohibited`

If `auto_remediate_s3_enabled = true`, block-public-access has already been re-enabled.
Verify: `s3://<soc-bucket>/remediation-logs/s3/`

### Manual remediation
```bash
aws s3api put-public-access-block --bucket "<BUCKET_NAME>" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Exposure assessment
```bash
# Check S3 server access logs for data exfiltration during exposure window
aws s3api get-bucket-logging --bucket "<BUCKET_NAME>"
# Review access logs for GET requests during the exposure period
```

---

## Post-Incident Review Template

```markdown
## Post-Incident Review — [DATE] [TITLE]
**Severity:** P1 / P2
**Duration:** [START] → [RESOLVED] (Δ [HH:MM])
**IR Commander:** [NAME]

### Timeline (UTC)
| Time | Event |
|---|---|
| HH:MM | Finding generated by GuardDuty |
| HH:MM | EventBridge triggered IR workflow |
| HH:MM | Auto-remediation executed (if applicable) |
| HH:MM | SOC analyst engaged |
| HH:MM | Containment confirmed |
| HH:MM | Resolved |

### Root Cause
[Description]

### Auto-Remediation Performance
- Did auto-remediation trigger? [Yes/No]
- Was it effective? [Yes/No/Partial]
- Time from finding to remediation: [X minutes]

### Action Items
| Item | Owner | Due |
|---|---|---|
| | | |
```

*Owner: Cloud Security Team | Review: After every P1 incident and quarterly*
