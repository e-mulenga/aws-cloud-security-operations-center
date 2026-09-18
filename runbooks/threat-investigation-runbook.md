# Threat Investigation Runbook
## AWS Cloud Security Operations Centre

**Portfolio Position 4 of 6 | Owner: Cloud Security Team**

---

## Investigation Toolkit

| Tool | Use Case | Access |
|---|---|---|
| Amazon Detective | Entity behaviour graph, timeline, peer comparison | AWS Console → Detective |
| Athena Named Queries | CloudTrail SQL queries | `<org>-<env>-soc-workgroup` |
| SOC S3 Bucket | Enriched findings, remediation logs, SBOM | `s3://<soc-bucket>/` |
| Security Hub | Finding detail, compliance score | AWS Console → Security Hub |
| GuardDuty | Raw finding detail, finding archive | AWS Console → GuardDuty |

---

## Investigation 1: Who Accessed a Resource?

```sql
-- Athena: All access to a specific S3 bucket in the last 24 hours
SELECT eventtime, useridentity.arn AS actor, eventname, sourceipaddress, awsregion,
  json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
  json_extract_scalar(requestparameters, '$.key') AS object_key,
  errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.bucketName') = '<BUCKET_NAME>'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '24' hour
ORDER BY eventtime DESC;
```

## Investigation 2: What Did a Compromised Principal Do?

```sql
-- Athena: All non-read-only actions by a specific principal
SELECT eventtime, eventname, eventsource, awsregion, sourceipaddress, errorcode,
  useridentity.arn AS actor_arn,
  json_extract_scalar(requestparameters, '$') AS params_summary
FROM cloudtrail_logs
WHERE useridentity.arn = '<COMPROMISED_ARN>'
  AND readonly = 'false'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '48' hour
ORDER BY eventtime DESC
LIMIT 500;
```

## Investigation 3: Has This IP Been Seen Before?

```sql
-- Athena: All CloudTrail events from a specific source IP
SELECT eventtime, eventname, eventsource, useridentity.arn AS actor,
  awsregion, recipientaccountid
FROM cloudtrail_logs
WHERE sourceipaddress = '<SUSPICIOUS_IP>'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '30' day
ORDER BY eventtime DESC;
```

## Investigation 4: Privilege Escalation Path

```sql
-- Athena: IAM permission changes that could enable escalation
SELECT eventtime, eventname, useridentity.arn AS actor,
  json_extract_scalar(requestparameters, '$.roleName') AS target_role,
  json_extract_scalar(requestparameters, '$.policyDocument') AS policy_doc,
  sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('PutRolePolicy','AttachRolePolicy','CreateRole','UpdateAssumeRolePolicy',
                    'PutUserPolicy','AttachUserPolicy','CreatePolicy','CreatePolicyVersion')
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
ORDER BY eventtime DESC;
```

## Investigation 5: Data Exfiltration Assessment

```sql
-- Athena: Large S3 GetObject operations (potential exfil)
SELECT eventtime, useridentity.arn AS actor, sourceipaddress,
  json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
  json_extract_scalar(requestparameters, '$.key') AS object_key,
  awsregion
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND errorcode IS NULL
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '2' hour
GROUP BY 1,2,3,4,5,6
ORDER BY eventtime DESC
LIMIT 1000;
```

---

## Using Amazon Detective for Investigation

```bash
# Get Detective graph ARN
GRAPH_ARN=$(aws detective list-graphs --query 'GraphList[0].Arn' --output text --region af-south-1)
echo "Detective graph: ${GRAPH_ARN}"

# Search for an entity
aws detective search-graph \
  --graph-arn "${GRAPH_ARN}" \
  --filter-criteria '{"CreatedTime":{"StartInclusive":"2024-01-01T00:00:00Z"}}' \
  --entity-filter '{"Type":"IAM_ROLE"}' \
  --region af-south-1
```

---

## Evidence Collection Checklist

Before any remediation that alters evidence:

- [ ] CloudTrail logs: identify the 30-minute window before/after finding
- [ ] VPC Flow Logs: download for the affected instance's ENI
- [ ] EBS snapshot: forensic snapshot taken before isolation
- [ ] S3 access logs: for any affected buckets
- [ ] IAM credential report: capture before any key deletion
- [ ] All evidence paths recorded in the SOC incident record

*Owner: Cloud Security Team | Review: Quarterly*
