# Operational Runbook
## AWS Cloud Security Operations Centre

**Portfolio Position 4 of 6 | Owner: Cloud Security Team**

---

## Daily SOC Tasks

### Morning Check (09:00 daily)
```bash
# 1. Check overnight Security Hub findings
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Account:AwsAccountId,Time:UpdatedAt}' \
  --output table --region af-south-1

# 2. Check IR state machine executions
aws stepfunctions list-executions \
  --state-machine-arn "<IR_STATE_MACHINE_ARN>" \
  --status-filter RUNNING \
  --query 'executions[*].{Name:name,Start:startDate,Status:status}' \
  --output table --region af-south-1

# 3. Open SOC dashboard in browser
echo "https://console.aws.amazon.com/cloudwatch/home?region=af-south-1#dashboards:name=<org>-prod-soc-command-centre"
```

---

## Adding a New Member Account to Detective

```bash
GRAPH_ARN=$(aws detective list-graphs --query 'GraphList[0].Arn' --output text --region af-south-1)
aws detective create-members \
  --graph-arn "${GRAPH_ARN}" \
  --accounts AccountId="<NEW_ACCOUNT_ID>",EmailAddress="<ACCOUNT_EMAIL>" \
  --message "Invitation to join SOC Detective behaviour graph" \
  --region af-south-1
```

---

## Tuning GuardDuty Suppression Rules

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region af-south-1)

# Create suppression filter for known-good scanner IPs
aws guardduty create-filter \
  --detector-id "${DETECTOR_ID}" \
  --name "Suppress-SecurityScanner-$(date +%Y%m%d)" \
  --action ARCHIVE \
  --description "Suppress findings from approved vulnerability scanner" \
  --finding-criteria '{
    "Criterion": {
      "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": {
        "Equals": ["<SCANNER_IP>"]
      }
    }
  }' \
  --region af-south-1
# IMPORTANT: Document all suppressions with justification and expiry date
```

---

## Running a Manual Macie Scan

```bash
# Start a one-time classification job
aws macie2 create-classification-job \
  --name "Manual-Scan-$(date +%Y%m%d-%H%M)" \
  --job-type ONE_TIME \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "<ACCOUNT_ID>",
      "buckets": ["<BUCKET_NAME>"]
    }]
  }' \
  --region af-south-1
```

---

## Maintenance Schedule

| Task | Frequency | Owner |
|---|---|---|
| Review Security Hub CRITICAL/HIGH findings | Daily | SOC Analyst |
| Review GuardDuty findings > severity 5 | Daily | SOC Analyst |
| Check IR state machine for stuck executions | Daily | SOC Analyst |
| Review Access Analyzer external-access findings | Weekly | Cloud Security |
| Review and renew suppression rules | Monthly | Cloud Security |
| Test IR workflow with simulated finding | Monthly | Cloud Security |
| Glue crawler re-run verification | Monthly | Platform Engineering |
| Well-Architected review of SOC posture | Quarterly | Cloud Architect |
| Full IR tabletop exercise | Bi-annually | All teams |

*Owner: Cloud Security Team | Review: Quarterly*
