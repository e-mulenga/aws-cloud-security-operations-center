# Service Selection Rationale
## AWS Cloud Security Operations Centre

---

## AWS Security Hub (Finding Aggregation)

### Why Selected
Security Hub is the native AWS compliance and finding aggregation service. It normalises findings from GuardDuty, Inspector, Macie, Access Analyzer, and third-party tools into the AWS Security Finding Format (ASFF), providing a single compliance posture across CIS AWS Foundations v1.4, FSBP, and NIST 800-53.

### Problem It Solves
Without Security Hub, SOC analysts must check five separate consoles per account. At 5 accounts and 5 services, that is 25 tabs before any investigation starts. Security Hub aggregates all findings cross-account and cross-region into one pane with a numerical compliance score.

### Alternatives Considered
| Alternative | Why Not Selected |
|---|---|
| Splunk SIEM | Significant data egress cost; requires agents; adds SaaS dependency |
| Datadog Cloud SIEM | External data transfer cost; no native AWS IAM integration |
| Manual log review | Not scalable; finding in noise requires dedicated analyst hours |

### Enhancements in This Repo
- **Cross-region finding aggregator** — `aws_securityhub_finding_aggregator` with `ALL_REGIONS` mode
- **Kinesis Firehose export** — all findings streamed to S3 in Parquet for Athena querying
- **Custom actions** — `SendToIR`, `SuppressFinding`, `EnrichFinding` buttons in console

### Well-Architected Alignment
- **Security:** Unified compliance posture; CRITICAL/HIGH alerting with <5-minute latency
- **Operational Excellence:** Single finding queue; EventBridge routing eliminates manual triage
- **Cost Optimization:** $0.001 per finding check; cheaper than SIEM data ingestion at scale

---

## Amazon GuardDuty (Threat Detection + Automation)

### Why Selected
GuardDuty is serverless, agentless ML-powered threat detection. It analyses CloudTrail management events, S3 data events, VPC Flow Logs, DNS query logs, EKS audit logs, and EC2 EBS malware — with no infrastructure to manage. This SOC extends the Landing Zone GuardDuty with automated response Lambdas triggered via EventBridge.

### Automated Responses Built
| GuardDuty Finding Type | Auto-Response | Opt-in Variable |
|---|---|---|
| `Policy:S3/BucketPublicAccess` | Re-enable S3 block-public-access | `auto_remediate_s3_enabled = true` |
| `UnauthorizedAccess:IAMUser/*` | Attach DenyAll + deactivate keys | `auto_disable_iam_enabled = true` |
| `Backdoor:EC2/*`, `Trojan:EC2/*` | Forensic snapshot + network isolation | `auto_isolate_ec2_enabled = true` |

### Design Decision: Disruptive Actions Default to `false`
Automated EC2 isolation and IAM user disablement are disruptive by nature. A false positive would take a production instance offline or lock out an engineer. All disruptive remediations require explicit opt-in via Terraform variable — the safe path is always the default.

### Well-Architected Alignment
- **Security:** ML-based runtime threat detection with near-real-time response
- **Reliability:** Auto-enables on all new Organisation member accounts
- **Cost Optimization:** Volume-based pricing; no compute overhead for monitoring

---

## Amazon Detective (Investigation)

### Why Selected
Detective automatically builds a behaviour graph from CloudTrail, VPC Flow Logs, and GuardDuty findings. When a Security Hub CRITICAL finding triggers the incident response workflow, analysts can follow the Detective link directly to a pre-built investigation view showing the affected entity's activity timeline, peer comparisons, and connected entities — cutting investigation time from hours to minutes.

### Problem It Solves
CloudTrail log analysis is slow. Finding all API calls made by a compromised IAM role in the past 24 hours requires Athena queries that take minutes to run. Detective pre-computes these relationships and presents them as an interactive graph — the analyst clicks, not queries.

### Well-Architected Alignment
- **Operational Excellence:** Reduces MTTR for security investigations
- **Security:** Entity behaviour baselines detect anomalies that rule-based tools miss

---

## AWS Glue + Amazon Athena (CloudTrail Analytics)

### Why Selected
CloudTrail logs in S3 are JSON-compressed files in a partitioned hierarchy. Athena with a Glue catalogue enables SQL queries over petabytes of log data with no data movement, no ETL pipeline, and no server provisioning. Five named queries are pre-built covering every CIS CloudTrail section 4 control.

### Problem It Solves
Manual CloudTrail investigation requires: download logs → decompress → grep → correlate. At organisation scale this is impractical. Athena queries run in seconds against the same S3 bucket the Landing Zone already writes to — zero additional data movement or cost for storage.

### Pre-Built Named Queries
1. **Unauthorized API calls** — last 24 hours, sorted by time
2. **Root account usage** — last 7 days, any region
3. **IAM policy changes** — all create/attach/delete actions
4. **Security group changes** — ingress/egress rule modifications
5. **Console logins with MFA status** — compliance evidence

### Well-Architected Alignment
- **Operational Excellence:** SQL-accessible audit trail; no log download required
- **Cost Optimization:** Pay per query; Glue catalogue is $1/month for metadata
- **Sustainability:** No dedicated compute — queries run on shared Athena fleet

---

## Amazon Kinesis Data Firehose (Finding Export)

### Why Selected
Firehose provides a managed, serverless pipeline from Security Hub findings (via EventBridge) to S3 — with automatic batching, compression (GZIP), dynamic partitioning by date, and KMS encryption. This creates the SIEM-ready data lake consumed by `multi-cloud-governance`.

### Alternatives Considered
| Alternative | Why Not Selected |
|---|---|
| Lambda → S3 direct write | No automatic batching; risk of partial writes under load |
| Kinesis Data Streams | Requires consumer management; adds operational overhead |
| EventBridge → S3 direct | No compression or partitioning support |

### Well-Architected Alignment
- **Reliability:** Managed retry; no data loss on transient S3 errors
- **Cost Optimization:** Compression reduces S3 storage cost by 60–80%

---

## AWS Step Functions (Incident Response Orchestration)

### Why Selected
Step Functions provides a visual, auditable state machine for incident response. Each step is logged with input/output, execution time, and retry history. When an analyst reviews a past incident, they can see exactly which automated steps ran, in what order, and what the response was — a complete audit trail without additional logging code.

### Incident Response Workflow Stages
1. **ClassifyFinding** — Lambda determines CRITICAL/HIGH/MEDIUM/LOW
2. **RouteBySeverity** — Choice state branches to appropriate handler
3. **HandleCritical** — Parallel: CreateOpsItem + NotifyCritical + GatherEvidence
4. **UpdateFindingWorkflow** — Sets Security Hub finding to IN_PROGRESS
5. **IncidentComplete** — Succeed state; execution record available 90 days

### Well-Architected Alignment
- **Reliability:** Built-in retry with exponential backoff for Lambda invocations
- **Operational Excellence:** Visual execution history; zero additional logging code
- **Security:** IAM role scoped only to required step actions

---

## Amazon Macie (Sensitive Data Discovery)

### Why Selected
Macie uses ML to discover PII, credentials, and sensitive data in S3 buckets. For organisations subject to POPIA (South Africa), GDPR (EU), or PCI-DSS, Macie provides automated evidence that sensitive data is classified and monitored. This SOC adds a custom data identifier for South African ID numbers, extending Macie's 75+ built-in managed identifiers.

### Well-Architected Alignment
- **Security:** Automated PII discovery; compliance evidence for POPIA/GDPR
- **Operational Excellence:** Scheduled weekly scans; findings routed to SOC SNS topic

---

## AWS IAM Access Analyzer (External Access Detection)

### Why Selected
Access Analyzer continuously analyses resource-based policies (S3, IAM roles, KMS keys, SQS queues, Lambda, Secrets Manager) and identifies any resource reachable from outside the AWS Organisation. Unlike GuardDuty (which detects active threats), Access Analyzer detects configuration risks before they are exploited.

### Well-Architected Alignment
- **Security:** Preventive control for external access misconfiguration
- **Operational Excellence:** Continuous evaluation; EventBridge routing to SOC alerts

---

## Amazon CloudWatch (SOC Dashboard + Alarms)

### Why Selected
CloudWatch provides the SOC command centre dashboard aggregating nine security metric filters from CloudTrail logs. Each filter corresponds to a CIS AWS Foundations Benchmark Section 4 control. The dashboard is the first screen a SOC analyst opens — a real-time view of security event frequency across all monitored controls.

### Metric Filters Implemented (CIS Section 4)
| Alarm | CIS Control |
|---|---|
| Unauthorized API calls | 4.1 |
| Root account usage | 4.3 |
| Console login without MFA | 4.2 |
| IAM policy changes | 4.4 |
| CloudTrail config changes | 4.5 |
| S3 bucket policy changes | 4.8 |
| Security group changes | 4.10 |
| Network ACL changes | 4.11 |
| KMS key deletion/disablement | 4.7 |

### Well-Architected Alignment
- **Operational Excellence:** Real-time SOC visibility; alarm-to-SNS latency <5 minutes
- **Cost Optimization:** Custom metrics cost $0.30/metric/month — 9 metrics = $2.70/month

---

*Owner: Cloud Security Team | Review: Quarterly*
