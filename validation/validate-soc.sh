#!/usr/bin/env bash
# Post-deploy validation for the Cloud Security Operations Centre
# Usage: ENV=prod ORG=acme AWS_REGION=af-south-1 bash validation/validate-soc.sh
set -euo pipefail
: "${ENV:?Required}"; : "${ORG:?Required}"; : "${AWS_REGION:=${AWS_DEFAULT_REGION:-af-south-1}}"
PASS=0; FAIL=0; WARN=0
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

echo "==========================================="
echo " SOC Validation | Org: ${ORG} | Env: ${ENV}"
echo "==========================================="

# Security Hub
echo -e "\n--- Security Hub ---"
SH=$(aws securityhub describe-hub --query 'HubArn' --output text --region "${AWS_REGION}" 2>/dev/null || echo "NONE")
[[ "${SH}" != "NONE" ]] && pass "Security Hub enabled" || fail "Security Hub NOT enabled"

FA=$(aws securityhub list-finding-aggregators --query 'FindingAggregators[0].FindingAggregatorArn' --output text --region "${AWS_REGION}" 2>/dev/null || echo "")
[[ -n "${FA}" ]] && pass "Finding aggregator configured" || warn "No finding aggregator (cross-region may be disabled)"

# GuardDuty
echo -e "\n--- GuardDuty ---"
DID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region "${AWS_REGION}" 2>/dev/null || echo "")
[[ -n "${DID}" && "${DID}" != "None" ]] && pass "GuardDuty detector: ${DID}" || fail "GuardDuty detector NOT found"

# Access Analyzer
echo -e "\n--- IAM Access Analyzer ---"
AA=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text --region "${AWS_REGION}" 2>/dev/null || echo "")
[[ -n "${AA}" && "${AA}" != "None" ]] && pass "Access Analyzer: ${AA}" || fail "Access Analyzer NOT found"

# SOC S3 Bucket
echo -e "\n--- SOC Data Bucket ---"
SOC_BUCKET="${ORG}-soc-data-${ENV}"
if aws s3api head-bucket --bucket "${SOC_BUCKET}" 2>/dev/null; then
  pass "SOC bucket exists: ${SOC_BUCKET}"
  ENC=$(aws s3api get-bucket-encryption --bucket "${SOC_BUCKET}" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "NONE")
  [[ "${ENC}" == "aws:kms" ]] && pass "SOC bucket encrypted with KMS" || fail "SOC bucket NOT encrypted with KMS"
  VER=$(aws s3api get-bucket-versioning --bucket "${SOC_BUCKET}" --query 'Status' --output text 2>/dev/null || echo "NONE")
  [[ "${VER}" == "Enabled" ]] && pass "SOC bucket versioning enabled" || fail "SOC bucket versioning NOT enabled"
else
  fail "SOC bucket NOT found: ${SOC_BUCKET}"
fi

# SNS Topics
echo -e "\n--- SNS Notifications ---"
CRITICAL=$(aws sns list-topics --query "Topics[?contains(TopicArn,'${ORG}-${ENV}-soc-critical')].TopicArn" --output text --region "${AWS_REGION}" 2>/dev/null || echo "")
[[ -n "${CRITICAL}" ]] && pass "Critical alerts topic exists" || fail "Critical alerts topic NOT found"
HIGH=$(aws sns list-topics --query "Topics[?contains(TopicArn,'${ORG}-${ENV}-soc-high')].TopicArn" --output text --region "${AWS_REGION}" 2>/dev/null || echo "")
[[ -n "${HIGH}" ]] && pass "High alerts topic exists" || fail "High alerts topic NOT found"

# Lambda functions
echo -e "\n--- Lambda Remediation Functions ---"
for FN in "finding-enricher" "auto-remediate-s3"; do
  FNAME="${ORG}-${ENV}-${FN}"
  STATUS=$(aws lambda get-function --function-name "${FNAME}" --query 'Configuration.State' --output text --region "${AWS_REGION}" 2>/dev/null || echo "NOT_FOUND")
  [[ "${STATUS}" == "Active" ]] && pass "Lambda active: ${FNAME}" || warn "Lambda not found or inactive: ${FNAME}"
done

# Athena Workgroup
echo -e "\n--- CloudTrail Analytics ---"
WG="${ORG}-${ENV}-soc-workgroup"
WG_STATUS=$(aws athena get-work-group --work-group "${WG}" --query 'WorkGroup.State' --output text --region "${AWS_REGION}" 2>/dev/null || echo "NOT_FOUND")
[[ "${WG_STATUS}" == "ENABLED" ]] && pass "Athena workgroup: ${WG}" || warn "Athena workgroup not found: ${WG}"

# CloudWatch Dashboard
echo -e "\n--- Monitoring ---"
DB="${ORG}-${ENV}-soc-command-centre"
DB_STATUS=$(aws cloudwatch get-dashboard --dashboard-name "${DB}" --query 'DashboardName' --output text --region "${AWS_REGION}" 2>/dev/null || echo "NOT_FOUND")
[[ "${DB_STATUS}" != "NOT_FOUND" ]] && pass "SOC dashboard: ${DB}" || warn "SOC dashboard not found: ${DB}"

echo -e "\n==========================================="
echo " PASS: ${PASS}  WARN: ${WARN}  FAIL: ${FAIL}"
echo "==========================================="
[[ "${FAIL}" -gt 0 ]] && exit 1 || exit 0
