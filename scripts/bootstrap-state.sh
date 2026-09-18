#!/usr/bin/env bash
# Bootstrap S3 + DynamoDB Terraform remote state for SOC
# Usage: ENV=prod ORG=acme AWS_REGION=af-south-1 bash scripts/bootstrap-state.sh
set -euo pipefail
: "${ENV:?Required}"; : "${ORG:?Required}"; : "${AWS_REGION:=${AWS_DEFAULT_REGION:-af-south-1}}"
BUCKET="${ORG}-soc-state-${ENV}"; TABLE="${ORG}-soc-lock-${ENV}"; KMS_ALIAS="alias/soc-state-key-${ENV}"
echo "Bootstrapping: ${BUCKET} / ${TABLE}"
if ! aws kms describe-key --key-id "${KMS_ALIAS}" --region "${AWS_REGION}" &>/dev/null; then
  KEY_ID=$(aws kms create-key --description "SOC state key ${ENV}" --region "${AWS_REGION}" --query 'KeyMetadata.KeyId' --output text)
  aws kms create-alias --alias-name "${KMS_ALIAS}" --target-key-id "${KEY_ID}" --region "${AWS_REGION}"
  aws kms enable-key-rotation --key-id "${KEY_ID}" --region "${AWS_REGION}"
  echo "[✓] KMS key: ${KMS_ALIAS}"
else echo "[✓] KMS key already exists"; fi
if ! aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  aws s3api create-bucket --bucket "${BUCKET}" --region "${AWS_REGION}" --create-bucket-configuration LocationConstraint="${AWS_REGION}"
  aws s3api put-bucket-versioning --bucket "${BUCKET}" --versioning-configuration Status=Enabled
  aws s3api put-public-access-block --bucket "${BUCKET}" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-encryption --bucket "${BUCKET}" --server-side-encryption-configuration "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"${KMS_ALIAS}\"},\"BucketKeyEnabled\":true}]}"
  echo "[✓] S3 bucket: ${BUCKET}"
else echo "[✓] S3 bucket already exists"; fi
if ! aws dynamodb describe-table --table-name "${TABLE}" --region "${AWS_REGION}" &>/dev/null; then
  aws dynamodb create-table --table-name "${TABLE}" --attribute-definitions AttributeName=LockID,AttributeType=S --key-schema AttributeName=LockID,KeyType=HASH --billing-mode PAY_PER_REQUEST --sse-specification Enabled=true,SSEType=KMS --region "${AWS_REGION}"
  aws dynamodb wait table-exists --table-name "${TABLE}" --region "${AWS_REGION}"
  echo "[✓] DynamoDB: ${TABLE}"
else echo "[✓] DynamoDB already exists"; fi
echo "Update environments/${ENV}/backend.tf: bucket=\"${BUCKET}\" dynamodb_table=\"${TABLE}\" kms_key_id=\"${KMS_ALIAS}\""
