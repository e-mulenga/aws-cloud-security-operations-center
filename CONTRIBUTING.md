# Contributing Guide
## AWS Cloud Security Operations Centre

**Portfolio Position 4 of 6** — Changes here affect `multi-cloud-governance` (downstream consumer).

## Critical Rules

- **Never disable auto_remediate without documented justification** — every variable default is a security decision
- **Lambda handlers must be idempotent** — EventBridge may deliver events more than once
- **All destructive remediation requires `auto_*_enabled = true` opt-in** — never auto-enable breaking changes
- **Every finding enrichment must write to the SOC S3 bucket** — immutable audit trail is non-negotiable

## Adding a New Auto-Remediation Lambda

1. Create `lambda/<action-name>/handler.py` — follow the existing patterns
2. Add `data "archive_file"` and `aws_lambda_function` in `modules/guardduty-automation/main.tf`
3. Add EventBridge rule scoped to the specific GuardDuty finding type
4. Add a new `auto_<action>_enabled` variable defaulting to `false`
5. Update `variables.tf`, `README.md`, and `architecture/service-selection-rationale.md`
6. Write an operational runbook entry for the new remediation

## Terraform Standards

- `provider.tf` — both `terraform {}` block and providers; no `versions.tf`
- No hardcoded account IDs, regions, emails, or secrets
- All Lambda zip archives use `data "archive_file"` — never pre-built binaries in git
- `for_each` over `count` for all named resources
- `sensitive = true` on all KMS ARN outputs
