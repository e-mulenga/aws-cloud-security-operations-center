# Security Policy
## AWS Cloud Security Operations Centre

## Reporting a Vulnerability

**Email:** security@[your-org].com  
**Subject:** `[SECURITY] aws-cloud-security-operations-center — <description>`

Do NOT open public GitHub issues for security vulnerabilities.
Acknowledge within 48 hours. Remediation within 5 business days.

## Security Controls in This Repository

| Control | Implementation |
|---|---|
| No hardcoded secrets | All credentials via Secrets Manager / SSM |
| Encrypted SOC data store | S3 KMS CMK, TLS-only policy, versioning, WORM (deny-delete) |
| Encrypted finding stream | Kinesis Firehose with KMS CMK |
| Lambda least-privilege | Scoped IAM policies per Lambda function |
| Auto-remediation opt-in | All disruptive actions default to `false` |
| Audit trail | Every remediation logged to SOC S3 bucket |
| OIDC GitHub Actions | No long-lived AWS keys in CI/CD |

## Supported Versions

| Branch | Security Fixes |
|---|---|
| `main` | ✅ Yes |
| `develop` | ✅ Yes |
| Feature branches | ❌ Merge to develop first |
