# AWS Cloud Security Operations Center
# Athena Query Library

---

## Unauthorized API Calls

```sql
SELECT
  eventtime,
  eventname,
  eventsource,
  errorcode,
  useridentity.arn
FROM cloudtrail_logs
WHERE errorcode IN (
  'AccessDenied',
  'UnauthorizedOperation',
  'AuthFailure'
)
ORDER BY eventtime DESC;
```

---

## Root Account Usage

```sql
SELECT
  eventtime,
  eventname,
  sourceipaddress
FROM cloudtrail_logs
WHERE useridentity.type = 'Root'
ORDER BY eventtime DESC;
```

---

## Console Logins

```sql
SELECT
  eventtime,
  useridentity.username,
  sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
ORDER BY eventtime DESC;
```

---

## IAM Changes

```sql
SELECT
  eventtime,
  eventname,
  useridentity.arn
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
ORDER BY eventtime DESC;
```

---

## Security Group Changes

```sql
SELECT
  eventtime,
  eventname,
  sourceipaddress
FROM cloudtrail_logs
WHERE eventsource = 'ec2.amazonaws.com'
ORDER BY eventtime DESC;
```

---

## GuardDuty Findings

```sql
SELECT *
FROM securityhub_findings
WHERE severity_label IN ('HIGH', 'CRITICAL')
ORDER BY updated_at DESC;
```