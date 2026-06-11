# Org Security Controls

AWS CDK project implementing organization-wide security guardrails, real-time security notifications, and automated cost control.

---

## Prerequisites (one-time setup)

Before the first deployment, run these commands from the management account:

```bash
# 1. Enable SCPs on the organization root
aws organizations enable-policy-type \
  --root-id <YOUR_ROOT_ID> \
  --policy-type SERVICE_CONTROL_POLICY \
  --profile <YOUR_PROFILE>

# 2. Enable CloudTrail trusted service access for the organization
aws organizations enable-aws-service-access \
  --service-principal cloudtrail.amazonaws.com \
  --profile <YOUR_PROFILE>

# 3. Verify SES sender and recipient emails in the deployment region
aws ses verify-email-identity --email-address <SENDER_EMAIL> --profile <YOUR_PROFILE>
aws ses verify-email-identity --email-address <RECIPIENT_EMAIL> --profile <YOUR_PROFILE>

# 4. Bootstrap CDK in the deployment region
npx cdk bootstrap --profile <YOUR_PROFILE>

# 5. Copy .env.sample to .env and fill in your values
cp .env.sample .env
```

---

## ⚠️ When a New Account Joins the Organization

SCPs, the organization trail, and EventBridge rules apply automatically. However, the **Watchdog Lambda** needs a cross-account role to operate. Follow these steps:

### Accounts created via `CreateAccount` (AWS Organizations)

Nothing to do. AWS automatically provisions `OrganizationAccountAccessRole` in the new account.

### Accounts invited via `InviteAccountToOrganization`

The role is **not** created automatically. After the account accepts the invitation:

1. Sign into the new member account as an administrator
2. Create an IAM role named `OrganizationAccountAccessRole` with:
   - **Trust policy**: Allow the management account to assume it
   - **Permissions**: Attach the `AdministratorAccess` managed policy (or a scoped-down policy covering EC2, ECS, RDS, EIP, ELB, CloudWatch Logs, and STS)
3. Verify the Watchdog Lambda can assume the role:
   ```bash
   aws sts assume-role \
     --role-arn arn:aws:iam::<NEW_ACCOUNT_ID>:role/OrganizationAccountAccessRole \
     --role-session-name test \
     --profile <YOUR_PROFILE>
   ```
4. The new account will be picked up automatically on the next Friday Watchdog run

### What applies immediately (no manual steps)

| Component | Coverage |
|-----------|----------|
| DenyServices SCP | ✅ Inherited from org root |
| EnforceMFA SCP | ✅ Inherited from org root |
| Organization CloudTrail | ✅ Captures all accounts |
| EventBridge notifications | ✅ Events flow from org trail |
| Watchdog Lambda | ⚠️ Requires role (see above) |

---

## Architecture

- **SCPs**: 2 policies (DenyServices + EnforceMFA) attached to the organization root
- **Organization Trail**: Captures management events across all accounts → default EventBridge bus
- **EventBridge Rules**: 17 rules with precise pattern matching → Notifier Lambda (SES email)
- **Watchdog Lambda**: Friday schedule, assumes into member accounts, stops idle resources, reports waste

## Deployment

```bash
npx cdk deploy --profile <YOUR_PROFILE>
```

## Test Plan

### SCP Verification

SCPs only apply to member accounts. To test, you need a role or credentials in the member account. If `OrganizationAccountAccessRole` is not set up yet (invited accounts), SCP enforcement is still active — you just can't test it via CLI from the management account.

### EventBridge Notifier Verification

Trigger a real security event and verify an email arrives:

1. Create and immediately delete a security group with an ingress rule (generates `AuthorizeSecurityGroupIngress` event)
2. Wait 1–5 minutes for the email

### Watchdog Lambda Verification

Invoke the Watchdog Lambda manually and check for the execution report email.

### Quick Smoke Test Script

See `test/smoke-test.sh` for a ready-to-run script that verifies the Notifier and Watchdog are functional.

**Pass criteria:**
- EventBridge test → alert email received within 5 minutes
- Watchdog invocation → execution report email received
- SCP tests (if member account access available) → AccessDenied on blocked actions

Environment-specific values (`.env` file, not committed):
- `CDK_DEFAULT_ACCOUNT` — Management account ID
- `CDK_DEFAULT_REGION` — Deployment region
- `ORGANIZATION_ID` — AWS Organization ID
- `ORGANIZATION_ROOT_ID` — Organization root ID
- `RECIPIENT_EMAIL` — Alert recipient
- `SENDER_EMAIL` — SES verified sender

Policy parameters (`cdk.json`, committed):
- `approvedRegions` — Allowed regions for resource deployment
- `allowedRdsClasses` — Permitted RDS instance classes
- `allowedEc2Types` — Permitted EC2 instance types (allowlist)
- `bedrockAllowedPrincipals` — ARNs allowed to use Bedrock
- `watchdogScheduleHour` — UTC hour for Friday Watchdog run


## Configuration

Environment-specific values (`.env` file, not committed):
- `CDK_DEFAULT_ACCOUNT` — Management account ID
- `CDK_DEFAULT_REGION` — Deployment region
- `ORGANIZATION_ID` — AWS Organization ID
- `ORGANIZATION_ROOT_ID` — Organization root ID
- `RECIPIENT_EMAIL` — Alert recipient
- `SENDER_EMAIL` — SES verified sender

Policy parameters (`cdk.json`, committed):
- `approvedRegions` — Allowed regions for resource deployment
- `allowedRdsClasses` — Permitted RDS instance classes
- `allowedEc2Types` — Permitted EC2 instance types (allowlist)
- `bedrockAllowedPrincipals` — ARNs allowed to use Bedrock
- `watchdogScheduleHour` — UTC hour for Friday Watchdog run
