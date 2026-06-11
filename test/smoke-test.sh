#!/bin/bash
#
# Smoke test for Org Security Controls stack
# Run from the project root after deployment
#
# Profiles:
#   seb     = management account (401955065246)
#   maxi80  = member account (743602823695)
#
set -e

MGMT_PROFILE="seb"
MEMBER_PROFILE="maxi80"
REGION="eu-west-1"
UNAPPROVED_REGION="ap-southeast-1"
WATCHDOG_FUNCTION="OrgSecurityControlsStack-WatchdogLambdaCF2B57E4-aZC0GGm8a0H6"
X86_AMI="ami-0d36f874f92143e29"
VPC_ID="vpc-7672c012"

echo "============================================"
echo "  Org Security Controls - Smoke Test"
echo "============================================"
echo ""

# ─── TEST 1: SCP - Region Restriction ──────────────────────────────────────────
echo "▶ Test 1: SCP - Region restriction (unapproved region)"
echo "  Attempting ec2:DescribeInstances in ${UNAPPROVED_REGION} from member account..."
if aws ec2 describe-instances --region $UNAPPROVED_REGION --profile $MEMBER_PROFILE 2>&1 | grep -q "explicit deny"; then
  echo "  ✅ PASS - Denied by SCP (region restriction)"
else
  echo "  ❌ FAIL - Request was not denied"
fi
echo ""

# ─── TEST 2: SCP - EC2 Instance Type Restriction ──────────────────────────────
echo "▶ Test 2: SCP - EC2 type restriction (blocked type: m5.large)"
echo "  Attempting ec2:RunInstances with m5.large in ${REGION} from member account..."
if aws ec2 run-instances --instance-type m5.large --image-id $X86_AMI --dry-run \
  --region $REGION --profile $MEMBER_PROFILE 2>&1 | grep -q "denied\|not authorized\|UnauthorizedOperation"; then
  echo "  ✅ PASS - Denied by SCP (EC2 type restriction)"
else
  echo "  ❌ FAIL - Request was not denied"
fi
echo ""

# ─── TEST 3: SCP - IAM User Creation ──────────────────────────────────────────
echo "▶ Test 3: SCP - IAM user creation denial"
echo "  Attempting iam:CreateUser from member account..."
if aws iam create-user --user-name test-scp-block --profile $MEMBER_PROFILE 2>&1 | grep -q "denied\|not authorized"; then
  echo "  ✅ PASS - Denied by SCP"
else
  echo "  ❌ FAIL - User was created (cleaning up...)"
  aws iam delete-user --user-name test-scp-block --profile $MEMBER_PROFILE 2>/dev/null
fi
echo ""

# ─── TEST 4: SCP - CloudTrail Tampering ────────────────────────────────────────
echo "▶ Test 4: SCP - CloudTrail tampering prevention"
echo "  Attempting cloudtrail:StopLogging from member account..."
if aws cloudtrail stop-logging --name nonexistent-trail --region $REGION --profile $MEMBER_PROFILE 2>&1 | grep -q "denied\|not authorized"; then
  echo "  ✅ PASS - Denied by SCP"
else
  echo "  ❌ FAIL - Request was not denied"
fi
echo ""

# ─── TEST 5: EventBridge Notifier ──────────────────────────────────────────────
echo "▶ Test 5: EventBridge notifier (trigger SecurityGroupIngress event)"
echo "  Creating security group in management account..."
SG_ID=$(aws ec2 create-security-group \
  --group-name smoke-test-alert-$(date +%s) \
  --description "smoke test - will be deleted" \
  --vpc-id $VPC_ID \
  --region $REGION --profile $MGMT_PROFILE \
  --query 'GroupId' --output text)

echo "  Security group: $SG_ID"
echo "  Adding ingress rule (0.0.0.0/0:22)..."
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 \
  --region $REGION --profile $MGMT_PROFILE > /dev/null

echo "  ✅ Event triggered. Check your email within 1-5 minutes."
echo "  Cleaning up security group..."
aws ec2 delete-security-group --group-id $SG_ID --region $REGION --profile $MGMT_PROFILE
echo ""

# ─── TEST 6: Watchdog Lambda Manual Invocation ─────────────────────────────────
echo "▶ Test 6: Watchdog Lambda manual invocation"
echo "  Invoking $WATCHDOG_FUNCTION..."
aws lambda invoke \
  --function-name $WATCHDOG_FUNCTION \
  --payload '{}' \
  --region $REGION --profile $MGMT_PROFILE \
  /tmp/watchdog-output.json > /dev/null 2>&1

if [ $? -eq 0 ]; then
  echo "  ✅ Lambda invoked successfully."
  echo "  Response:"
  cat /tmp/watchdog-output.json | python3 -m json.tool 2>/dev/null || cat /tmp/watchdog-output.json
  echo ""
  echo "  Check your email for the execution report."
else
  echo "  ❌ FAIL - Lambda invocation failed"
fi
echo ""

# ─── SUMMARY ───────────────────────────────────────────────────────────────────
echo "============================================"
echo "  Summary"
echo "============================================"
echo ""
echo "  Tests 1-4: SCP enforcement (DenyServices policy)"
echo ""
echo "  Test 5: Check email for SecurityGroupIngress alert"
echo "  Test 6: Check email for Watchdog execution report"
echo ""
echo "  NOTE: The Watchdog will report role assumption failure for"
echo "  account 743602823695 because OrganizationAccountAccessRole"
echo "  does not exist there yet (invited account)."
echo "============================================"
