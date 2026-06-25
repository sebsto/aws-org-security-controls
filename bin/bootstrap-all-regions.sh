#!/bin/bash
#
# One-off CDK bootstrap for every region the notifier deploys into.
#
# The regional notifier stacks are deployed to all enabled regions (see
# REGIONS below — must match notifierRegions in bin/app.ts). Each region needs
# its own CDK bootstrap stack before `cdk deploy` can target it.
#
# Usage:
#   AWS_PROFILE=default bash bin/bootstrap-all-regions.sh
#
# Env:
#   AWS_PROFILE  AWS profile / credentials to use (default: current environment)
#   ACCOUNT      Override the account id (default: resolved via sts get-caller-identity)
#
set -euo pipefail

# Keep this list in sync with notifierRegions in bin/app.ts.
REGIONS=(
  us-east-1 us-east-2 us-west-1 us-west-2
  ca-central-1 sa-east-1
  eu-west-1 eu-west-2 eu-west-3 eu-central-1 eu-north-1
  ap-south-1 ap-northeast-1 ap-northeast-2 ap-northeast-3
  ap-southeast-1 ap-southeast-2
)

ACCOUNT="${ACCOUNT:-$(aws sts get-caller-identity --query Account --output text)}"
echo "Bootstrapping account ${ACCOUNT} in ${#REGIONS[@]} regions..."

failed=()
for region in "${REGIONS[@]}"; do
  echo
  echo "=== cdk bootstrap aws://${ACCOUNT}/${region} ==="
  if npx cdk bootstrap "aws://${ACCOUNT}/${region}"; then
    echo "  ✓ ${region}"
  else
    echo "  ✗ ${region} FAILED"
    failed+=("${region}")
  fi
done

echo
if [ ${#failed[@]} -eq 0 ]; then
  echo "All ${#REGIONS[@]} regions bootstrapped successfully."
else
  echo "Bootstrap failed in: ${failed[*]}"
  exit 1
fi
