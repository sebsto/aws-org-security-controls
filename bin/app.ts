#!/usr/bin/env node
import 'source-map-support/register';
import * as dotenv from 'dotenv';
import * as cdk from 'aws-cdk-lib';
import { OrgSecurityControlsStack } from '../lib/org-security-controls-stack';
import { RegionalNotifierStack } from '../lib/regional-notifier-stack';

dotenv.config();

const app = new cdk.App();

const account = process.env.CDK_DEFAULT_ACCOUNT;
const recipientEmail = process.env.RECIPIENT_EMAIL!;
const senderEmail = process.env.SENDER_EMAIL!;

// All mail is sent through SES in this single region, so identities only need
// verifying once even though the Notifier runs in every region.
const sesRegion = process.env.SES_REGION ?? process.env.CDK_DEFAULT_REGION ?? 'us-east-1';

// Regions to deploy the regional notifier (Notifier Lambda + EventBridge rules) into.
// CloudTrail delivers events to the default bus in the region where the call happened,
// so global events (root login, IAM, Organizations) only appear in us-east-1, while
// regional events appear in their own region. The management account is NOT constrained
// by the region SCP, so cover all reachable regions to catch unexpected-region activity.
//
// Limited to regions where STS is activated for this account: CDK assumes a per-region
// bootstrap deploy-role via the regional STS endpoint, and regions with STS deactivated
// throw RegionDisabledException (CDK warns and falls back to caller creds). The omitted
// regions below are enabled-by-default but have regional STS turned off for this account.
const notifierRegions = (
  app.node.tryGetContext('notifierRegions') as string[] | undefined
) ?? [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-3', 'eu-central-1',
];

// Global stack: SCP + Organization CloudTrail + Watchdog. Deployed once.
// Must run in the SES region so the Watchdog's SES identities resolve there too.
const globalStack = new OrgSecurityControlsStack(app, 'OrgSecurityControlsStack', {
  env: { account, region: sesRegion },
  sesRegion,
});

// Regional notifier stacks: Notifier Lambda + 18 EventBridge rules, one per region.
// Each depends on the global stack so `cdk deploy --all` provisions the SCP and the
// organization trail (which feeds events to every regional default bus) first.
for (const region of notifierRegions) {
  const regionalStack = new RegionalNotifierStack(app, `OrgSecurityNotifier-${region}`, {
    env: { account, region },
    recipientEmail,
    senderEmail,
    sesRegion,
  });
  regionalStack.addDependency(globalStack);
}
