#!/usr/bin/env node
import 'source-map-support/register';
import * as dotenv from 'dotenv';
import * as cdk from 'aws-cdk-lib';
import { OrgSecurityControlsStack } from '../lib/org-security-controls-stack';

dotenv.config();

const app = new cdk.App();
new OrgSecurityControlsStack(app, 'OrgSecurityControlsStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
