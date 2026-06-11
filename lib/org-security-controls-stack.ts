import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { Construct } from 'constructs';
import * as path from 'path';
import { ScpEngine } from './scp-engine';
import { OrgTrail } from './org-trail';
import { EventBridgeRules } from './eventbridge-rules';

export class OrgSecurityControlsStack extends cdk.Stack {
  public readonly notifierLambda: nodejs.NodejsFunction;
  public readonly watchdogLambda: nodejs.NodejsFunction;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Read configuration from CDK context
    const approvedRegions = this.node.tryGetContext('approvedRegions') as string[];
    const allowedRdsClasses = this.node.tryGetContext('allowedRdsClasses') as string[];
    const allowedEc2Types = this.node.tryGetContext('allowedEc2Types') as string[];
    const bedrockAllowedPrincipals = this.node.tryGetContext('bedrockAllowedPrincipals') as string[];
    const watchdogScheduleHour = this.node.tryGetContext('watchdogScheduleHour') as number;

    // Read environment-specific values from process.env (loaded via .env)
    const organizationId = process.env.ORGANIZATION_ID!;
    const organizationRootId = process.env.ORGANIZATION_ROOT_ID!;
    const recipientEmail = process.env.RECIPIENT_EMAIL!;
    const senderEmail = process.env.SENDER_EMAIL!;

    // Instantiate SCP Engine construct
    new ScpEngine(this, 'ScpEngine', {
      approvedRegions,
      allowedRdsClasses,
      allowedEc2Types,
      bedrockAllowedPrincipals,
      organizationRootId,
    });

    // Instantiate Organization Trail construct
    new OrgTrail(this, 'OrgTrail', {
      organizationId,
    });

    // Create Notifier Lambda
    this.notifierLambda = new nodejs.NodejsFunction(this, 'NotifierLambda', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'handler',
      entry: path.join(__dirname, '..', 'lambda', 'notifier', 'handler.ts'),
      environment: {
        RECIPIENT_EMAIL: recipientEmail,
        SENDER_EMAIL: senderEmail,
      },
      bundling: {
        minify: true,
        sourceMap: true,
      },
    });

    // Grant SES send permissions to Notifier Lambda
    this.notifierLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ses:SendEmail', 'ses:SendRawEmail'],
        resources: ['*'],
      })
    );

    // Create Watchdog Lambda
    this.watchdogLambda = new nodejs.NodejsFunction(this, 'WatchdogLambda', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'handler',
      entry: path.join(__dirname, '..', 'lambda', 'watchdog', 'handler.ts'),
      timeout: cdk.Duration.seconds(900),
      environment: {
        RECIPIENT_EMAIL: recipientEmail,
        SENDER_EMAIL: senderEmail,
        APPROVED_REGIONS: approvedRegions.join(','),
        CROSS_ACCOUNT_ROLE_NAME: 'OrganizationAccountAccessRole',
        MANAGEMENT_ACCOUNT_ID: this.account,
      },
      bundling: {
        minify: true,
        sourceMap: true,
      },
    });

    // Grant SES send permissions to Watchdog Lambda
    this.watchdogLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ses:SendEmail', 'ses:SendRawEmail'],
        resources: ['*'],
      })
    );

    // Grant Organizations ListAccounts permission to Watchdog Lambda
    this.watchdogLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['organizations:ListAccounts'],
        resources: ['*'],
      })
    );

    // Grant STS AssumeRole permission to Watchdog Lambda
    this.watchdogLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRole'],
        resources: ['*'],
      })
    );

    // Instantiate EventBridge Rules construct with Notifier Lambda
    new EventBridgeRules(this, 'EventBridgeRules', {
      notifierLambda: this.notifierLambda,
    });

    // Create EventBridge scheduled rule for Watchdog Lambda (Friday cron)
    const watchdogScheduleRule = new events.Rule(this, 'WatchdogScheduleRule', {
      ruleName: 'WatchdogWeeklySchedule',
      schedule: events.Schedule.expression(`cron(0 ${watchdogScheduleHour} ? * FRI *)`),
    });

    watchdogScheduleRule.addTarget(new targets.LambdaFunction(this.watchdogLambda));
  }
}
