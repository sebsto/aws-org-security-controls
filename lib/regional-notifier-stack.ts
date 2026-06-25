import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import * as path from 'path';
import { EventBridgeRules } from './eventbridge-rules';

export interface RegionalNotifierStackProps extends cdk.StackProps {
  recipientEmail: string;
  senderEmail: string;
  /** Region whose SES is used to send all mail (identities verified once there). */
  sesRegion: string;
}

/**
 * Regional security-notification stack: a Notifier Lambda plus the EventBridge
 * rules that match security events on the regional default bus.
 *
 * Deployed once per region. CloudTrail delivers events to the default bus in the
 * account+region where the API call happened, so these rules must live in each
 * region whose events you want to catch. SES is centralized via SES_REGION.
 */
export class RegionalNotifierStack extends cdk.Stack {
  public readonly notifierLambda: nodejs.NodejsFunction;

  constructor(scope: Construct, id: string, props: RegionalNotifierStackProps) {
    super(scope, id, props);

    // Explicit log group with 30-day retention to keep CloudWatch Logs cost minimal.
    // (The default Lambda log group never expires.)
    const notifierLogGroup = new logs.LogGroup(this, 'NotifierLogGroup', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.notifierLambda = new nodejs.NodejsFunction(this, 'NotifierLambda', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'handler',
      entry: path.join(__dirname, '..', 'lambda', 'notifier', 'handler.ts'),
      logGroup: notifierLogGroup,
      environment: {
        RECIPIENT_EMAIL: props.recipientEmail,
        SENDER_EMAIL: props.senderEmail,
        SES_REGION: props.sesRegion,
      },
      bundling: {
        minify: true,
        sourceMap: true,
      },
    });

    this.notifierLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ses:SendEmail', 'ses:SendRawEmail'],
        resources: ['*'],
      })
    );

    new EventBridgeRules(this, 'EventBridgeRules', {
      notifierLambda: this.notifierLambda,
    });
  }
}
