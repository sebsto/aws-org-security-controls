import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { Duration } from 'aws-cdk-lib';
import { EventBridgeRulesProps } from './types';

/**
 * CDK Construct that defines 17 EventBridge rules on the default bus
 * for real-time security event notifications.
 *
 * Each rule matches a specific event pattern and targets the Notifier Lambda
 * with retry policy: 3 attempts, 24h retention.
 */
export class EventBridgeRules extends Construct {
  constructor(scope: Construct, id: string, props: EventBridgeRulesProps) {
    super(scope, id);

    const lambdaTarget = new targets.LambdaFunction(props.notifierLambda, {
      retryAttempts: 3,
      maxEventAge: Duration.hours(24),
    });

    // Rule 1: Root Console Login
    new events.Rule(this, 'RootConsoleLogin', {
      ruleName: 'RootConsoleLogin',
      eventPattern: {
        source: ['aws.signin'],
        detailType: ['AWS Console Sign In via CloudTrail'],
        detail: {
          eventName: ['ConsoleLogin'],
          userIdentity: {
            type: ['Root'],
          },
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 2: Console Login without MFA
    new events.Rule(this, 'ConsoleLoginNoMFA', {
      ruleName: 'ConsoleLoginNoMFA',
      eventPattern: {
        source: ['aws.signin'],
        detailType: ['AWS Console Sign In via CloudTrail'],
        detail: {
          eventName: ['ConsoleLogin'],
          additionalEventData: {
            MFAUsed: ['No'],
          },
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 3: Login Failure
    new events.Rule(this, 'LoginFailure', {
      ruleName: 'LoginFailure',
      eventPattern: {
        source: ['aws.signin'],
        detailType: ['AWS Console Sign In via CloudTrail'],
        detail: {
          eventName: ['ConsoleLogin'],
          responseElements: {
            ConsoleLogin: ['Failure'],
          },
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 4: CloudTrail Stop Logging
    new events.Rule(this, 'CloudTrailStopLogging', {
      ruleName: 'CloudTrailStopLogging',
      eventPattern: {
        source: ['aws.cloudtrail'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['StopLogging'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 5: CloudTrail Delete Trail
    new events.Rule(this, 'CloudTrailDeleteTrail', {
      ruleName: 'CloudTrailDeleteTrail',
      eventPattern: {
        source: ['aws.cloudtrail'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['DeleteTrail'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 6: CloudTrail Update Trail
    new events.Rule(this, 'CloudTrailUpdateTrail', {
      ruleName: 'CloudTrailUpdateTrail',
      eventPattern: {
        source: ['aws.cloudtrail'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['UpdateTrail'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 7: CloudTrail Put Event Selectors
    new events.Rule(this, 'CloudTrailPutEventSelectors', {
      ruleName: 'CloudTrailPutEventSelectors',
      eventPattern: {
        source: ['aws.cloudtrail'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['PutEventSelectors'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 8: IAM User Created
    new events.Rule(this, 'IamUserCreated', {
      ruleName: 'IamUserCreated',
      eventPattern: {
        source: ['aws.iam'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['CreateUser'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 9: Access Key Created
    new events.Rule(this, 'AccessKeyCreated', {
      ruleName: 'AccessKeyCreated',
      eventPattern: {
        source: ['aws.iam'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['CreateAccessKey'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 10: Login Profile Attached
    new events.Rule(this, 'LoginProfileAttached', {
      ruleName: 'LoginProfileAttached',
      eventPattern: {
        source: ['aws.iam'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['CreateLoginProfile'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 11: MFA Device Deactivated
    new events.Rule(this, 'MfaDeviceDeactivated', {
      ruleName: 'MfaDeviceDeactivated',
      eventPattern: {
        source: ['aws.iam'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['DeactivateMFADevice'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 12: SSO User Created
    new events.Rule(this, 'SsoUserCreated', {
      ruleName: 'SsoUserCreated',
      eventPattern: {
        source: ['aws.sso-directory'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['CreateUser'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 13: Security Group Ingress Opened
    new events.Rule(this, 'SecurityGroupIngressOpened', {
      ruleName: 'SecurityGroupIngressOpened',
      eventPattern: {
        source: ['aws.ec2'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['AuthorizeSecurityGroupIngress'],
        },
      },
      targets: [lambdaTarget],
    });

    // Rule 14: Cost Anomaly Detected
    new events.Rule(this, 'CostAnomalyDetected', {
      ruleName: 'CostAnomalyDetected',
      eventPattern: {
        source: ['aws.ce'],
        detailType: ['AWS Cost Anomaly Detection Alert'],
      },
      targets: [lambdaTarget],
    });

    // Rule 15: Budget Threshold Breached
    new events.Rule(this, 'BudgetThresholdBreached', {
      ruleName: 'BudgetThresholdBreached',
      eventPattern: {
        source: ['aws.budgets'],
        detailType: ['Budget Notification'],
      },
      targets: [lambdaTarget],
    });

    // Rule 16: Access Analyzer Finding
    new events.Rule(this, 'AccessAnalyzerFinding', {
      ruleName: 'AccessAnalyzerFinding',
      eventPattern: {
        source: ['aws.access-analyzer'],
        detailType: ['Access Analyzer Finding'],
      },
      targets: [lambdaTarget],
    });

    // Rule 17: Organization Event
    new events.Rule(this, 'OrganizationEvent', {
      ruleName: 'OrganizationEvent',
      eventPattern: {
        source: ['aws.organizations'],
        detailType: ['AWS API Call via CloudTrail'],
      },
      targets: [lambdaTarget],
    });
  }
}
