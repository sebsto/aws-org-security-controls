import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { EventBridgeRules } from '../lib/eventbridge-rules';

describe('EventBridgeRules construct', () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'TestStack');

    const fn = new lambda.Function(stack, 'TestFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = () => {}'),
    });

    new EventBridgeRules(stack, 'EventBridgeRules', {
      notifierLambda: fn,
    });

    template = Template.fromStack(stack);
  });

  test('contains exactly 17 AWS::Events::Rule resources', () => {
    template.resourceCountIs('AWS::Events::Rule', 17);
  });

  test('contains exactly 17 AWS::Lambda::Permission resources', () => {
    template.resourceCountIs('AWS::Lambda::Permission', 17);
  });

  describe('event patterns', () => {
    test('RootConsoleLogin rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'RootConsoleLogin',
        EventPattern: {
          source: ['aws.signin'],
          'detail-type': ['AWS Console Sign In via CloudTrail'],
          detail: {
            eventName: ['ConsoleLogin'],
            userIdentity: {
              type: ['Root'],
            },
          },
        },
      });
    });

    test('ConsoleLoginNoMFA rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'ConsoleLoginNoMFA',
        EventPattern: {
          source: ['aws.signin'],
          'detail-type': ['AWS Console Sign In via CloudTrail'],
          detail: {
            eventName: ['ConsoleLogin'],
            additionalEventData: {
              MFAUsed: ['No'],
            },
          },
        },
      });
    });

    test('LoginFailure rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'LoginFailure',
        EventPattern: {
          source: ['aws.signin'],
          'detail-type': ['AWS Console Sign In via CloudTrail'],
          detail: {
            eventName: ['ConsoleLogin'],
            responseElements: {
              ConsoleLogin: ['Failure'],
            },
          },
        },
      });
    });

    test('CloudTrailStopLogging rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'CloudTrailStopLogging',
        EventPattern: {
          source: ['aws.cloudtrail'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['StopLogging'],
          },
        },
      });
    });

    test('CloudTrailDeleteTrail rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'CloudTrailDeleteTrail',
        EventPattern: {
          source: ['aws.cloudtrail'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['DeleteTrail'],
          },
        },
      });
    });

    test('CloudTrailUpdateTrail rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'CloudTrailUpdateTrail',
        EventPattern: {
          source: ['aws.cloudtrail'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['UpdateTrail'],
          },
        },
      });
    });

    test('CloudTrailPutEventSelectors rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'CloudTrailPutEventSelectors',
        EventPattern: {
          source: ['aws.cloudtrail'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['PutEventSelectors'],
          },
        },
      });
    });

    test('IamUserCreated rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'IamUserCreated',
        EventPattern: {
          source: ['aws.iam'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['CreateUser'],
          },
        },
      });
    });

    test('AccessKeyCreated rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'AccessKeyCreated',
        EventPattern: {
          source: ['aws.iam'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['CreateAccessKey'],
          },
        },
      });
    });

    test('LoginProfileAttached rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'LoginProfileAttached',
        EventPattern: {
          source: ['aws.iam'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['CreateLoginProfile'],
          },
        },
      });
    });

    test('MfaDeviceDeactivated rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'MfaDeviceDeactivated',
        EventPattern: {
          source: ['aws.iam'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['DeactivateMFADevice'],
          },
        },
      });
    });

    test('SsoUserCreated rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'SsoUserCreated',
        EventPattern: {
          source: ['aws.sso-directory'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['CreateUser'],
          },
        },
      });
    });

    test('SecurityGroupIngressOpened rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'SecurityGroupIngressOpened',
        EventPattern: {
          source: ['aws.ec2'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventName: ['AuthorizeSecurityGroupIngress'],
          },
        },
      });
    });

    test('CostAnomalyDetected rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'CostAnomalyDetected',
        EventPattern: {
          source: ['aws.ce'],
          'detail-type': ['AWS Cost Anomaly Detection Alert'],
        },
      });
    });

    test('BudgetThresholdBreached rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'BudgetThresholdBreached',
        EventPattern: {
          source: ['aws.budgets'],
          'detail-type': ['Budget Notification'],
        },
      });
    });

    test('AccessAnalyzerFinding rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'AccessAnalyzerFinding',
        EventPattern: {
          source: ['aws.access-analyzer'],
          'detail-type': ['Access Analyzer Finding'],
        },
      });
    });

    test('OrganizationEvent rule has correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Name: 'OrganizationEvent',
        EventPattern: {
          source: ['aws.organizations'],
          'detail-type': ['AWS API Call via CloudTrail'],
        },
      });
    });
  });

  describe('targets and retry configuration', () => {
    test('each rule targets the Notifier Lambda with retry policy', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Targets: Match.arrayWith([
          Match.objectLike({
            Arn: Match.anyValue(),
            RetryPolicy: {
              MaximumRetryAttempts: 3,
              MaximumEventAgeInSeconds: 86400,
            },
          }),
        ]),
      });
    });

    test('all 17 rules have targets with retry configuration', () => {
      const rules = template.findResources('AWS::Events::Rule');
      const ruleKeys = Object.keys(rules);
      expect(ruleKeys.length).toBe(17);

      for (const key of ruleKeys) {
        const rule = rules[key];
        const targets = rule.Properties.Targets;
        expect(targets).toBeDefined();
        expect(targets.length).toBeGreaterThan(0);
        expect(targets[0].RetryPolicy).toEqual({
          MaximumRetryAttempts: 3,
          MaximumEventAgeInSeconds: 86400,
        });
      }
    });
  });
});
