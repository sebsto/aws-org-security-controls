import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { OrgSecurityControlsStack } from '../lib/org-security-controls-stack';
import { RegionalNotifierStack } from '../lib/regional-notifier-stack';

describe('OrgSecurityControlsStack CDK Assertions', () => {
  let template: Template;

  beforeAll(() => {
    // Set environment variables for test (simulates .env loading)
    process.env.ORGANIZATION_ID = 'o-testorg123';
    process.env.ORGANIZATION_ROOT_ID = 'r-test';
    process.env.RECIPIENT_EMAIL = 'security@example.com';
    process.env.SENDER_EMAIL = 'noreply@example.com';

    const app = new cdk.App({
      context: {
        approvedRegions: ['eu-west-1', 'eu-west-3', 'eu-central-1', 'us-east-1'],
        allowedRdsClasses: ['db.t3.micro', 'db.t3.small', 'db.t4g.micro', 'db.t4g.small'],
        allowedEc2Types: ['t4g.nano', 't4g.micro'],
        bedrockAllowedPrincipals: [],
        watchdogScheduleHour: 18,
      },
    });

    const stack = new OrgSecurityControlsStack(app, 'TestStack', {
      env: { account: '123456789012', region: 'us-east-1' },
      sesRegion: 'us-east-1',
    });
    template = Template.fromStack(stack);
  });

  describe('Resource counts', () => {
    test('template has exactly 1 AWS::Organizations::Policy resource', () => {
      template.resourceCountIs('AWS::Organizations::Policy', 1);
    });

    test('template has 1 AWS::CloudTrail::Trail resource', () => {
      template.resourceCountIs('AWS::CloudTrail::Trail', 1);
    });

    test('template has 1 AWS::S3::Bucket resource', () => {
      template.resourceCountIs('AWS::S3::Bucket', 1);
    });

    test('template has 1 AWS::Events::Rule resource (the Watchdog scheduled rule)', () => {
      template.resourceCountIs('AWS::Events::Rule', 1);
    });

    test('template has 1 AWS::Lambda::Function resource (Watchdog only)', () => {
      template.resourceCountIs('AWS::Lambda::Function', 1);
    });
  });

  describe('Watchdog Lambda environment variables', () => {
    test('has RECIPIENT_EMAIL, SENDER_EMAIL, SES_REGION, APPROVED_REGIONS, and CROSS_ACCOUNT_ROLE_NAME', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: Match.objectLike({
            RECIPIENT_EMAIL: 'security@example.com',
            SENDER_EMAIL: 'noreply@example.com',
            SES_REGION: 'us-east-1',
            APPROVED_REGIONS: 'eu-west-1,eu-west-3,eu-central-1,us-east-1',
            CROSS_ACCOUNT_ROLE_NAME: 'OrganizationAccountAccessRole',
          }),
        },
      });
    });
  });

  describe('Watchdog Lambda timeout', () => {
    test('has timeout of 900 seconds', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Timeout: 900,
      });
    });

    test('Watchdog log group has 30-day retention', () => {
      template.hasResourceProperties('AWS::Logs::LogGroup', {
        RetentionInDays: 30,
      });
    });
  });

  describe('Scheduled rule', () => {
    test('has a ScheduleExpression containing FRI', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        ScheduleExpression: Match.stringLikeRegexp('.*FRI.*'),
      });
    });
  });

  describe('IAM permissions', () => {
    test('includes SES access policy for Lambdas', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['ses:SendEmail', 'ses:SendRawEmail'],
              Effect: 'Allow',
              Resource: '*',
            }),
          ]),
        },
      });
    });

    test('includes organizations:ListAccounts permission for Watchdog Lambda', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 'organizations:ListAccounts',
              Effect: 'Allow',
              Resource: '*',
            }),
          ]),
        },
      });
    });

    test('includes sts:AssumeRole permission for Watchdog Lambda', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 'sts:AssumeRole',
              Effect: 'Allow',
              Resource: '*',
            }),
          ]),
        },
      });
    });
  });
});

describe('RegionalNotifierStack CDK Assertions', () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new RegionalNotifierStack(app, 'TestNotifier', {
      env: { account: '123456789012', region: 'eu-west-1' },
      recipientEmail: 'security@example.com',
      senderEmail: 'noreply@example.com',
      sesRegion: 'us-east-1',
    });
    template = Template.fromStack(stack);
  });

  test('has the 17 security EventBridge rules', () => {
    template.resourceCountIs('AWS::Events::Rule', 17);
  });

  test('has exactly 1 Notifier Lambda function', () => {
    template.resourceCountIs('AWS::Lambda::Function', 1);
  });

  test('Notifier log group has 30-day retention', () => {
    template.hasResourceProperties('AWS::Logs::LogGroup', {
      RetentionInDays: 30,
    });
  });

  test('Notifier Lambda has RECIPIENT_EMAIL, SENDER_EMAIL, and SES_REGION', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: Match.objectLike({
          RECIPIENT_EMAIL: 'security@example.com',
          SENDER_EMAIL: 'noreply@example.com',
          SES_REGION: 'us-east-1',
        }),
      },
    });
  });

  test('Notifier Lambda has SES send permissions', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: ['ses:SendEmail', 'ses:SendRawEmail'],
            Effect: 'Allow',
            Resource: '*',
          }),
        ]),
      },
    });
  });

  test('has no SCP, trail, or bucket (those are in the global stack)', () => {
    template.resourceCountIs('AWS::Organizations::Policy', 0);
    template.resourceCountIs('AWS::CloudTrail::Trail', 0);
    template.resourceCountIs('AWS::S3::Bucket', 0);
  });
});
