import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { OrgSecurityControlsStack } from '../lib/org-security-controls-stack';

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
      env: { account: '123456789012', region: 'eu-west-1' },
    });
    template = Template.fromStack(stack);
  });

  describe('Resource counts', () => {
    test('template has exactly 2 AWS::Organizations::Policy resources', () => {
      template.resourceCountIs('AWS::Organizations::Policy', 2);
    });

    test('template has 1 AWS::CloudTrail::Trail resource', () => {
      template.resourceCountIs('AWS::CloudTrail::Trail', 1);
    });

    test('template has 1 AWS::S3::Bucket resource', () => {
      template.resourceCountIs('AWS::S3::Bucket', 1);
    });

    test('template has 18 AWS::Events::Rule resources (17 security rules + 1 scheduled rule)', () => {
      template.resourceCountIs('AWS::Events::Rule', 18);
    });

    test('template has 2 AWS::Lambda::Function resources', () => {
      template.resourceCountIs('AWS::Lambda::Function', 2);
    });
  });

  describe('Notifier Lambda environment variables', () => {
    test('has RECIPIENT_EMAIL and SENDER_EMAIL environment variables', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: Match.objectLike({
            RECIPIENT_EMAIL: 'security@example.com',
            SENDER_EMAIL: 'noreply@example.com',
          }),
        },
      });
    });
  });

  describe('Watchdog Lambda environment variables', () => {
    test('has RECIPIENT_EMAIL, SENDER_EMAIL, APPROVED_REGIONS, and CROSS_ACCOUNT_ROLE_NAME', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: Match.objectLike({
            RECIPIENT_EMAIL: 'security@example.com',
            SENDER_EMAIL: 'noreply@example.com',
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
