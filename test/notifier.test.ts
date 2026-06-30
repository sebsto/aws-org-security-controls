// Mock SES client - must be declared before imports due to jest hoisting
const mockSend = jest.fn();
jest.mock('@aws-sdk/client-ses', () => {
  return {
    SESClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
    SendEmailCommand: jest.fn((params: any) => params),
  };
});

import { handler, selectFormatter, genericFormat } from '../lambda/notifier/handler';
import { formatters, selectFormatter as selectFormatterFromFormatters } from '../lambda/notifier/formatters';
import { CloudTrailEventBridgeEvent } from '../lambda/notifier/types';

/**
 * Helper to build a base CloudTrail EventBridge event.
 */
function buildEvent(overrides: Partial<CloudTrailEventBridgeEvent> & { detail?: any }): CloudTrailEventBridgeEvent {
  return {
    version: '0',
    id: 'test-event-id-123',
    source: 'aws.iam',
    account: '123456789012',
    time: '2024-01-15T10:30:00Z',
    region: 'eu-west-1',
    'detail-type': 'AWS API Call via CloudTrail',
    detail: {
      eventVersion: '1.08',
      eventSource: 'iam.amazonaws.com',
      eventName: 'CreateUser',
      awsRegion: 'eu-west-1',
      sourceIPAddress: '203.0.113.50',
      userAgent: 'console.amazonaws.com',
      userIdentity: {
        type: 'IAMUser',
        principalId: 'AIDAEXAMPLE',
        arn: 'arn:aws:iam::123456789012:user/admin',
        accountId: '123456789012',
      },
      requestParameters: {},
      responseElements: {},
    },
    ...overrides,
  } as CloudTrailEventBridgeEvent;
}

describe('Notifier Lambda', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv, RECIPIENT_EMAIL: 'security@example.com', SENDER_EMAIL: 'noreply@example.com' };
    mockSend.mockResolvedValue({});
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  // ==========================================
  // Test Scenario 1: Each of the event types
  // ==========================================
  describe('Formatter selection and message formatting for all event types', () => {
    const eventPayloads: { name: string; event: CloudTrailEventBridgeEvent }[] = [
      {
        name: 'Root Console Login',
        event: buildEvent({
          source: 'aws.signin',
          'detail-type': 'AWS Console Sign In via CloudTrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'signin.amazonaws.com',
            eventName: 'ConsoleLogin',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.1',
            userAgent: 'Mozilla/5.0',
            userIdentity: {
              type: 'Root',
              principalId: '123456789012',
              arn: 'arn:aws:iam::123456789012:root',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: { ConsoleLogin: 'Success' },
          },
        }),
      },
      {
        name: 'Console Login Without MFA',
        event: buildEvent({
          source: 'aws.signin',
          'detail-type': 'AWS Console Sign In via CloudTrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'signin.amazonaws.com',
            eventName: 'ConsoleLogin',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.2',
            userAgent: 'Mozilla/5.0',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/developer',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: { ConsoleLogin: 'Success' },
            additionalEventData: { MFAUsed: 'No' },
          },
        }),
      },
      {
        name: 'Identity Center Login Without MFA',
        event: buildEvent({
          source: 'aws.signin',
          'detail-type': 'AWS Service Event via CloudTrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'signin.amazonaws.com',
            eventName: 'UserAuthentication',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.3',
            userAgent: 'Mozilla/5.0',
            userIdentity: {
              type: 'IdentityCenterUser',
              principalId: '54789458-8001-705b-db09-15eae8613a13',
              arn: '',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: {},
            additionalEventData: {
              CredentialType: 'PASSWORD',
              LoginTo: 'https://d-1234567890.awsapps.com/start/',
            },
          },
        }),
      },
      {
        name: 'Login Failure',
        event: buildEvent({
          source: 'aws.signin',
          'detail-type': 'AWS Console Sign In via CloudTrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'signin.amazonaws.com',
            eventName: 'ConsoleLogin',
            awsRegion: 'us-east-1',
            sourceIPAddress: '198.51.100.5',
            userAgent: 'Mozilla/5.0',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/attacker',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: { ConsoleLogin: 'Failure' },
            additionalEventData: { LoginTo: 'https://console.aws.amazon.com/console/home' },
          },
        }),
      },
      {
        name: 'CloudTrail StopLogging',
        event: buildEvent({
          source: 'aws.cloudtrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'cloudtrail.amazonaws.com',
            eventName: 'StopLogging',
            awsRegion: 'eu-west-1',
            sourceIPAddress: '203.0.113.10',
            userAgent: 'aws-cli/2.0',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/malicious',
              accountId: '123456789012',
            },
            requestParameters: { name: 'arn:aws:cloudtrail:eu-west-1:123456789012:trail/OrgTrail' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'CloudTrail DeleteTrail',
        event: buildEvent({
          source: 'aws.cloudtrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'cloudtrail.amazonaws.com',
            eventName: 'DeleteTrail',
            awsRegion: 'eu-west-1',
            sourceIPAddress: '203.0.113.10',
            userAgent: 'aws-cli/2.0',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/malicious',
              accountId: '123456789012',
            },
            requestParameters: { name: 'arn:aws:cloudtrail:eu-west-1:123456789012:trail/OrgTrail' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'CloudTrail UpdateTrail',
        event: buildEvent({
          source: 'aws.cloudtrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'cloudtrail.amazonaws.com',
            eventName: 'UpdateTrail',
            awsRegion: 'eu-west-1',
            sourceIPAddress: '203.0.113.10',
            userAgent: 'aws-cli/2.0',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/admin',
              accountId: '123456789012',
            },
            requestParameters: { name: 'arn:aws:cloudtrail:eu-west-1:123456789012:trail/OrgTrail' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'CloudTrail PutEventSelectors',
        event: buildEvent({
          source: 'aws.cloudtrail',
          detail: {
            eventVersion: '1.08',
            eventSource: 'cloudtrail.amazonaws.com',
            eventName: 'PutEventSelectors',
            awsRegion: 'eu-west-1',
            sourceIPAddress: '203.0.113.10',
            userAgent: 'aws-cli/2.0',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/admin',
              accountId: '123456789012',
            },
            requestParameters: { trailName: 'OrgTrail' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'IAM User Created',
        event: buildEvent({
          source: 'aws.iam',
          detail: {
            eventVersion: '1.08',
            eventSource: 'iam.amazonaws.com',
            eventName: 'CreateUser',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.20',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/admin',
              accountId: '123456789012',
            },
            requestParameters: { userName: 'new-user' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'Access Key Created',
        event: buildEvent({
          source: 'aws.iam',
          detail: {
            eventVersion: '1.08',
            eventSource: 'iam.amazonaws.com',
            eventName: 'CreateAccessKey',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.20',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/admin',
              accountId: '123456789012',
            },
            requestParameters: { userName: 'target-user' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'Login Profile Attached',
        event: buildEvent({
          source: 'aws.iam',
          detail: {
            eventVersion: '1.08',
            eventSource: 'iam.amazonaws.com',
            eventName: 'CreateLoginProfile',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.20',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/admin',
              accountId: '123456789012',
            },
            requestParameters: { userName: 'target-user' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'MFA Device Deactivated',
        event: buildEvent({
          source: 'aws.iam',
          detail: {
            eventVersion: '1.08',
            eventSource: 'iam.amazonaws.com',
            eventName: 'DeactivateMFADevice',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.20',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/admin',
              accountId: '123456789012',
            },
            requestParameters: { userName: 'target-user', serialNumber: 'arn:aws:iam::123456789012:mfa/target-user' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'SSO User Created',
        event: buildEvent({
          source: 'aws.sso-directory',
          detail: {
            eventVersion: '1.08',
            eventSource: 'sso-directory.amazonaws.com',
            eventName: 'CreateUser',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.30',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/sso-admin',
              accountId: '123456789012',
            },
            requestParameters: { userName: 'sso-new-user' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'Security Group Ingress Opened',
        event: buildEvent({
          source: 'aws.ec2',
          detail: {
            eventVersion: '1.08',
            eventSource: 'ec2.amazonaws.com',
            eventName: 'AuthorizeSecurityGroupIngress',
            awsRegion: 'eu-west-1',
            sourceIPAddress: '203.0.113.40',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/dev',
              accountId: '123456789012',
            },
            requestParameters: { groupId: 'sg-0123456789abcdef0' },
            responseElements: {},
          },
        }),
      },
      {
        name: 'Cost Anomaly Detected',
        event: buildEvent({
          source: 'aws.ce',
          'detail-type': 'AWS Cost Anomaly Detection Alert',
          detail: {
            eventVersion: '1.0',
            eventSource: 'ce.amazonaws.com',
            eventName: 'AnomalyDetected',
            awsRegion: 'us-east-1',
            sourceIPAddress: 'ce.amazonaws.com',
            userAgent: 'ce.amazonaws.com',
            userIdentity: {
              type: 'AWSService',
              principalId: 'ce.amazonaws.com',
              arn: 'arn:aws:iam::123456789012:root',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: {},
            anomalyId: 'anomaly-12345',
            totalImpact: '150.00',
          },
        }),
      },
      {
        name: 'Budget Threshold Breached',
        event: buildEvent({
          source: 'aws.budgets',
          'detail-type': 'Budget Notification',
          detail: {
            eventVersion: '1.0',
            eventSource: 'budgets.amazonaws.com',
            eventName: 'BudgetNotification',
            awsRegion: 'us-east-1',
            sourceIPAddress: 'budgets.amazonaws.com',
            userAgent: 'budgets.amazonaws.com',
            userIdentity: {
              type: 'AWSService',
              principalId: 'budgets.amazonaws.com',
              arn: 'arn:aws:iam::123456789012:root',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: {},
            budgetName: 'Monthly-Budget',
            budgetType: 'COST',
          },
        }),
      },
      {
        name: 'Access Analyzer Finding',
        event: buildEvent({
          source: 'aws.access-analyzer',
          'detail-type': 'Access Analyzer Finding',
          detail: {
            eventVersion: '1.0',
            eventSource: 'access-analyzer.amazonaws.com',
            eventName: 'FindingPublished',
            awsRegion: 'eu-west-1',
            sourceIPAddress: 'access-analyzer.amazonaws.com',
            userAgent: 'access-analyzer.amazonaws.com',
            userIdentity: {
              type: 'AWSService',
              principalId: 'access-analyzer.amazonaws.com',
              arn: 'arn:aws:iam::123456789012:root',
              accountId: '123456789012',
            },
            requestParameters: {},
            responseElements: {},
            resourceType: 'AWS::S3::Bucket',
            resource: 'arn:aws:s3:::my-public-bucket',
            status: 'ACTIVE',
          },
        }),
      },
      {
        name: 'Organization Event',
        event: buildEvent({
          source: 'aws.organizations',
          detail: {
            eventVersion: '1.08',
            eventSource: 'organizations.amazonaws.com',
            eventName: 'CreateAccount',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.50',
            userAgent: 'console.amazonaws.com',
            userIdentity: {
              type: 'IAMUser',
              principalId: 'AIDAEXAMPLE',
              arn: 'arn:aws:iam::123456789012:user/org-admin',
              accountId: '123456789012',
            },
            requestParameters: { email: 'new-account@example.com', accountName: 'NewAccount' },
            responseElements: {},
          },
        }),
      },
    ];

    test.each(eventPayloads)('selects the correct formatter for $name', ({ event }) => {
      const formatter = selectFormatter(event, formatters);
      expect(formatter).toBeDefined();
      expect(formatter!.canHandle(event)).toBe(true);
    });

    test.each(eventPayloads)('formats a non-empty subject and body for $name', ({ event }) => {
      const formatter = selectFormatter(event, formatters);
      expect(formatter).toBeDefined();

      const message = formatter!.format(event);
      expect(message.subject).toBeTruthy();
      expect(message.subject.length).toBeGreaterThan(0);
      expect(message.body).toBeTruthy();
      expect(message.body.length).toBeGreaterThan(0);
    });

    test.each(eventPayloads)('formatted body contains source, timestamp, account, and principal ARN for $name', ({ event }) => {
      const formatter = selectFormatter(event, formatters);
      expect(formatter).toBeDefined();

      const message = formatter!.format(event);
      expect(message.body).toContain(event.source);
      expect(message.body).toContain(event.time);
      expect(message.body).toContain(event.account);
      expect(message.body).toContain(event.detail.userIdentity.arn);
    });
  });

  // ==========================================
  // Test Scenario 2: Generic fallback for unknown event type
  // ==========================================
  describe('Generic fallback for unknown event type', () => {
    test('uses genericFormat when no formatter matches', () => {
      const unknownEvent = buildEvent({
        source: 'aws.unknown',
        detail: {
          eventVersion: '1.08',
          eventSource: 'unknown.amazonaws.com',
          eventName: 'UnknownAction',
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.99',
          userAgent: 'unknown-agent',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/mystery',
            accountId: '123456789012',
          },
          requestParameters: {},
          responseElements: {},
        },
      });

      const formatter = selectFormatter(unknownEvent, formatters);
      expect(formatter).toBeUndefined();

      const message = genericFormat(unknownEvent);
      expect(message.subject).toContain('Unknown event');
      expect(message.subject).toContain('aws.unknown');
      expect(message.body).toContain('aws.unknown');
      expect(message.body).toContain('UnknownAction');
      expect(message.body).toContain(JSON.stringify(unknownEvent, null, 2));
    });
  });

  // ==========================================
  // Test Scenario 3: Missing RECIPIENT_EMAIL env var
  // ==========================================
  describe('Missing RECIPIENT_EMAIL env var', () => {
    test('returns without calling SES when RECIPIENT_EMAIL is empty', async () => {
      process.env.RECIPIENT_EMAIL = '';
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const event = buildEvent({
        source: 'aws.iam',
        detail: {
          eventVersion: '1.08',
          eventSource: 'iam.amazonaws.com',
          eventName: 'CreateUser',
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.1',
          userAgent: 'console.amazonaws.com',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/admin',
            accountId: '123456789012',
          },
          requestParameters: { userName: 'new-user' },
          responseElements: {},
        },
      });

      await handler(event);

      expect(mockSend).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalledWith('Missing RECIPIENT_EMAIL configuration');

      consoleErrorSpy.mockRestore();
    });

    test('returns without calling SES when RECIPIENT_EMAIL is undefined', async () => {
      delete process.env.RECIPIENT_EMAIL;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const event = buildEvent({
        source: 'aws.iam',
        detail: {
          eventVersion: '1.08',
          eventSource: 'iam.amazonaws.com',
          eventName: 'CreateUser',
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.1',
          userAgent: 'console.amazonaws.com',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/admin',
            accountId: '123456789012',
          },
          requestParameters: { userName: 'new-user' },
          responseElements: {},
        },
      });

      await handler(event);

      expect(mockSend).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalledWith('Missing RECIPIENT_EMAIL configuration');

      consoleErrorSpy.mockRestore();
    });
  });

  // ==========================================
  // Test Scenario 4: SES delivery failure logging
  // ==========================================
  describe('SES delivery failure logging', () => {
    test('logs error on SES failure including event type, timestamp, and reason', async () => {
      mockSend.mockRejectedValue(new Error('MessageRejected: Email address not verified'));
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const event = buildEvent({
        source: 'aws.iam',
        time: '2024-03-10T14:22:00Z',
        detail: {
          eventVersion: '1.08',
          eventSource: 'iam.amazonaws.com',
          eventName: 'CreateUser',
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.1',
          userAgent: 'console.amazonaws.com',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/admin',
            accountId: '123456789012',
          },
          requestParameters: { userName: 'new-user' },
          responseElements: {},
        },
      });

      await handler(event);

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('SES delivery failed')
      );
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('aws.iam/CreateUser')
      );
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('2024-03-10T14:22:00Z')
      );
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('MessageRejected')
      );

      consoleErrorSpy.mockRestore();
    });

    test('does not throw when SES fails', async () => {
      mockSend.mockRejectedValue(new Error('Service unavailable'));

      const event = buildEvent({
        source: 'aws.cloudtrail',
        detail: {
          eventVersion: '1.08',
          eventSource: 'cloudtrail.amazonaws.com',
          eventName: 'StopLogging',
          awsRegion: 'eu-west-1',
          sourceIPAddress: '203.0.113.10',
          userAgent: 'aws-cli/2.0',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/admin',
            accountId: '123456789012',
          },
          requestParameters: { name: 'OrgTrail' },
          responseElements: {},
        },
      });

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      await expect(handler(event)).resolves.toBeUndefined();
      consoleErrorSpy.mockRestore();
    });
  });

  // ==========================================
  // Handler integration: sends email for known event
  // ==========================================
  describe('Handler end-to-end', () => {
    test('calls SES with formatted email for a known event type', async () => {
      const event = buildEvent({
        source: 'aws.iam',
        detail: {
          eventVersion: '1.08',
          eventSource: 'iam.amazonaws.com',
          eventName: 'CreateUser',
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.1',
          userAgent: 'console.amazonaws.com',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/admin',
            accountId: '123456789012',
          },
          requestParameters: { userName: 'new-user' },
          responseElements: {},
        },
      });

      await handler(event);

      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    test('calls SES with generic format for unknown event type', async () => {
      const event = buildEvent({
        source: 'aws.unknown',
        detail: {
          eventVersion: '1.08',
          eventSource: 'unknown.amazonaws.com',
          eventName: 'SomethingWeird',
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.99',
          userAgent: 'unknown',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: 'arn:aws:iam::123456789012:user/mystery',
            accountId: '123456789012',
          },
          requestParameters: {},
          responseElements: {},
        },
      });

      await handler(event);

      expect(mockSend).toHaveBeenCalledTimes(1);
    });
  });
});
