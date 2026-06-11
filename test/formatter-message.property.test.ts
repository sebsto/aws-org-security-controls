// Feature: org-security-controls, Property 4: Formatted Message Completeness
import * as fc from 'fast-check';
import { selectFormatter, formatters } from '../lambda/notifier/formatters';
import { genericFormat } from '../lambda/notifier/handler';
import { CloudTrailEventBridgeEvent } from '../lambda/notifier/types';

/**
 * Validates: Requirements 13.2
 */
describe('Property 4: Formatted Message Completeness', () => {
  // Generators for random field values
  const accountIdArb = fc.stringOf(
    fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'),
    { minLength: 12, maxLength: 12 }
  );

  const timestampArb = fc.date({
    min: new Date('2020-01-01'),
    max: new Date('2025-12-31'),
  }).map((d) => d.toISOString());

  const regionArb = fc.constantFrom(
    'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1'
  );

  const arnArb = accountIdArb.map(
    (id) => `arn:aws:iam::${id}:user/TestUser-${id.slice(0, 4)}`
  );

  const ipArb = fc.tuple(
    fc.integer({ min: 1, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 0, max: 255 })
  ).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

  const uuidArb = fc.uuid();

  /**
   * Build a base event with common fields filled in randomly, plus overrides for event type.
   */
  function baseEventArb(overrides: {
    source: string;
    detailType: string;
    eventName: string;
    extraDetail?: Record<string, unknown>;
  }): fc.Arbitrary<CloudTrailEventBridgeEvent> {
    return fc.tuple(accountIdArb, timestampArb, regionArb, arnArb, ipArb, uuidArb).map(
      ([account, time, region, principalArn, sourceIp, id]) => ({
        version: '0' as const,
        id,
        source: overrides.source,
        account,
        time,
        region,
        'detail-type': overrides.detailType,
        detail: {
          eventVersion: '1.08',
          eventSource: `${overrides.source.replace('aws.', '')}.amazonaws.com`,
          eventName: overrides.eventName,
          awsRegion: region,
          sourceIPAddress: sourceIp,
          userAgent: 'aws-cli/2.0',
          userIdentity: {
            type: 'IAMUser',
            principalId: 'AIDAEXAMPLE',
            arn: principalArn,
            accountId: account,
          },
          requestParameters: {},
          responseElements: {},
          ...overrides.extraDetail,
        },
      })
    );
  }

  /**
   * 17 event type generators producing events that match exactly one formatter.
   */
  const eventTypeGenerators: fc.Arbitrary<CloudTrailEventBridgeEvent>[] = [
    // 1. Root Console Login
    baseEventArb({
      source: 'aws.signin',
      detailType: 'AWS Console Sign In via CloudTrail',
      eventName: 'ConsoleLogin',
      extraDetail: {
        userIdentity: {
          type: 'Root',
          principalId: 'AIDAEXAMPLE',
          arn: 'arn:aws:iam::123456789012:root',
          accountId: '123456789012',
        },
        additionalEventData: { MFAUsed: 'Yes' },
        responseElements: { ConsoleLogin: 'Success' },
      },
    }),

    // 2. Console Login Without MFA
    baseEventArb({
      source: 'aws.signin',
      detailType: 'AWS Console Sign In via CloudTrail',
      eventName: 'ConsoleLogin',
      extraDetail: {
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAEXAMPLE',
          arn: 'arn:aws:iam::123456789012:user/SomeUser',
          accountId: '123456789012',
        },
        additionalEventData: { MFAUsed: 'No' },
        responseElements: { ConsoleLogin: 'Success' },
      },
    }),

    // 3. Login Failure
    baseEventArb({
      source: 'aws.signin',
      detailType: 'AWS Console Sign In via CloudTrail',
      eventName: 'ConsoleLogin',
      extraDetail: {
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAEXAMPLE',
          arn: 'arn:aws:iam::123456789012:user/SomeUser',
          accountId: '123456789012',
        },
        additionalEventData: { MFAUsed: 'Yes' },
        responseElements: { ConsoleLogin: 'Failure' },
      },
    }),

    // 4. CloudTrail StopLogging
    baseEventArb({
      source: 'aws.cloudtrail',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'StopLogging',
    }),

    // 5. CloudTrail DeleteTrail
    baseEventArb({
      source: 'aws.cloudtrail',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'DeleteTrail',
    }),

    // 6. CloudTrail UpdateTrail
    baseEventArb({
      source: 'aws.cloudtrail',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'UpdateTrail',
    }),

    // 7. CloudTrail PutEventSelectors
    baseEventArb({
      source: 'aws.cloudtrail',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'PutEventSelectors',
    }),

    // 8. IAM CreateUser
    baseEventArb({
      source: 'aws.iam',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'CreateUser',
    }),

    // 9. IAM CreateAccessKey
    baseEventArb({
      source: 'aws.iam',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'CreateAccessKey',
    }),

    // 10. IAM CreateLoginProfile
    baseEventArb({
      source: 'aws.iam',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'CreateLoginProfile',
    }),

    // 11. IAM DeactivateMFADevice
    baseEventArb({
      source: 'aws.iam',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'DeactivateMFADevice',
    }),

    // 12. SSO-Directory CreateUser
    baseEventArb({
      source: 'aws.sso-directory',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'CreateUser',
    }),

    // 13. EC2 AuthorizeSecurityGroupIngress
    baseEventArb({
      source: 'aws.ec2',
      detailType: 'AWS API Call via CloudTrail',
      eventName: 'AuthorizeSecurityGroupIngress',
    }),

    // 14. Cost Anomaly Detected
    baseEventArb({
      source: 'aws.ce',
      detailType: 'AWS Cost Anomaly Detection Alert',
      eventName: '',
    }),

    // 15. Budget Notification
    baseEventArb({
      source: 'aws.budgets',
      detailType: 'Budget Notification',
      eventName: '',
    }),

    // 16. Access Analyzer Finding
    baseEventArb({
      source: 'aws.access-analyzer',
      detailType: 'Access Analyzer Finding',
      eventName: '',
    }),

    // 17. Organizations event
    fc.constantFrom(
      'CreateAccount', 'MoveAccount', 'InviteAccountToOrganization',
      'RemoveAccountFromOrganization', 'CreateOrganizationalUnit', 'DeleteOrganizationalUnit',
      'AttachPolicy', 'DetachPolicy', 'EnablePolicyType'
    ).chain((eventName) =>
      baseEventArb({
        source: 'aws.organizations',
        detailType: 'AWS API Call via CloudTrail',
        eventName,
      })
    ),
  ];

  // Generator that picks a random event type from the set of 17
  const eventArb = fc.integer({ min: 0, max: 16 }).chain((idx) => eventTypeGenerators[idx]);

  it('every formatted EmailMessage body contains event source, timestamp, account, principal ARN, and at least one event-specific field', () => {
    fc.assert(
      fc.property(eventArb, (event) => {
        // Select the formatter (or use generic fallback)
        const formatter = selectFormatter(event);
        const message = formatter
          ? formatter.format(event)
          : genericFormat(event);

        const body = message.body;

        // Assert body contains the event source
        expect(body).toContain(event.source);

        // Assert body contains the timestamp
        expect(body).toContain(event.time);

        // Assert body contains the affected account ID
        expect(body).toContain(event.account);

        // Assert body contains the principal ARN
        const principalArn = event.detail?.userIdentity?.arn;
        expect(body).toContain(principalArn);

        // Assert body contains at least one event-specific field beyond the four common fields.
        // Each formatter includes additional contextual information (region, source IP,
        // event name, trail ARN, user name, security group ID, anomaly ID, budget name, etc.)
        // We verify by counting distinct <tr> rows in the HTML table body (each row = one field).
        // The 4 common fields are: source, timestamp, account, principal ARN.
        // Any formatter that includes more than 4 rows has event-specific content.
        const tableRows = (body.match(/<tr>/g) || []).length;
        expect(tableRows).toBeGreaterThan(4);
      }),
      { numRuns: 100 }
    );
  });
});
