// Feature: org-security-controls, Property 3: Formatter Selection Correctness
import * as fc from 'fast-check';
import { formatters } from '../lambda/notifier/formatters';
import { CloudTrailEventBridgeEvent } from '../lambda/notifier/types';

/**
 * Validates: Requirements 12.1, 13.1
 */
describe('Property 3: Formatter Selection Correctness', () => {
  // Generators for random filler fields
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
    (id) => `arn:aws:iam::${id}:user/TestUser`
  );

  const ipArb = fc.tuple(
    fc.integer({ min: 1, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 0, max: 255 })
  ).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

  const uuidArb = fc.uuid();

  /**
   * Build a base event with common fields filled in randomly.
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
   * Define 17 event type generators, each producing events that match exactly one formatter.
   * For sign-in events, ensure distinguishing fields don't overlap:
   * - Type 1 (Root login): userIdentity.type=Root, MFAUsed=Yes, ConsoleLogin=Success
   * - Type 2 (No MFA login): userIdentity.type=IAMUser, MFAUsed=No, ConsoleLogin=Success
   * - Type 3 (Login failure): userIdentity.type=IAMUser, MFAUsed=Yes, ConsoleLogin=Failure
   */
  const eventTypeGenerators: fc.Arbitrary<CloudTrailEventBridgeEvent>[] = [
    // 1. Root Console Login (type=Root, MFAUsed=Yes to avoid matching NoMFA, ConsoleLogin=Success to avoid matching Failure)
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

    // 2. Console Login Without MFA (type=IAMUser to avoid Root match, MFAUsed=No, ConsoleLogin=Success to avoid Failure)
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

    // 3. Login Failure (type=IAMUser to avoid Root, MFAUsed=Yes to avoid NoMFA, ConsoleLogin=Failure)
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

    // 14. Cost Anomaly Detected (non-CloudTrail, uses detail-type matching)
    baseEventArb({
      source: 'aws.ce',
      detailType: 'AWS Cost Anomaly Detection Alert',
      eventName: '',
    }),

    // 15. Budget Notification (non-CloudTrail, uses detail-type matching)
    baseEventArb({
      source: 'aws.budgets',
      detailType: 'Budget Notification',
      eventName: '',
    }),

    // 16. Access Analyzer Finding (non-CloudTrail, uses detail-type matching)
    baseEventArb({
      source: 'aws.access-analyzer',
      detailType: 'Access Analyzer Finding',
      eventName: '',
    }),

    // 17. Organizations event (any eventName)
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

  it('exactly one formatter canHandle() returns true for each generated event', () => {
    fc.assert(
      fc.property(eventArb, (event) => {
        const matchingFormatters = formatters.filter((f) => f.canHandle(event));

        // Exactly one formatter should match
        expect(matchingFormatters.length).toBe(1);
      }),
      { numRuns: 100 }
    );
  });
});
