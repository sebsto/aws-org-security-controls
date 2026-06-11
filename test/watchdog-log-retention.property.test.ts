// Feature: org-security-controls, Property 10: Log Group Retention Enforcement Logic
import * as fc from 'fast-check';
import { LogGroup } from '@aws-sdk/client-cloudwatch-logs';
import { filterLogGroupsWithoutRetention } from '../lambda/watchdog/actions/logs';

/**
 * Validates: Requirements 20.2, 20.3
 *
 * For any set of CloudWatch log groups, filterLogGroupsWithoutRetention SHALL return
 * only those groups where retentionInDays is undefined/null. Groups with any existing
 * retention value SHALL never be included in the result.
 */
describe('Property 10: Log Group Retention Enforcement Logic', () => {
  // Common valid retention values for CloudWatch Logs
  const validRetentionValues = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];

  // Generator for a log group with a defined retention policy
  const logGroupWithRetentionArb = fc.record({
    logGroupName: fc.string({ minLength: 1, maxLength: 50 }).map(s => `/aws/lambda/${s}`),
    retentionInDays: fc.constantFrom(...validRetentionValues),
  }) as fc.Arbitrary<LogGroup>;

  // Generator for a log group without a retention policy (retentionInDays is undefined)
  const logGroupWithoutRetentionArb = fc.record({
    logGroupName: fc.string({ minLength: 1, maxLength: 50 }).map(s => `/aws/logs/${s}`),
  }).map(({ logGroupName }) => ({ logGroupName, retentionInDays: undefined } as LogGroup));

  // Generator for a mixed array of log groups
  const logGroupListArb = fc.array(
    fc.oneof(logGroupWithRetentionArb, logGroupWithoutRetentionArb),
    { minLength: 0, maxLength: 30 }
  );

  it('returns only groups where retentionInDays is undefined', () => {
    fc.assert(
      fc.property(logGroupListArb, (logGroups) => {
        const result = filterLogGroupsWithoutRetention(logGroups);

        // Every returned group must have retentionInDays as undefined or null
        for (const group of result) {
          expect(group.retentionInDays === undefined || group.retentionInDays === null).toBe(true);
        }
      }),
      { numRuns: 100 }
    );
  });

  it('never includes groups with an existing retention policy', () => {
    fc.assert(
      fc.property(logGroupListArb, (logGroups) => {
        const result = filterLogGroupsWithoutRetention(logGroups);

        // No group with a defined retentionInDays should appear in the result
        const groupsWithRetention = logGroups.filter(
          g => g.retentionInDays !== undefined && g.retentionInDays !== null
        );
        const resultNames = new Set(result.map(g => g.logGroupName));

        for (const group of groupsWithRetention) {
          expect(resultNames.has(group.logGroupName)).toBe(false);
        }
      }),
      { numRuns: 100 }
    );
  });

  it('returns exactly the set of groups without retention (completeness)', () => {
    fc.assert(
      fc.property(logGroupListArb, (logGroups) => {
        const result = filterLogGroupsWithoutRetention(logGroups);

        // The result should contain exactly those groups where retentionInDays is undefined/null
        const expected = logGroups.filter(
          g => g.retentionInDays === undefined || g.retentionInDays === null
        );

        expect(result).toHaveLength(expected.length);
        expect(result).toEqual(expected);
      }),
      { numRuns: 100 }
    );
  });
});
