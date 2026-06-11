// Feature: org-security-controls, Property 5: Management Account Exclusion
import * as fc from 'fast-check';
import { Account } from '@aws-sdk/client-organizations';
import { filterMemberAccounts } from '../lambda/watchdog/handler';

const MANAGEMENT_ACCOUNT_ID = '000000000000';

/**
 * Validates: Requirements 15.1
 */
describe('Property 5: Management Account Exclusion', () => {
  // Generator for a 12-digit account ID string
  const accountIdArb = fc.stringOf(
    fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'),
    { minLength: 12, maxLength: 12 },
  );

  // Generator for a single Account object with a random ID
  const accountArb = (id: string): Account => ({
    Id: id,
    Name: `account-${id}`,
  });

  // Generator for an account list (1-50 accounts) that always includes the management account
  const accountListArb = fc
    .array(
      accountIdArb.filter((id) => id !== MANAGEMENT_ACCOUNT_ID),
      { minLength: 0, maxLength: 49 },
    )
    .chain((otherIds) => {
      // Insert the management account at a random position
      const accounts = otherIds.map((id) => accountArb(id));
      return fc.nat({ max: accounts.length }).map((insertIdx) => {
        const result = [...accounts];
        result.splice(insertIdx, 0, accountArb(MANAGEMENT_ACCOUNT_ID));
        return result;
      });
    });

  it('excludes the management account while preserving all other accounts in original order', () => {
    fc.assert(
      fc.property(accountListArb, (accounts) => {
        const filtered = filterMemberAccounts(accounts, MANAGEMENT_ACCOUNT_ID);

        // Assert management account is NOT in the filtered list
        const managementInFiltered = filtered.some(
          (a) => a.Id === MANAGEMENT_ACCOUNT_ID,
        );
        expect(managementInFiltered).toBe(false);

        // Assert all other accounts are present in the filtered list
        const otherAccounts = accounts.filter(
          (a) => a.Id !== MANAGEMENT_ACCOUNT_ID,
        );
        expect(filtered).toHaveLength(otherAccounts.length);

        // Assert original order is preserved
        expect(filtered).toEqual(otherAccounts);

        // Assert length is original - 1 (since management account is always present)
        expect(filtered.length).toBe(accounts.length - 1);
      }),
      { numRuns: 100 },
    );
  });
});
