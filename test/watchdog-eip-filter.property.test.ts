// Feature: org-security-controls, Property 7: EIP Release Filtering
import * as fc from 'fast-check';
import { Address } from '@aws-sdk/client-ec2';
import { filterUnattachedEips } from '../lambda/watchdog/actions/network';

/**
 * Validates: Requirements 18.2
 */
describe('Property 7: EIP Release Filtering', () => {
  // Generator for a random AllocationId
  const allocationIdArb = fc.string({ minLength: 5, maxLength: 20 }).map(
    (s) => `eipalloc-${s.replace(/[^a-z0-9]/g, 'x')}`,
  );

  // Generator for an optional NetworkInterfaceId (present or undefined)
  const networkInterfaceIdArb = fc.option(
    fc.string({ minLength: 5, maxLength: 20 }).map(
      (s) => `eni-${s.replace(/[^a-z0-9]/g, 'x')}`,
    ),
    { nil: undefined },
  );

  // Generator for an optional AssociationId (present or undefined)
  const associationIdArb = fc.option(
    fc.string({ minLength: 5, maxLength: 20 }).map(
      (s) => `eipassoc-${s.replace(/[^a-z0-9]/g, 'x')}`,
    ),
    { nil: undefined },
  );

  // Generator for a single Address object
  const addressArb: fc.Arbitrary<Address> = fc
    .tuple(allocationIdArb, networkInterfaceIdArb, associationIdArb)
    .map(([AllocationId, NetworkInterfaceId, AssociationId]) => ({
      AllocationId,
      NetworkInterfaceId,
      AssociationId,
    }));

  // Generator for an array of Address objects (0-50 items)
  const addressListArb = fc.array(addressArb, { minLength: 0, maxLength: 50 });

  it('returns only EIPs with no NetworkInterfaceId and no AssociationId', () => {
    fc.assert(
      fc.property(addressListArb, (addresses) => {
        const result = filterUnattachedEips(addresses);

        // Every returned EIP must have no NetworkInterfaceId and no AssociationId
        for (const eip of result) {
          expect(eip.NetworkInterfaceId).toBeUndefined();
          expect(eip.AssociationId).toBeUndefined();
        }
      }),
      { numRuns: 100 },
    );
  });

  it('never releases EIPs that have either NetworkInterfaceId or AssociationId', () => {
    fc.assert(
      fc.property(addressListArb, (addresses) => {
        const result = filterUnattachedEips(addresses);

        // Every EIP with either field present must NOT be in the result
        const associatedEips = addresses.filter(
          (addr) => addr.NetworkInterfaceId || addr.AssociationId,
        );

        for (const associated of associatedEips) {
          expect(result).not.toContain(associated);
        }
      }),
      { numRuns: 100 },
    );
  });

  it('releases if and only if both NetworkInterfaceId and AssociationId are absent', () => {
    fc.assert(
      fc.property(addressListArb, (addresses) => {
        const result = filterUnattachedEips(addresses);

        for (const addr of addresses) {
          const isUnattached = !addr.NetworkInterfaceId && !addr.AssociationId;
          const isInResult = result.includes(addr);

          // An EIP is in the result if and only if it is unattached
          expect(isInResult).toBe(isUnattached);
        }
      }),
      { numRuns: 100 },
    );
  });
});
