// Feature: org-security-controls, Property 8: Resource Waste Identification
import * as fc from 'fast-check';
import { Volume } from '@aws-sdk/client-ec2';
import { filterAvailableVolumes, isAlbEmpty } from '../lambda/watchdog/actions/reporting';

/**
 * Validates: Requirements 19.1, 19.2
 */
describe('Property 8: Resource Waste Identification', () => {
  // Generator for EBS volume states
  const volumeStates = ['available', 'in-use', 'creating', 'deleting'] as const;

  // Generator for a single Volume with a random state
  const volumeArb: fc.Arbitrary<Volume> = fc.record({
    VolumeId: fc.string({ minLength: 4, maxLength: 20 }).map((s) => `vol-${s}`),
    State: fc.constantFrom(...volumeStates),
    Size: fc.integer({ min: 1, max: 16384 }),
    AvailabilityZone: fc.constantFrom('us-east-1a', 'eu-west-1b', 'ap-southeast-1c'),
  });

  // Generator for a list of volumes (0-30 items)
  const volumeListArb = fc.array(volumeArb, { minLength: 0, maxLength: 30 });

  // Generator for a single target group health entry (0-5 targets)
  const targetGroupHealthArb = fc.record({
    targetGroupArn: fc.string({ minLength: 5, maxLength: 30 }).map(
      (s) => `arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/${s}`,
    ),
    targets: fc.integer({ min: 0, max: 5 }),
  });

  // Generator for target group health list (1-5 TGs per ALB)
  const targetGroupListArb = fc.array(targetGroupHealthArb, { minLength: 1, maxLength: 5 });

  describe('filterAvailableVolumes', () => {
    it('returns exactly the volumes with state "available"', () => {
      fc.assert(
        fc.property(volumeListArb, (volumes) => {
          const result = filterAvailableVolumes(volumes);

          // All returned volumes must be in 'available' state
          const allAvailable = result.every((v) => v.State === 'available');

          // Count of returned volumes must match count of 'available' volumes in input
          const expectedCount = volumes.filter((v) => v.State === 'available').length;
          const correctCount = result.length === expectedCount;

          // Every 'available' volume from input must appear in the result
          const availableFromInput = volumes.filter((v) => v.State === 'available');
          const allPresent = availableFromInput.every((av) =>
            result.some((rv) => rv.VolumeId === av.VolumeId),
          );

          return allAvailable && correctCount && allPresent;
        }),
        { numRuns: 100 },
      );
    });

    it('never includes volumes with non-available states', () => {
      fc.assert(
        fc.property(volumeListArb, (volumes) => {
          const result = filterAvailableVolumes(volumes);
          return result.every((v) => v.State === 'available');
        }),
        { numRuns: 100 },
      );
    });
  });

  describe('isAlbEmpty', () => {
    it('returns true if and only if every target group has zero targets', () => {
      fc.assert(
        fc.property(targetGroupListArb, (targetGroupHealths) => {
          const result = isAlbEmpty(targetGroupHealths);
          const allZero = targetGroupHealths.every((tg) => tg.targets === 0);
          return result === allZero;
        }),
        { numRuns: 100 },
      );
    });

    it('returns true for an empty target group list', () => {
      expect(isAlbEmpty([])).toBe(true);
    });

    it('returns false if any target group has at least one target', () => {
      // Generator that guarantees at least one TG with targets > 0
      const nonEmptyTgListArb = fc
        .array(targetGroupHealthArb, { minLength: 1, maxLength: 5 })
        .filter((tgs) => tgs.some((tg) => tg.targets > 0));

      fc.assert(
        fc.property(nonEmptyTgListArb, (targetGroupHealths) => {
          return isAlbEmpty(targetGroupHealths) === false;
        }),
        { numRuns: 100 },
      );
    });
  });
});
