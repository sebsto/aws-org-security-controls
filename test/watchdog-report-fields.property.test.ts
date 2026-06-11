// Feature: org-security-controls, Property 9: Report Entry Field Completeness
import * as fc from 'fast-check';
import { compileReport } from '../lambda/watchdog/report';
import { AccountResult, RegionResult, VolumeInfo, AlbInfo } from '../lambda/watchdog/types';

/**
 * Validates: Requirements 19.3, 19.4
 */
describe('Property 9: Report Entry Field Completeness', () => {
  // Generator for non-empty strings of varying length
  const nonEmptyStringArb = fc.string({ minLength: 1, maxLength: 50 });

  // Generator for VolumeInfo
  const volumeInfoArb = (region: string): fc.Arbitrary<VolumeInfo> =>
    fc.record({
      volumeId: nonEmptyStringArb.map((s) => `vol-${s}`),
      sizeGiB: fc.nat({ max: 16384 }),
      region: fc.constant(region),
    });

  // Generator for AlbInfo
  const albInfoArb = (region: string): fc.Arbitrary<AlbInfo> =>
    fc.record({
      albName: nonEmptyStringArb,
      albArn: nonEmptyStringArb.map(
        (s) => `arn:aws:elasticloadbalancing:${region}:123456789012:loadbalancer/app/${s}/abc123`,
      ),
      region: fc.constant(region),
    });

  // Valid region codes for generation
  const regionCodes = [
    'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
    'ap-southeast-1', 'ap-northeast-1',
  ];

  // Generator for a RegionResult with random volumes and ALBs
  const regionResultArb: fc.Arbitrary<RegionResult> = fc.constantFrom(...regionCodes).chain(
    (region) =>
      fc.record({
        region: fc.constant(region),
        ec2Stopped: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 3 }),
        ecsTasksStopped: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 3 }),
        rdsInstancesStopped: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 3 }),
        rdsClustersStopped: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 3 }),
        eipsReleased: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 3 }),
        logGroupsUpdated: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 3 }),
        unusedEbsVolumes: fc.array(volumeInfoArb(region), { minLength: 0, maxLength: 5 }),
        emptyAlbs: fc.array(albInfoArb(region), { minLength: 0, maxLength: 5 }),
        errors: fc.array(nonEmptyStringArb, { minLength: 0, maxLength: 2 }),
      }),
  );

  // Generator for AccountResult with at least one region
  const accountResultArb: fc.Arbitrary<AccountResult> = fc.record({
    accountId: fc.stringOf(fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'), {
      minLength: 12,
      maxLength: 12,
    }),
    accountName: nonEmptyStringArb,
    roleAssumptionSuccess: fc.constant(true),
    regions: fc.array(regionResultArb, { minLength: 1, maxLength: 4 }),
  });

  // Generator for an array of AccountResults
  const accountResultsArb = fc.array(accountResultArb, { minLength: 1, maxLength: 5 });

  it('each AccountSummary contains accountId, and each EBS entry contains volumeId, sizeGiB, region; each ALB entry contains albName, region', () => {
    fc.assert(
      fc.property(accountResultsArb, (accountResults) => {
        const report = compileReport(accountResults, [], accountResults.length);

        for (const summary of report.accountResults) {
          // Verify AccountSummary has accountId (non-empty string)
          expect(typeof summary.accountId).toBe('string');
          expect(summary.accountId.length).toBeGreaterThan(0);

          // Verify each EBS volume entry has required fields
          for (const volume of summary.unusedEbsVolumes) {
            expect(typeof volume.volumeId).toBe('string');
            expect(volume.volumeId.length).toBeGreaterThan(0);

            expect(typeof volume.sizeGiB).toBe('number');
            expect(volume.sizeGiB).toBeGreaterThanOrEqual(0);

            expect(typeof volume.region).toBe('string');
            expect(volume.region.length).toBeGreaterThan(0);
          }

          // Verify each ALB entry has required fields
          for (const alb of summary.emptyAlbs) {
            expect(typeof alb.albName).toBe('string');
            expect(alb.albName.length).toBeGreaterThan(0);

            expect(typeof alb.region).toBe('string');
            expect(alb.region.length).toBeGreaterThan(0);
          }
        }
      }),
      { numRuns: 100 },
    );
  });
});
