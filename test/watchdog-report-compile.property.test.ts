// Feature: org-security-controls, Property 11: Execution Report Compilation Correctness
import * as fc from 'fast-check';
import { compileReport } from '../lambda/watchdog/report';
import {
  AccountResult,
  RegionResult,
  FailedAccount,
  VolumeInfo,
  AlbInfo,
} from '../lambda/watchdog/types';

/**
 * Validates: Requirements 21.1, 21.2, 21.5
 */
describe('Property 11: Execution Report Compilation Correctness', () => {
  // Generator for a VolumeInfo object
  const volumeInfoArb: fc.Arbitrary<VolumeInfo> = fc.record({
    volumeId: fc.string({ minLength: 1, maxLength: 20 }),
    sizeGiB: fc.integer({ min: 1, max: 16384 }),
    region: fc.constantFrom(
      'us-east-1',
      'eu-west-1',
      'eu-west-3',
      'eu-central-1',
    ),
  });

  // Generator for an AlbInfo object
  const albInfoArb: fc.Arbitrary<AlbInfo> = fc.record({
    albName: fc.string({ minLength: 1, maxLength: 30 }),
    albArn: fc.string({ minLength: 1, maxLength: 80 }),
    region: fc.constantFrom(
      'us-east-1',
      'eu-west-1',
      'eu-west-3',
      'eu-central-1',
    ),
  });

  // Generator for a RegionResult object
  const regionResultArb: fc.Arbitrary<RegionResult> = fc.record({
    region: fc.constantFrom(
      'us-east-1',
      'eu-west-1',
      'eu-west-3',
      'eu-central-1',
    ),
    ec2Stopped: fc.array(fc.string({ minLength: 1, maxLength: 20 }), {
      minLength: 0,
      maxLength: 5,
    }),
    ecsTasksStopped: fc.array(fc.string({ minLength: 1, maxLength: 20 }), {
      minLength: 0,
      maxLength: 5,
    }),
    rdsInstancesStopped: fc.array(fc.string({ minLength: 1, maxLength: 20 }), {
      minLength: 0,
      maxLength: 5,
    }),
    rdsClustersStopped: fc.array(fc.string({ minLength: 1, maxLength: 20 }), {
      minLength: 0,
      maxLength: 5,
    }),
    eipsReleased: fc.array(fc.string({ minLength: 1, maxLength: 20 }), {
      minLength: 0,
      maxLength: 5,
    }),
    logGroupsUpdated: fc.array(fc.string({ minLength: 1, maxLength: 20 }), {
      minLength: 0,
      maxLength: 5,
    }),
    unusedEbsVolumes: fc.array(volumeInfoArb, {
      minLength: 0,
      maxLength: 3,
    }),
    emptyAlbs: fc.array(albInfoArb, { minLength: 0, maxLength: 3 }),
    errors: fc.array(fc.string({ minLength: 0, maxLength: 50 }), {
      minLength: 0,
      maxLength: 3,
    }),
  });

  // Generator for an AccountResult object
  const accountResultArb: fc.Arbitrary<AccountResult> = fc.record({
    accountId: fc.stringOf(
      fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'),
      { minLength: 12, maxLength: 12 },
    ),
    accountName: fc.string({ minLength: 1, maxLength: 30 }),
    roleAssumptionSuccess: fc.constant(true),
    regions: fc.array(regionResultArb, { minLength: 1, maxLength: 4 }),
  });

  // Generator for a FailedAccount object
  const failedAccountArb: fc.Arbitrary<FailedAccount> = fc.record({
    accountId: fc.stringOf(
      fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'),
      { minLength: 12, maxLength: 12 },
    ),
    accountName: fc.string({ minLength: 1, maxLength: 30 }),
    error: fc.string({ minLength: 1, maxLength: 100 }),
  });

  it('report.totalAccounts matches the input totalAccounts parameter', () => {
    fc.assert(
      fc.property(
        fc.array(accountResultArb, { minLength: 0, maxLength: 10 }),
        fc.array(failedAccountArb, { minLength: 0, maxLength: 5 }),
        (accountResults, failedAccounts) => {
          const totalAccounts = accountResults.length + failedAccounts.length;
          const report = compileReport(
            accountResults,
            failedAccounts,
            totalAccounts,
          );

          expect(report.totalAccounts).toBe(totalAccounts);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('report.processedAccounts matches accountResults.length', () => {
    fc.assert(
      fc.property(
        fc.array(accountResultArb, { minLength: 0, maxLength: 10 }),
        fc.array(failedAccountArb, { minLength: 0, maxLength: 5 }),
        (accountResults, failedAccounts) => {
          const totalAccounts = accountResults.length + failedAccounts.length;
          const report = compileReport(
            accountResults,
            failedAccounts,
            totalAccounts,
          );

          expect(report.processedAccounts).toBe(accountResults.length);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('report.failedAccounts has same length and entries as input', () => {
    fc.assert(
      fc.property(
        fc.array(accountResultArb, { minLength: 0, maxLength: 10 }),
        fc.array(failedAccountArb, { minLength: 0, maxLength: 5 }),
        (accountResults, failedAccounts) => {
          const totalAccounts = accountResults.length + failedAccounts.length;
          const report = compileReport(
            accountResults,
            failedAccounts,
            totalAccounts,
          );

          expect(report.failedAccounts).toHaveLength(failedAccounts.length);
          expect(report.failedAccounts).toEqual(failedAccounts);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('per-account counts match sum of respective arrays across regions', () => {
    fc.assert(
      fc.property(
        fc.array(accountResultArb, { minLength: 1, maxLength: 10 }),
        fc.array(failedAccountArb, { minLength: 0, maxLength: 5 }),
        (accountResults, failedAccounts) => {
          const totalAccounts = accountResults.length + failedAccounts.length;
          const report = compileReport(
            accountResults,
            failedAccounts,
            totalAccounts,
          );

          for (let i = 0; i < accountResults.length; i++) {
            const input = accountResults[i];
            const summary = report.accountResults[i];

            // ec2StoppedCount matches sum across regions
            const expectedEc2 = input.regions.reduce(
              (sum, r) => sum + r.ec2Stopped.length,
              0,
            );
            expect(summary.ec2StoppedCount).toBe(expectedEc2);

            // ecsTasksStoppedCount matches sum across regions
            const expectedEcs = input.regions.reduce(
              (sum, r) => sum + r.ecsTasksStopped.length,
              0,
            );
            expect(summary.ecsTasksStoppedCount).toBe(expectedEcs);

            // rdsInstancesStoppedCount matches sum across regions
            const expectedRdsInstances = input.regions.reduce(
              (sum, r) => sum + r.rdsInstancesStopped.length,
              0,
            );
            expect(summary.rdsInstancesStoppedCount).toBe(expectedRdsInstances);

            // rdsClustersStoppedCount matches sum across regions
            const expectedRdsClusters = input.regions.reduce(
              (sum, r) => sum + r.rdsClustersStopped.length,
              0,
            );
            expect(summary.rdsClustersStoppedCount).toBe(expectedRdsClusters);

            // eipsReleasedCount matches sum across regions
            const expectedEips = input.regions.reduce(
              (sum, r) => sum + r.eipsReleased.length,
              0,
            );
            expect(summary.eipsReleasedCount).toBe(expectedEips);

            // logGroupsUpdatedCount matches sum across regions
            const expectedLogGroups = input.regions.reduce(
              (sum, r) => sum + r.logGroupsUpdated.length,
              0,
            );
            expect(summary.logGroupsUpdatedCount).toBe(expectedLogGroups);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it('all resource entries (unusedEbsVolumes, emptyAlbs) are present and match input data', () => {
    fc.assert(
      fc.property(
        fc.array(accountResultArb, { minLength: 1, maxLength: 10 }),
        fc.array(failedAccountArb, { minLength: 0, maxLength: 5 }),
        (accountResults, failedAccounts) => {
          const totalAccounts = accountResults.length + failedAccounts.length;
          const report = compileReport(
            accountResults,
            failedAccounts,
            totalAccounts,
          );

          for (let i = 0; i < accountResults.length; i++) {
            const input = accountResults[i];
            const summary = report.accountResults[i];

            // unusedEbsVolumes should be the flattened list from all regions
            const expectedVolumes = input.regions.flatMap(
              (r) => r.unusedEbsVolumes,
            );
            expect(summary.unusedEbsVolumes).toEqual(expectedVolumes);
            expect(summary.unusedEbsVolumes).toHaveLength(
              expectedVolumes.length,
            );

            // emptyAlbs should be the flattened list from all regions
            const expectedAlbs = input.regions.flatMap((r) => r.emptyAlbs);
            expect(summary.emptyAlbs).toEqual(expectedAlbs);
            expect(summary.emptyAlbs).toHaveLength(expectedAlbs.length);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
