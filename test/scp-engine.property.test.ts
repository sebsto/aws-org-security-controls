// Feature: org-security-controls, Property 1: SCP Policy Construction Correctness
import * as fc from 'fast-check';
import { buildDenyServicesPolicy } from '../lib/scp-engine';
import { ScpEngineProps } from '../lib/types';

/**
 * Validates: Requirements 1.1, 2.1, 3.1, 4.3, 7.1, 8.1, 8.4
 */
describe('Property 1: SCP Policy Construction Correctness', () => {
  // Valid AWS region codes for generation
  const validRegionCodes = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
    'sa-east-1', 'ca-central-1', 'me-south-1',
  ];

  // Generator for a non-empty list of unique approved regions (1-10)
  const approvedRegionsArb = fc.uniqueArray(
    fc.constantFrom(...validRegionCodes),
    { minLength: 1, maxLength: 10 }
  );

  // Generator for RDS class lists (0-5 items)
  const rdsClassArb = fc.array(
    fc.constantFrom(
      'db.t3.micro', 'db.t3.small', 'db.t3.medium',
      'db.t4g.micro', 'db.t4g.small', 'db.t4g.medium',
      'db.r5.large', 'db.m5.large'
    ),
    { minLength: 0, maxLength: 5 }
  );

  // Generator for EC2 blocked patterns (0-10 items)
  const ec2PatternsArb = fc.array(
    fc.constantFrom(
      'p4*', 'p5*', 'g4*', 'g5*', 'inf*', 'trn*',
      '*.metal', '*.24xlarge', 'x1e*', 'dl*'
    ),
    { minLength: 0, maxLength: 10 }
  );

  // Generator for Bedrock ARN lists (0-20 items) using realistic ARN patterns
  const bedrockArnsArb = fc.array(
    fc.tuple(
      fc.stringOf(fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'), { minLength: 12, maxLength: 12 }),
      fc.stringOf(fc.constantFrom(...'abcdefghijklmnop'.split('')), { minLength: 4, maxLength: 16 })
    ).map(([accountId, roleName]) => `arn:aws:iam::${accountId}:role/${roleName}`),
    { minLength: 0, maxLength: 20 }
  );

  // Generator for optional break-glass ARN
  const breakGlassArb = fc.option(
    fc.stringOf(fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'), { minLength: 12, maxLength: 12 })
      .map(accountId => `arn:aws:iam::${accountId}:role/BreakGlass`),
    { nil: undefined }
  );

  // Combined ScpEngineProps generator
  const scpEnginePropsArb = fc.tuple(
    approvedRegionsArb,
    rdsClassArb,
    ec2PatternsArb,
    bedrockArnsArb,
    breakGlassArb
  ).map(([approvedRegions, allowedRdsClasses, allowedEc2Types, bedrockAllowedPrincipals, breakGlassRoleArn]) => ({
    approvedRegions,
    allowedRdsClasses,
    allowedEc2Types,
    bedrockAllowedPrincipals,
    breakGlassRoleArn,
    organizationRootId: 'r-abc1',
  } as ScpEngineProps));

  it('produces a valid policy with correct structure for any valid input', () => {
    fc.assert(
      fc.property(scpEnginePropsArb, (props) => {
        let policy: any;
        try {
          policy = buildDenyServicesPolicy(props);
        } catch (e: any) {
          // If the policy exceeds 5120 chars, that's a valid outcome (not a test failure)
          if (e.message && e.message.includes('exceeds 5120 character maximum')) {
            return true;
          }
          throw e;
        }

        // Assert Version is 2012-10-17
        expect(policy.Version).toBe('2012-10-17');

        // Assert exactly 7 statements
        expect(policy.Statement).toHaveLength(7);

        // Assert all Sids are unique
        const sids = policy.Statement.map((s: any) => s.Sid);
        expect(new Set(sids).size).toBe(7);

        // Assert region restriction references exactly the input approvedRegions
        const regionStmt = policy.Statement.find((s: any) => s.Sid === 'DenyOutsideApprovedRegions');
        expect(regionStmt.Condition.StringNotEquals['aws:RequestedRegion']).toEqual(props.approvedRegions);

        // Assert RDS condition references exactly the input allowedRdsClasses
        const rdsStmt = policy.Statement.find((s: any) => s.Sid === 'DenyUnapprovedRdsClasses');
        expect(rdsStmt.Condition.StringNotEquals['rds:DatabaseClass']).toEqual(props.allowedRdsClasses);

        // Assert EC2 condition references exactly the input allowedEc2Types
        const ec2Stmt = policy.Statement.find((s: any) => s.Sid === 'DenyUnapprovedEc2Types');
        expect(ec2Stmt.Condition.StringNotEquals['ec2:InstanceType']).toEqual(props.allowedEc2Types);

        // Assert Bedrock condition references bedrockAllowedPrincipals (or absent when empty)
        const bedrockStmt = policy.Statement.find((s: any) => s.Sid === 'DenyBedrockUnauthorized');
        if (props.bedrockAllowedPrincipals.length > 0) {
          expect(bedrockStmt.Condition.ArnNotLike['aws:PrincipalArn']).toEqual(props.bedrockAllowedPrincipals);
        } else {
          expect(bedrockStmt.Condition).toBeUndefined();
        }

        // Assert CloudTrail statement has ArnNotLike condition iff breakGlassRoleArn is provided
        const cloudTrailStmt = policy.Statement.find((s: any) => s.Sid === 'DenyCloudTrailTampering');
        if (props.breakGlassRoleArn) {
          expect(cloudTrailStmt.Condition).toBeDefined();
          expect(cloudTrailStmt.Condition.ArnNotLike['aws:PrincipalArn']).toBe(props.breakGlassRoleArn);
        } else {
          expect(cloudTrailStmt.Condition).toBeUndefined();
        }

        return true;
      }),
      { numRuns: 100 }
    );
  });
});
