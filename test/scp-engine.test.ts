import { buildDenyServicesPolicy } from '../lib/scp-engine';
import { ScpEngineProps } from '../lib/types';

describe('buildDenyServicesPolicy', () => {
  const baseProps: ScpEngineProps = {
    approvedRegions: ['eu-west-1', 'eu-west-3', 'eu-central-1', 'us-east-1'],
    allowedRdsClasses: ['db.t3.micro', 'db.t3.small', 'db.t4g.micro', 'db.t4g.small'],
    allowedEc2Types: ['t4g.nano', 't4g.micro'],
    bedrockAllowedPrincipals: ['arn:aws:iam::123456789012:role/BedrockUser'],
    breakGlassRoleArn: 'arn:aws:iam::123456789012:role/BreakGlass',
    organizationRootId: 'r-abc1',
  };

  test('produces a policy with Version 2012-10-17', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    expect(policy.Version).toBe('2012-10-17');
  });

  test('produces exactly 7 statements', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    expect(policy.Statement).toHaveLength(7);
  });

  test('all statements have unique Sids', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const sids = policy.Statement.map((s: any) => s.Sid);
    expect(new Set(sids).size).toBe(7);
    expect(sids).toContain('DenyOutsideApprovedRegions');
    expect(sids).toContain('DenyUnapprovedRdsClasses');
    expect(sids).toContain('DenyUnapprovedEc2Types');
    expect(sids).toContain('DenyCloudTrailTampering');
    expect(sids).toContain('DenyRootUserActions');
    expect(sids).toContain('DenyIamUserCreation');
    expect(sids).toContain('DenyBedrockUnauthorized');
  });

  test('region restriction uses NotAction to exclude global services', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyOutsideApprovedRegions');
    expect(stmt.NotAction).toContain('iam:*');
    expect(stmt.NotAction).toContain('sts:*');
    expect(stmt.NotAction).toContain('organizations:*');
    expect(stmt.NotAction).toContain('cloudfront:*');
    expect(stmt.NotAction).toContain('route53:*');
    expect(stmt.NotAction).toContain('support:*');
    expect(stmt.NotAction).toContain('budgets:*');
    expect(stmt.Condition.StringNotEquals['aws:RequestedRegion']).toEqual(baseProps.approvedRegions);
  });

  test('RDS class restriction uses StringNotEquals condition', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyUnapprovedRdsClasses');
    expect(stmt.Condition.StringNotEquals['rds:DatabaseClass']).toEqual(baseProps.allowedRdsClasses);
  });

  test('EC2 type restriction uses StringNotEquals condition', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyUnapprovedEc2Types');
    expect(stmt.Condition.StringNotEquals['ec2:InstanceType']).toEqual(baseProps.allowedEc2Types);
  });

  test('CloudTrail statement includes break-glass exclusion when provided', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyCloudTrailTampering');
    expect(stmt.Condition.ArnNotLike['aws:PrincipalArn']).toBe(baseProps.breakGlassRoleArn);
  });

  test('CloudTrail statement omits condition when no break-glass role', () => {
    const propsNoBreakGlass = { ...baseProps, breakGlassRoleArn: undefined };
    const policy = buildDenyServicesPolicy(propsNoBreakGlass) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyCloudTrailTampering');
    expect(stmt.Condition).toBeUndefined();
  });

  test('root user statement uses aws:PrincipalArn condition', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyRootUserActions');
    expect(stmt.Condition.StringLike['aws:PrincipalArn']).toBe('arn:aws:iam::*:root');
  });

  test('IAM user creation denial covers correct actions', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyIamUserCreation');
    expect(stmt.Action).toContain('iam:CreateUser');
    expect(stmt.Action).toContain('iam:CreateLoginProfile');
    expect(stmt.Action).toContain('iam:CreateAccessKey');
  });

  test('Bedrock statement includes ArnNotLike when allowlist is non-empty', () => {
    const policy = buildDenyServicesPolicy(baseProps) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyBedrockUnauthorized');
    expect(stmt.Condition.ArnNotLike['aws:PrincipalArn']).toEqual(baseProps.bedrockAllowedPrincipals);
  });

  test('Bedrock statement omits condition when allowlist is empty', () => {
    const propsEmptyBedrock = { ...baseProps, bedrockAllowedPrincipals: [] };
    const policy = buildDenyServicesPolicy(propsEmptyBedrock) as any;
    const stmt = policy.Statement.find((s: any) => s.Sid === 'DenyBedrockUnauthorized');
    expect(stmt.Condition).toBeUndefined();
  });

  test('throws error when approvedRegions is empty', () => {
    const propsEmptyRegions = { ...baseProps, approvedRegions: [] };
    expect(() => buildDenyServicesPolicy(propsEmptyRegions)).toThrow(
      'At least 1 approved region must be specified'
    );
  });

  test('throws error when policy exceeds 5120 characters', () => {
    const propsLarge = {
      ...baseProps,
      bedrockAllowedPrincipals: Array.from({ length: 20 }, (_, i) =>
        `arn:aws:iam::${String(i).padStart(12, '0')}:role/VeryLongRoleNameThatWillMakeThePolicyExceedTheMaximumAllowedSizeLimitOf5120Characters${i}`
      ),
      allowedEc2Types: Array.from({ length: 50 }, (_, i) => `instance.type.pattern.${i}`),
    };
    expect(() => buildDenyServicesPolicy(propsLarge)).toThrow(
      /exceeds 5120 character maximum/
    );
  });

  test('does not throw when policy is within 5120 characters', () => {
    expect(() => buildDenyServicesPolicy(baseProps)).not.toThrow();
  });
});
