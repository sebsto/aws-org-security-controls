import { Construct } from 'constructs';
import * as organizations from 'aws-cdk-lib/aws-organizations';
import { ScpEngineProps } from './types';

/**
 * Builds the DenyServices SCP policy document containing 7 deny statements.
 * Validates configuration at synthesis time.
 */
export function buildDenyServicesPolicy(props: ScpEngineProps): object {
  // Synthesis-time validation: approvedRegions must not be empty
  if (props.approvedRegions.length === 0) {
    throw new Error('At least 1 approved region must be specified');
  }

  const statements: object[] = [];

  // Statement 1: Deny actions outside approved regions (excluding global services)
  statements.push({
    Sid: 'DenyOutsideApprovedRegions',
    Effect: 'Deny',
    NotAction: [
      'iam:*',
      'sts:*',
      'organizations:*',
      'cloudfront:*',
      'route53:*',
      'support:*',
      'budgets:*',
    ],
    Resource: '*',
    Condition: {
      StringNotEquals: {
        'aws:RequestedRegion': props.approvedRegions,
      },
    },
  });

  // Statement 2: Deny unapproved RDS instance classes
  statements.push({
    Sid: 'DenyUnapprovedRdsClasses',
    Effect: 'Deny',
    Action: [
      'rds:CreateDBInstance',
      'rds:ModifyDBInstance',
      'rds:CreateDBCluster',
      'rds:RestoreDBInstanceFromDBSnapshot',
      'rds:RestoreDBInstanceToPointInTime',
    ],
    Resource: '*',
    Condition: {
      StringNotEquals: {
        'rds:DatabaseClass': props.allowedRdsClasses,
      },
    },
  });

  // Statement 3: Deny EC2 instance types not in allowed list
  statements.push({
    Sid: 'DenyUnapprovedEc2Types',
    Effect: 'Deny',
    Action: 'ec2:RunInstances',
    Resource: '*',
    Condition: {
      StringNotEquals: {
        'ec2:InstanceType': props.allowedEc2Types,
      },
    },
  });

  // Statement 4: Deny CloudTrail tampering (with optional break-glass exclusion)
  const cloudTrailStatement: Record<string, unknown> = {
    Sid: 'DenyCloudTrailTampering',
    Effect: 'Deny',
    Action: [
      'cloudtrail:StopLogging',
      'cloudtrail:DeleteTrail',
      'cloudtrail:UpdateTrail',
      'cloudtrail:PutEventSelectors',
    ],
    Resource: '*',
  };

  if (props.breakGlassRoleArn) {
    cloudTrailStatement.Condition = {
      ArnNotLike: {
        'aws:PrincipalArn': props.breakGlassRoleArn,
      },
    };
  }

  statements.push(cloudTrailStatement);

  // Statement 5: Deny root user actions
  statements.push({
    Sid: 'DenyRootUserActions',
    Effect: 'Deny',
    Action: '*',
    Resource: '*',
    Condition: {
      StringLike: {
        'aws:PrincipalArn': 'arn:aws:iam::*:root',
      },
    },
  });

  // Statement 6: Deny IAM user creation
  statements.push({
    Sid: 'DenyIamUserCreation',
    Effect: 'Deny',
    Action: [
      'iam:CreateUser',
      'iam:CreateLoginProfile',
      'iam:CreateAccessKey',
    ],
    Resource: '*',
  });

  // Statement 7: Deny IAM user creation
  statements.push({
    Sid: 'DenySageMaker',
    Effect: 'Deny',
    Action: [
      'sagemaker:*'
    ],
    Resource: '*',
  });

  // Statement 8: Deny Bedrock access unless principal is in allowlist
  const bedrockStatement: Record<string, unknown> = {
    Sid: 'DenyBedrockUnauthorized',
    Effect: 'Deny',
    Action: 'bedrock:*',
    Resource: '*',
  };

  if (props.bedrockAllowedPrincipals.length > 0) {
    bedrockStatement.Condition = {
      ArnNotLike: {
        'aws:PrincipalArn': props.bedrockAllowedPrincipals,
      },
    };
  }
  // When allowlist is empty, no condition is added — deny all Bedrock access

  statements.push(bedrockStatement);

  const policyDocument = {
    Version: '2012-10-17',
    Statement: statements,
  };

  // Synthesis-time validation: policy must not exceed 5120 characters
  const serialized = JSON.stringify(policyDocument);
  if (serialized.length > 5120) {
    throw new Error(
      `DenyServices policy is ${serialized.length} characters, exceeds 5120 character maximum`
    );
  }

  return policyDocument;
}

/**
 * SCP Engine CDK Construct.
 * Builds and deploys the DenyServices Service Control Policy to the organization root.
 */
export class ScpEngine extends Construct {
  public readonly denyServicesPolicy: object;

  constructor(scope: Construct, id: string, props: ScpEngineProps) {
    super(scope, id);

    // Build the DenyServices policy document (includes validation)
    this.denyServicesPolicy = buildDenyServicesPolicy(props);

    // Create CfnPolicy for DenyServices
    new organizations.CfnPolicy(this, 'DenyServicesPolicy', {
      name: 'DenyServices',
      type: 'SERVICE_CONTROL_POLICY',
      content: this.denyServicesPolicy,
      targetIds: [props.organizationRootId],
    });
  }
}
