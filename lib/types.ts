import * as lambda from 'aws-cdk-lib/aws-lambda';

export interface ScpEngineProps {
  approvedRegions: string[];
  allowedRdsClasses: string[];
  allowedEc2Types: string[];
  bedrockAllowedPrincipals: string[];
  breakGlassRoleArn?: string;
  organizationRootId: string;
}

export interface OrgTrailProps {
  organizationId: string;
  trailName?: string;
}

export interface EventBridgeRulesProps {
  notifierLambda: lambda.IFunction;
}
