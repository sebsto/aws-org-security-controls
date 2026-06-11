import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { ScpEngine } from '../lib/scp-engine';

describe('ScpEngine CDK Assertions', () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'TestStack');
    new ScpEngine(stack, 'ScpEngine', {
      approvedRegions: ['eu-west-1', 'us-east-1'],
      allowedRdsClasses: ['db.t3.micro', 'db.t3.small'],
      allowedEc2Types: ['t4g.nano', 't4g.micro'],
      bedrockAllowedPrincipals: [],
      organizationRootId: 'r-abc1',
    });
    template = Template.fromStack(stack);
  });

  test('template has exactly 1 AWS::Organizations::Policy resource', () => {
    template.resourceCountIs('AWS::Organizations::Policy', 1);
  });

  describe('DenyServices policy', () => {
    test('has Name "DenyServices", Type "SERVICE_CONTROL_POLICY", and TargetIds containing org root', () => {
      template.hasResourceProperties('AWS::Organizations::Policy', {
        Name: 'DenyServices',
        Type: 'SERVICE_CONTROL_POLICY',
        TargetIds: Match.arrayWith(['r-abc1']),
      });
    });

    test('Content has Version "2012-10-17" and Statement array with 7 items', () => {
      template.hasResourceProperties('AWS::Organizations::Policy', {
        Name: 'DenyServices',
        Content: Match.objectLike({
          Version: '2012-10-17',
          Statement: Match.arrayEquals([
            Match.anyValue(),
            Match.anyValue(),
            Match.anyValue(),
            Match.anyValue(),
            Match.anyValue(),
            Match.anyValue(),
            Match.anyValue(),
          ]),
        }),
      });
    });
  });

});
