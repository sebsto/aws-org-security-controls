import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { OrgTrail } from '../lib/org-trail';

describe('OrgTrail Construct', () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'TestStack');
    new OrgTrail(stack, 'TestTrail', {
      organizationId: 'o-lzfhtgvhr7',
    });
    template = Template.fromStack(stack);
  });

  describe('CloudTrail Trail resource', () => {
    test('creates a trail with IsOrganizationTrail enabled', () => {
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        IsOrganizationTrail: true,
      });
    });

    test('creates a trail with IsMultiRegionTrail enabled', () => {
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        IsMultiRegionTrail: true,
      });
    });

    test('trail has management event selectors with IncludeManagementEvents and ReadWriteType All', () => {
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        EventSelectors: Match.arrayWith([
          Match.objectLike({
            IncludeManagementEvents: true,
            ReadWriteType: 'All',
          }),
        ]),
      });
    });

    test('trail has logging enabled', () => {
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        IsLogging: true,
      });
    });

    test('trail has log file validation enabled', () => {
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        EnableLogFileValidation: true,
      });
    });
  });

  describe('S3 Bucket resource', () => {
    test('creates an S3 bucket with BlockPublicAccess configured', () => {
      template.hasResourceProperties('AWS::S3::Bucket', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
      });
    });
  });

  describe('S3 Bucket Policy', () => {
    test('bucket policy allows cloudtrail.amazonaws.com for GetBucketAcl', () => {
      template.hasResourceProperties('AWS::S3::BucketPolicy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 's3:GetBucketAcl',
              Effect: 'Allow',
              Principal: {
                Service: 'cloudtrail.amazonaws.com',
              },
              Condition: {
                StringEquals: {
                  'aws:SourceOrgID': 'o-lzfhtgvhr7',
                },
              },
            }),
          ]),
        },
      });
    });

    test('bucket policy allows cloudtrail.amazonaws.com for PutObject', () => {
      template.hasResourceProperties('AWS::S3::BucketPolicy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 's3:PutObject',
              Effect: 'Allow',
              Principal: {
                Service: 'cloudtrail.amazonaws.com',
              },
              Condition: {
                StringEquals: {
                  's3:x-amz-acl': 'bucket-owner-full-control',
                  'aws:SourceOrgID': 'o-lzfhtgvhr7',
                },
              },
            }),
          ]),
        },
      });
    });
  });

  describe('Custom trail name', () => {
    test('uses custom trail name when provided', () => {
      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'CustomNameStack');
      new OrgTrail(stack, 'CustomTrail', {
        organizationId: 'o-lzfhtgvhr7',
        trailName: 'MyCustomTrail',
      });
      const customTemplate = Template.fromStack(stack);
      customTemplate.hasResourceProperties('AWS::CloudTrail::Trail', {
        TrailName: 'MyCustomTrail',
      });
    });

    test('uses default trail name OrgSecurityTrail when not provided', () => {
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        TrailName: 'OrgSecurityTrail',
      });
    });
  });
});
