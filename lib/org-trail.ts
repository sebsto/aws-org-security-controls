import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { OrgTrailProps } from './types';

export class OrgTrail extends Construct {
  public readonly trail: cloudtrail.CfnTrail;
  public readonly bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: OrgTrailProps) {
    super(scope, id);

    const trailName = props.trailName ?? 'OrgSecurityTrail';

    // Create S3 bucket for CloudTrail logs
    this.bucket = new s3.Bucket(this, 'TrailBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [
        {
          transitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: cdk.Duration.days(90),
            },
          ],
          expiration: cdk.Duration.days(365),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Add bucket policy allowing CloudTrail writes from the organization
    this.bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowCloudTrailGetBucketAcl',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['s3:GetBucketAcl'],
        resources: [this.bucket.bucketArn],
        conditions: {
          StringEquals: {
            'aws:SourceOrgID': props.organizationId,
          },
        },
      })
    );

    this.bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowCloudTrailWrite',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['s3:PutObject'],
        resources: [this.bucket.arnForObjects('AWSLogs/*')],
        conditions: {
          StringEquals: {
            's3:x-amz-acl': 'bucket-owner-full-control',
            'aws:SourceOrgID': props.organizationId,
          },
        },
      })
    );

    // Create CloudTrail organization trail
    this.trail = new cloudtrail.CfnTrail(this, 'Trail', {
      trailName,
      isLogging: true,
      isOrganizationTrail: true,
      isMultiRegionTrail: true,
      s3BucketName: this.bucket.bucketName,
      includeGlobalServiceEvents: true,
      enableLogFileValidation: true,
      eventSelectors: [
        {
          includeManagementEvents: true,
          readWriteType: 'All',
        },
      ],
    });

    // Ensure the trail depends on the bucket policy being applied
    this.trail.node.addDependency(this.bucket);
  }
}
