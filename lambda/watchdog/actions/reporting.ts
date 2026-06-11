import {
  EC2Client,
  DescribeVolumesCommand,
  Volume,
} from '@aws-sdk/client-ec2';
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  LoadBalancer,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import { VolumeInfo, AlbInfo } from '../types';

/**
 * Filters volumes to only those in the 'available' state (not attached to any instance).
 * Exported for testing.
 */
export function filterAvailableVolumes(volumes: Volume[]): Volume[] {
  return volumes.filter((v) => v.State === 'available');
}

/**
 * Determines if an ALB is "empty" — all its target groups have zero registered targets.
 * Exported for testing.
 */
export function isAlbEmpty(
  targetGroupHealths: { targetGroupArn: string; targets: number }[],
): boolean {
  if (targetGroupHealths.length === 0) {
    return true;
  }
  return targetGroupHealths.every((tg) => tg.targets === 0);
}

/**
 * Enumerates EBS volumes in 'available' state (not attached to any instance).
 * Returns array of VolumeInfo objects with volumeId, sizeGiB, and region.
 * Logs failures and returns empty array on error.
 */
export async function findUnusedEbsVolumes(
  credentials: any,
  region: string,
): Promise<VolumeInfo[]> {
  try {
    const ec2Client = new EC2Client({
      region,
      credentials: {
        accessKeyId: credentials.AccessKeyId,
        secretAccessKey: credentials.SecretAccessKey,
        sessionToken: credentials.SessionToken,
      },
    });

    const response = await ec2Client.send(
      new DescribeVolumesCommand({
        Filters: [
          {
            Name: 'status',
            Values: ['available'],
          },
        ],
      }),
    );

    const volumes = response.Volumes || [];
    return volumes.map((v) => ({
      volumeId: v.VolumeId || 'unknown',
      sizeGiB: v.Size || 0,
      region,
    }));
  } catch (error: any) {
    console.error('Failed to enumerate EBS volumes:', {
      region,
      error: error.message,
    });
    return [];
  }
}

/**
 * Enumerates Application Load Balancers and identifies those where all target groups
 * have zero registered targets (empty ALBs).
 * Returns array of AlbInfo objects with albName, albArn, and region.
 * Logs failures and continues.
 */
export async function findEmptyAlbs(
  credentials: any,
  region: string,
): Promise<AlbInfo[]> {
  try {
    const elbClient = new ElasticLoadBalancingV2Client({
      region,
      credentials: {
        accessKeyId: credentials.AccessKeyId,
        secretAccessKey: credentials.SecretAccessKey,
        sessionToken: credentials.SessionToken,
      },
    });

    const lbResponse = await elbClient.send(
      new DescribeLoadBalancersCommand({}),
    );

    const allLbs = lbResponse.LoadBalancers || [];
    const albs = allLbs.filter((lb) => lb.Type === 'application');

    const emptyAlbs: AlbInfo[] = [];

    for (const alb of albs) {
      try {
        const albArn = alb.LoadBalancerArn || '';
        const albName = alb.LoadBalancerName || 'unknown';

        const tgResponse = await elbClient.send(
          new DescribeTargetGroupsCommand({
            LoadBalancerArn: albArn,
          }),
        );

        const targetGroups = tgResponse.TargetGroups || [];
        const targetGroupHealths: { targetGroupArn: string; targets: number }[] = [];

        for (const tg of targetGroups) {
          try {
            const healthResponse = await elbClient.send(
              new DescribeTargetHealthCommand({
                TargetGroupArn: tg.TargetGroupArn,
              }),
            );

            targetGroupHealths.push({
              targetGroupArn: tg.TargetGroupArn || '',
              targets: (healthResponse.TargetHealthDescriptions || []).length,
            });
          } catch (error: any) {
            console.error('Failed to describe target health:', {
              targetGroupArn: tg.TargetGroupArn,
              region,
              error: error.message,
            });
            // If we can't check a target group, assume it has targets (don't falsely report)
            targetGroupHealths.push({
              targetGroupArn: tg.TargetGroupArn || '',
              targets: 1,
            });
          }
        }

        if (isAlbEmpty(targetGroupHealths)) {
          emptyAlbs.push({
            albName,
            albArn,
            region,
          });
        }
      } catch (error: any) {
        console.error('Failed to check ALB target groups:', {
          albArn: alb.LoadBalancerArn,
          region,
          error: error.message,
        });
        // Continue to next ALB
      }
    }

    return emptyAlbs;
  } catch (error: any) {
    console.error('Failed to enumerate ALBs:', {
      region,
      error: error.message,
    });
    return [];
  }
}
