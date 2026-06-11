import {
  EC2Client,
  DescribeInstancesCommand,
  StopInstancesCommand,
} from '@aws-sdk/client-ec2';
import {
  ECSClient,
  ListClustersCommand,
  ListTasksCommand,
  StopTaskCommand,
} from '@aws-sdk/client-ecs';

/**
 * Stops all running EC2 instances in the given region using the provided credentials.
 * Logs and continues on individual stop failures.
 *
 * @param credentials - AWS STS AssumeRole response Credentials object
 * @param region - AWS region to scan
 * @returns Array of stopped instance IDs
 */
export async function stopEc2Instances(
  credentials: any,
  region: string,
): Promise<string[]> {
  const ec2Client = new EC2Client({
    region,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
    },
  });

  const stoppedInstanceIds: string[] = [];

  try {
    // Enumerate all running instances
    let nextToken: string | undefined;
    const runningInstanceIds: string[] = [];

    do {
      const describeResponse = await ec2Client.send(
        new DescribeInstancesCommand({
          Filters: [
            {
              Name: 'instance-state-name',
              Values: ['running'],
            },
          ],
          NextToken: nextToken,
        }),
      );

      if (describeResponse.Reservations) {
        for (const reservation of describeResponse.Reservations) {
          if (reservation.Instances) {
            for (const instance of reservation.Instances) {
              if (instance.InstanceId) {
                runningInstanceIds.push(instance.InstanceId);
              }
            }
          }
        }
      }

      nextToken = describeResponse.NextToken;
    } while (nextToken);

    // Stop each running instance individually
    for (const instanceId of runningInstanceIds) {
      try {
        await ec2Client.send(
          new StopInstancesCommand({
            InstanceIds: [instanceId],
          }),
        );
        stoppedInstanceIds.push(instanceId);
      } catch (error: any) {
        console.error('Failed to stop EC2 instance:', {
          instanceId,
          region,
          error: error.message,
        });
      }
    }
  } catch (error: any) {
    console.error('Failed to enumerate EC2 instances:', {
      region,
      error: error.message,
    });
  }

  return stoppedInstanceIds;
}

/**
 * Stops all running ECS tasks across all clusters in the given region using the provided credentials.
 * Logs and continues on individual stop failures.
 *
 * @param credentials - AWS STS AssumeRole response Credentials object
 * @param region - AWS region to scan
 * @returns Array of stopped task ARNs
 */
export async function stopEcsTasks(
  credentials: any,
  region: string,
): Promise<string[]> {
  const ecsClient = new ECSClient({
    region,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
    },
  });

  const stoppedTaskArns: string[] = [];

  try {
    // Enumerate all clusters
    let clusterNextToken: string | undefined;
    const clusterArns: string[] = [];

    do {
      const listClustersResponse = await ecsClient.send(
        new ListClustersCommand({
          nextToken: clusterNextToken,
        }),
      );

      if (listClustersResponse.clusterArns) {
        clusterArns.push(...listClustersResponse.clusterArns);
      }

      clusterNextToken = listClustersResponse.nextToken;
    } while (clusterNextToken);

    // For each cluster, list and stop running tasks
    for (const clusterArn of clusterArns) {
      try {
        let taskNextToken: string | undefined;
        const runningTaskArns: string[] = [];

        do {
          const listTasksResponse = await ecsClient.send(
            new ListTasksCommand({
              cluster: clusterArn,
              desiredStatus: 'RUNNING',
              nextToken: taskNextToken,
            }),
          );

          if (listTasksResponse.taskArns) {
            runningTaskArns.push(...listTasksResponse.taskArns);
          }

          taskNextToken = listTasksResponse.nextToken;
        } while (taskNextToken);

        // Stop each running task
        for (const taskArn of runningTaskArns) {
          try {
            await ecsClient.send(
              new StopTaskCommand({
                cluster: clusterArn,
                task: taskArn,
                reason: 'Stopped by Watchdog Lambda for cost control',
              }),
            );
            stoppedTaskArns.push(taskArn);
          } catch (error: any) {
            console.error('Failed to stop ECS task:', {
              taskArn,
              clusterArn,
              region,
              error: error.message,
            });
          }
        }
      } catch (error: any) {
        console.error('Failed to enumerate ECS tasks in cluster:', {
          clusterArn,
          region,
          error: error.message,
        });
      }
    }
  } catch (error: any) {
    console.error('Failed to enumerate ECS clusters:', {
      region,
      error: error.message,
    });
  }

  return stoppedTaskArns;
}
