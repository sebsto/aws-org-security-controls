import {
  RDSClient,
  DescribeDBInstancesCommand,
  StopDBInstanceCommand,
  DescribeDBClustersCommand,
  StopDBClusterCommand,
  DBInstance,
  DBCluster,
} from '@aws-sdk/client-rds';

/**
 * Stops all RDS DB instances in the 'available' state.
 * Logs and continues on individual stop failures.
 *
 * @param credentials - STS assumed role credentials
 * @param region - AWS region to scan
 * @returns Array of stopped instance identifiers
 */
export async function stopRdsInstances(
  credentials: any,
  region: string,
): Promise<string[]> {
  const rdsClient = new RDSClient({
    region,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
    },
  });

  const stoppedInstances: string[] = [];

  // Enumerate all DB instances, handling pagination
  let marker: string | undefined;
  const availableInstances: DBInstance[] = [];

  do {
    const response = await rdsClient.send(
      new DescribeDBInstancesCommand({ Marker: marker }),
    );
    if (response.DBInstances) {
      for (const instance of response.DBInstances) {
        if (instance.DBInstanceStatus === 'available') {
          availableInstances.push(instance);
        }
      }
    }
    marker = response.Marker;
  } while (marker);

  // Stop each available instance
  for (const instance of availableInstances) {
    const instanceId = instance.DBInstanceIdentifier || 'unknown';
    try {
      await rdsClient.send(
        new StopDBInstanceCommand({
          DBInstanceIdentifier: instanceId,
        }),
      );
      stoppedInstances.push(instanceId);
    } catch (error: any) {
      console.error('Failed to stop RDS instance:', {
        instanceId,
        region,
        error: error.message,
      });
    }
  }

  return stoppedInstances;
}

/**
 * Stops all Aurora DB clusters in the 'available' state.
 * Logs and continues on individual stop failures.
 *
 * @param credentials - STS assumed role credentials
 * @param region - AWS region to scan
 * @returns Array of stopped cluster identifiers
 */
export async function stopRdsClusters(
  credentials: any,
  region: string,
): Promise<string[]> {
  const rdsClient = new RDSClient({
    region,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
    },
  });

  const stoppedClusters: string[] = [];

  // Enumerate all DB clusters, handling pagination
  let marker: string | undefined;
  const availableClusters: DBCluster[] = [];

  do {
    const response = await rdsClient.send(
      new DescribeDBClustersCommand({ Marker: marker }),
    );
    if (response.DBClusters) {
      for (const cluster of response.DBClusters) {
        if (cluster.Status === 'available') {
          availableClusters.push(cluster);
        }
      }
    }
    marker = response.Marker;
  } while (marker);

  // Stop each available cluster
  for (const cluster of availableClusters) {
    const clusterId = cluster.DBClusterIdentifier || 'unknown';
    try {
      await rdsClient.send(
        new StopDBClusterCommand({
          DBClusterIdentifier: clusterId,
        }),
      );
      stoppedClusters.push(clusterId);
    } catch (error: any) {
      console.error('Failed to stop RDS cluster:', {
        clusterId,
        region,
        error: error.message,
      });
    }
  }

  return stoppedClusters;
}
