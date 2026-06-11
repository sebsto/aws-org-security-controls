import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
  PutRetentionPolicyCommand,
  LogGroup,
} from '@aws-sdk/client-cloudwatch-logs';

const RETENTION_DAYS = 30;

/**
 * Pure filtering logic: returns only log groups where retentionInDays is undefined/null.
 * Exported separately for property-based testing.
 */
export function filterLogGroupsWithoutRetention(logGroups: LogGroup[]): LogGroup[] {
  return logGroups.filter(
    (group) => group.retentionInDays === undefined || group.retentionInDays === null,
  );
}

/**
 * Enumerates all CloudWatch log groups in the given region, and sets a 30-day
 * retention policy on any log group that does not already have one configured.
 *
 * Never modifies log groups that already have any retention policy set.
 * Handles individual failures by logging and continuing.
 *
 * Returns an array of log group names that were successfully updated.
 */
export async function enforceLogRetention(
  credentials: any,
  region: string,
): Promise<string[]> {
  const client = new CloudWatchLogsClient({
    region,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
    },
  });

  // Enumerate all log groups with pagination
  const allLogGroups: LogGroup[] = [];
  let nextToken: string | undefined;

  do {
    const response = await client.send(
      new DescribeLogGroupsCommand({ nextToken }),
    );
    if (response.logGroups) {
      allLogGroups.push(...response.logGroups);
    }
    nextToken = response.nextToken;
  } while (nextToken);

  // Filter to only those without a retention policy
  const groupsWithoutRetention = filterLogGroupsWithoutRetention(allLogGroups);

  // Set retention policy on each, handling individual failures
  const updatedGroups: string[] = [];

  for (const group of groupsWithoutRetention) {
    const logGroupName = group.logGroupName;
    if (!logGroupName) {
      continue;
    }

    try {
      await client.send(
        new PutRetentionPolicyCommand({
          logGroupName,
          retentionInDays: RETENTION_DAYS,
        }),
      );
      updatedGroups.push(logGroupName);
    } catch (error: any) {
      console.error('Failed to set retention policy on log group:', {
        logGroupName,
        region,
        error: error.message,
      });
    }
  }

  return updatedGroups;
}
