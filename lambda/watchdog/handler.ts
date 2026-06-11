import {
  OrganizationsClient,
  ListAccountsCommand,
  Account,
} from '@aws-sdk/client-organizations';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import {
  AccountResult,
  RegionResult,
  FailedAccount,
} from './types';
import { compileReport, sendReport } from './report';

const MANAGEMENT_ACCOUNT_ID = process.env.MANAGEMENT_ACCOUNT_ID!;

/**
 * Filters out the management account from the list of accounts.
 * Preserves original order of remaining accounts.
 */
export function filterMemberAccounts(
  accounts: Account[],
  managementAccountId: string,
): Account[] {
  return accounts.filter((account) => account.Id !== managementAccountId);
}

/**
 * Validates that the session duration is exactly 3600 seconds.
 * Rejects any value greater than 3600.
 */
export function validateSessionDuration(duration: number): void {
  if (duration > 3600) {
    throw new Error(
      `Session duration ${duration} exceeds maximum allowed value of 3600 seconds`,
    );
  }
}

/**
 * Stub for processing a region in a member account.
 * Will be replaced by actual action modules in tasks 7.2-7.6.
 */
export async function processRegion(
  credentials: any,
  region: string,
  accountId: string,
): Promise<RegionResult> {
  return {
    region,
    ec2Stopped: [],
    ecsTasksStopped: [],
    rdsInstancesStopped: [],
    rdsClustersStopped: [],
    eipsReleased: [],
    logGroupsUpdated: [],
    unusedEbsVolumes: [],
    emptyAlbs: [],
    errors: [],
  };
}

/**
 * Lists all accounts in the organization, handling pagination.
 */
async function listAllAccounts(
  orgClient: OrganizationsClient,
): Promise<Account[]> {
  const accounts: Account[] = [];
  let nextToken: string | undefined;

  do {
    const response = await orgClient.send(
      new ListAccountsCommand({ NextToken: nextToken }),
    );
    if (response.Accounts) {
      accounts.push(...response.Accounts);
    }
    nextToken = response.NextToken;
  } while (nextToken);

  return accounts;
}

/**
 * Main Watchdog Lambda handler.
 * Triggered by EventBridge scheduled event (weekly on Friday).
 */
export const handler = async (event: any): Promise<void> => {
  // Read environment variables
  const approvedRegions = (process.env.APPROVED_REGIONS || '').split(',').filter(Boolean);
  const crossAccountRoleName =
    process.env.CROSS_ACCOUNT_ROLE_NAME || 'OrganizationAccountAccessRole';
  const recipientEmail = process.env.RECIPIENT_EMAIL || '';
  const senderEmail = process.env.SENDER_EMAIL || '';

  const orgClient = new OrganizationsClient({});
  const stsClient = new STSClient({});

  // Step 1: List all accounts in the organization
  let allAccounts: Account[];
  try {
    allAccounts = await listAllAccounts(orgClient);
  } catch (error: any) {
    console.error('Failed to list organization accounts, aborting:', {
      error: error.message,
    });
    return;
  }

  // Step 2: Filter out management account
  const memberAccounts = filterMemberAccounts(allAccounts, MANAGEMENT_ACCOUNT_ID);

  const accountResults: AccountResult[] = [];
  const failedAccounts: FailedAccount[] = [];

  // Step 3: Process each member account
  for (const account of memberAccounts) {
    const accountId = account.Id || 'unknown';
    const accountName = account.Name || 'unknown';

    // Assume role in the member account
    let credentials: any;
    try {
      validateSessionDuration(3600);
      const assumeRoleResponse = await stsClient.send(
        new AssumeRoleCommand({
          RoleArn: `arn:aws:iam::${accountId}:role/${crossAccountRoleName}`,
          RoleSessionName: `watchdog-${accountId}`,
          DurationSeconds: 3600,
        }),
      );
      credentials = assumeRoleResponse.Credentials;
    } catch (error: any) {
      console.error('Failed to assume role in account:', {
        accountId,
        accountName,
        error: error.message,
      });
      failedAccounts.push({
        accountId,
        accountName,
        error: error.message,
      });
      continue;
    }

    // Step 4: For each approved region, execute action modules
    const regionResults: RegionResult[] = [];
    for (const region of approvedRegions) {
      const regionResult = await processRegion(credentials, region, accountId);
      regionResults.push(regionResult);
    }

    accountResults.push({
      accountId,
      accountName,
      roleAssumptionSuccess: true,
      regions: regionResults,
    });
  }

  // Step 5: Compile execution report
  const report = compileReport(
    accountResults,
    failedAccounts,
    memberAccounts.length,
  );

  // Step 6: Send report via SES
  if (recipientEmail && senderEmail) {
    await sendReport(report, senderEmail, recipientEmail);
  } else {
    console.error('Missing RECIPIENT_EMAIL or SENDER_EMAIL, skipping report delivery');
  }
};
