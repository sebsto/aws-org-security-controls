import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import {
  AccountResult,
  ExecutionReport,
  AccountSummary,
  FailedAccount,
} from './types';

/**
 * Compiles the execution report from account results.
 * Builds per-account summaries by aggregating region-level action counts,
 * includes all failed accounts, and all resource entries (EBS volumes, ALBs).
 */
export function compileReport(
  accountResults: AccountResult[],
  failedAccounts: FailedAccount[],
  totalAccounts: number,
): ExecutionReport {
  const accountSummaries: AccountSummary[] = accountResults.map((result) => {
    const summary: AccountSummary = {
      accountId: result.accountId,
      accountName: result.accountName,
      ec2StoppedCount: result.regions.reduce(
        (sum, r) => sum + r.ec2Stopped.length,
        0,
      ),
      ecsTasksStoppedCount: result.regions.reduce(
        (sum, r) => sum + r.ecsTasksStopped.length,
        0,
      ),
      rdsInstancesStoppedCount: result.regions.reduce(
        (sum, r) => sum + r.rdsInstancesStopped.length,
        0,
      ),
      rdsClustersStoppedCount: result.regions.reduce(
        (sum, r) => sum + r.rdsClustersStopped.length,
        0,
      ),
      eipsReleasedCount: result.regions.reduce(
        (sum, r) => sum + r.eipsReleased.length,
        0,
      ),
      logGroupsUpdatedCount: result.regions.reduce(
        (sum, r) => sum + r.logGroupsUpdated.length,
        0,
      ),
      unusedEbsVolumes: result.regions.flatMap((r) => r.unusedEbsVolumes),
      emptyAlbs: result.regions.flatMap((r) => r.emptyAlbs),
      errors: result.regions.flatMap((r) => r.errors),
    };
    return summary;
  });

  return {
    executionTime: new Date().toISOString(),
    totalAccounts,
    processedAccounts: accountResults.length,
    failedAccounts,
    accountResults: accountSummaries,
  };
}

/**
 * Formats the execution report as a structured HTML email body.
 * Includes summary section, failed accounts section, per-account breakdowns,
 * and resource detail tables for unused EBS volumes and empty ALBs.
 */
export function formatReportHtml(report: ExecutionReport): string {
  // Summary section
  const summarySection = `
    <h2>Summary</h2>
    <table border="1" cellpadding="4" cellspacing="0">
      <tr><td><strong>Total Accounts</strong></td><td>${report.totalAccounts}</td></tr>
      <tr><td><strong>Processed</strong></td><td>${report.processedAccounts}</td></tr>
      <tr><td><strong>Failed</strong></td><td>${report.failedAccounts.length}</td></tr>
    </table>`;

  // Failed accounts section
  let failedSection = '';
  if (report.failedAccounts.length > 0) {
    const failedRows = report.failedAccounts
      .map(
        (f) =>
          `<tr><td>${f.accountId}</td><td>${f.accountName}</td><td>${f.error}</td></tr>`,
      )
      .join('');
    failedSection = `
    <h2>Failed Accounts</h2>
    <table border="1" cellpadding="4" cellspacing="0">
      <tr><th>Account ID</th><th>Account Name</th><th>Error</th></tr>
      ${failedRows}
    </table>`;
  }

  // Per-account breakdowns
  const accountSections = report.accountResults
    .map((a) => {
      let ebsTable = '';
      if (a.unusedEbsVolumes.length > 0) {
        const ebsRows = a.unusedEbsVolumes
          .map(
            (v) =>
              `<tr><td>${v.volumeId}</td><td>${v.sizeGiB}</td><td>${v.region}</td></tr>`,
          )
          .join('');
        ebsTable = `
      <h4>Unused EBS Volumes</h4>
      <table border="1" cellpadding="4" cellspacing="0">
        <tr><th>Volume ID</th><th>Size (GiB)</th><th>Region</th></tr>
        ${ebsRows}
      </table>`;
      }

      let albTable = '';
      if (a.emptyAlbs.length > 0) {
        const albRows = a.emptyAlbs
          .map(
            (alb) =>
              `<tr><td>${alb.albName}</td><td>${alb.albArn}</td><td>${alb.region}</td></tr>`,
          )
          .join('');
        albTable = `
      <h4>Empty ALBs</h4>
      <table border="1" cellpadding="4" cellspacing="0">
        <tr><th>ALB Name</th><th>ALB ARN</th><th>Region</th></tr>
        ${albRows}
      </table>`;
      }

      return `
    <h3>${a.accountId} (${a.accountName})</h3>
    <table border="1" cellpadding="4" cellspacing="0">
      <tr><td>EC2 Instances Stopped</td><td>${a.ec2StoppedCount}</td></tr>
      <tr><td>ECS Tasks Stopped</td><td>${a.ecsTasksStoppedCount}</td></tr>
      <tr><td>RDS Instances Stopped</td><td>${a.rdsInstancesStoppedCount}</td></tr>
      <tr><td>RDS Clusters Stopped</td><td>${a.rdsClustersStoppedCount}</td></tr>
      <tr><td>EIPs Released</td><td>${a.eipsReleasedCount}</td></tr>
      <tr><td>Log Groups Updated</td><td>${a.logGroupsUpdatedCount}</td></tr>
      <tr><td>Unused EBS Volumes</td><td>${a.unusedEbsVolumes.length}</td></tr>
      <tr><td>Empty ALBs</td><td>${a.emptyAlbs.length}</td></tr>
    </table>
    ${ebsTable}
    ${albTable}`;
    })
    .join('');

  return `<html><body>
  <h1>Watchdog Execution Report</h1>
  <p>Execution time: ${report.executionTime}</p>
  ${summarySection}
  ${failedSection}
  <h2>Account Results</h2>
  ${accountSections}
</body></html>`;
}

/**
 * Sends the execution report via SES.
 * Logs error on explicit SES failure. Does NOT log pending delivery states as failures.
 */
export async function sendReport(
  report: ExecutionReport,
  senderEmail: string,
  recipientEmail: string,
): Promise<void> {
  const sesClient = new SESClient({});
  const htmlBody = formatReportHtml(report);

  const command = new SendEmailCommand({
    Source: senderEmail,
    Destination: {
      ToAddresses: [recipientEmail],
    },
    Message: {
      Subject: {
        Data: `Watchdog Report - ${report.executionTime}`,
      },
      Body: {
        Html: {
          Data: htmlBody,
        },
      },
    },
  });

  try {
    await sesClient.send(command);
  } catch (error: any) {
    console.error('Failed to send execution report via SES:', {
      error: error.message,
      executionTime: report.executionTime,
    });
  }
}
