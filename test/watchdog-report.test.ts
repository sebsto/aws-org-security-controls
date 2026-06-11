// Mock SES client - must be declared before imports due to jest hoisting
const mockSend = jest.fn();
jest.mock('@aws-sdk/client-ses', () => {
  return {
    SESClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
    SendEmailCommand: jest.fn((params: any) => ({ ...params, _type: 'SendEmail' })),
  };
});

import { compileReport, formatReportHtml, sendReport } from '../lambda/watchdog/report';
import { AccountResult, FailedAccount } from '../lambda/watchdog/types';

describe('Watchdog Report Module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('compileReport', () => {
    test('compiles report from account results with correct counts', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111111111111',
          accountName: 'dev-account',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: ['i-1', 'i-2'],
              ecsTasksStopped: ['task-1'],
              rdsInstancesStopped: ['db-1'],
              rdsClustersStopped: [],
              eipsReleased: ['eipalloc-1'],
              logGroupsUpdated: ['/aws/lambda/fn1'],
              unusedEbsVolumes: [{ volumeId: 'vol-1', sizeGiB: 100, region: 'eu-west-1' }],
              emptyAlbs: [{ albName: 'my-alb', albArn: 'arn:aws:elasticloadbalancing:eu-west-1:111:loadbalancer/app/my-alb/123', region: 'eu-west-1' }],
              errors: [],
            },
            {
              region: 'eu-central-1',
              ec2Stopped: ['i-3'],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: ['aurora-1'],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [],
              emptyAlbs: [],
              errors: ['Failed to describe EBS in eu-central-1'],
            },
          ],
        },
      ];

      const failedAccounts: FailedAccount[] = [
        { accountId: '222222222222', accountName: 'staging', error: 'Access denied' },
      ];

      const report = compileReport(accountResults, failedAccounts, 3);

      expect(report.totalAccounts).toBe(3);
      expect(report.processedAccounts).toBe(1);
      expect(report.failedAccounts).toHaveLength(1);
      expect(report.failedAccounts[0].accountId).toBe('222222222222');
      expect(report.failedAccounts[0].error).toBe('Access denied');
      expect(report.accountResults).toHaveLength(1);

      const summary = report.accountResults[0];
      expect(summary.accountId).toBe('111111111111');
      expect(summary.accountName).toBe('dev-account');
      expect(summary.ec2StoppedCount).toBe(3); // 2 + 1 across regions
      expect(summary.ecsTasksStoppedCount).toBe(1);
      expect(summary.rdsInstancesStoppedCount).toBe(1);
      expect(summary.rdsClustersStoppedCount).toBe(1);
      expect(summary.eipsReleasedCount).toBe(1);
      expect(summary.logGroupsUpdatedCount).toBe(1);
      expect(summary.unusedEbsVolumes).toHaveLength(1);
      expect(summary.unusedEbsVolumes[0].volumeId).toBe('vol-1');
      expect(summary.emptyAlbs).toHaveLength(1);
      expect(summary.emptyAlbs[0].albName).toBe('my-alb');
      expect(summary.errors).toHaveLength(1);
    });

    test('compiles report with empty account results', () => {
      const report = compileReport([], [], 5);

      expect(report.totalAccounts).toBe(5);
      expect(report.processedAccounts).toBe(0);
      expect(report.failedAccounts).toHaveLength(0);
      expect(report.accountResults).toHaveLength(0);
      expect(report.executionTime).toBeDefined();
    });

    test('includes all failed accounts in report', () => {
      const failedAccounts: FailedAccount[] = [
        { accountId: '111', accountName: 'a1', error: 'err1' },
        { accountId: '222', accountName: 'a2', error: 'err2' },
        { accountId: '333', accountName: 'a3', error: 'err3' },
      ];

      const report = compileReport([], failedAccounts, 3);

      expect(report.failedAccounts).toHaveLength(3);
      expect(report.failedAccounts).toEqual(failedAccounts);
    });

    test('aggregates resource entries from multiple regions', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111',
          accountName: 'test',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: [],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [
                { volumeId: 'vol-1', sizeGiB: 50, region: 'eu-west-1' },
                { volumeId: 'vol-2', sizeGiB: 200, region: 'eu-west-1' },
              ],
              emptyAlbs: [{ albName: 'alb-1', albArn: 'arn:1', region: 'eu-west-1' }],
              errors: [],
            },
            {
              region: 'us-east-1',
              ec2Stopped: [],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [
                { volumeId: 'vol-3', sizeGiB: 500, region: 'us-east-1' },
              ],
              emptyAlbs: [{ albName: 'alb-2', albArn: 'arn:2', region: 'us-east-1' }],
              errors: [],
            },
          ],
        },
      ];

      const report = compileReport(accountResults, [], 1);
      const summary = report.accountResults[0];

      expect(summary.unusedEbsVolumes).toHaveLength(3);
      expect(summary.emptyAlbs).toHaveLength(2);
    });
  });

  describe('formatReportHtml', () => {
    test('includes summary section with counts', () => {
      const report = compileReport([], [], 5);
      const html = formatReportHtml(report);

      expect(html).toContain('<h1>Watchdog Execution Report</h1>');
      expect(html).toContain('<h2>Summary</h2>');
      expect(html).toContain('5'); // total accounts
      expect(html).toContain('0'); // processed
    });

    test('includes failed accounts section when there are failures', () => {
      const failedAccounts: FailedAccount[] = [
        { accountId: '999', accountName: 'broken', error: 'Role not found' },
      ];
      const report = compileReport([], failedAccounts, 2);
      const html = formatReportHtml(report);

      expect(html).toContain('<h2>Failed Accounts</h2>');
      expect(html).toContain('999');
      expect(html).toContain('broken');
      expect(html).toContain('Role not found');
    });

    test('omits failed accounts section when there are no failures', () => {
      const report = compileReport([], [], 1);
      const html = formatReportHtml(report);

      expect(html).not.toContain('<h2>Failed Accounts</h2>');
    });

    test('includes per-account breakdown with action counts', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111',
          accountName: 'dev',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: ['i-1', 'i-2'],
              ecsTasksStopped: ['t-1'],
              rdsInstancesStopped: ['db-1'],
              rdsClustersStopped: [],
              eipsReleased: ['eip-1'],
              logGroupsUpdated: ['lg-1', 'lg-2'],
              unusedEbsVolumes: [],
              emptyAlbs: [],
              errors: [],
            },
          ],
        },
      ];
      const report = compileReport(accountResults, [], 1);
      const html = formatReportHtml(report);

      expect(html).toContain('111');
      expect(html).toContain('dev');
      expect(html).toContain('EC2 Instances Stopped');
      expect(html).toContain('ECS Tasks Stopped');
      expect(html).toContain('RDS Instances Stopped');
    });

    test('includes EBS volume detail table when volumes exist', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111',
          accountName: 'dev',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: [],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [{ volumeId: 'vol-abc123', sizeGiB: 100, region: 'eu-west-1' }],
              emptyAlbs: [],
              errors: [],
            },
          ],
        },
      ];
      const report = compileReport(accountResults, [], 1);
      const html = formatReportHtml(report);

      expect(html).toContain('Unused EBS Volumes');
      expect(html).toContain('vol-abc123');
      expect(html).toContain('100');
    });

    test('includes ALB detail table when empty ALBs exist', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111',
          accountName: 'dev',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: [],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [],
              emptyAlbs: [{ albName: 'idle-alb', albArn: 'arn:aws:elasticloadbalancing:eu-west-1:111:loadbalancer/app/idle-alb/456', region: 'eu-west-1' }],
              errors: [],
            },
          ],
        },
      ];
      const report = compileReport(accountResults, [], 1);
      const html = formatReportHtml(report);

      expect(html).toContain('Empty ALBs');
      expect(html).toContain('idle-alb');
      expect(html).toContain('arn:aws:elasticloadbalancing:eu-west-1:111:loadbalancer/app/idle-alb/456');
    });
  });

  describe('sendReport', () => {
    test('sends email via SES with formatted HTML', async () => {
      mockSend.mockResolvedValueOnce({ MessageId: 'msg-123' });

      const report = compileReport([], [], 1);
      await sendReport(report, 'sender@example.com', 'recipient@example.com');

      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    test('logs error on SES failure without throwing', async () => {
      mockSend.mockRejectedValueOnce(new Error('MessageRejected'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const report = compileReport([], [], 1);
      await expect(
        sendReport(report, 'sender@example.com', 'recipient@example.com'),
      ).resolves.toBeUndefined();

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to send execution report via SES:',
        expect.objectContaining({ error: 'MessageRejected' }),
      );

      consoleErrorSpy.mockRestore();
    });
  });
});
