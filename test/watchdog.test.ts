// Mock AWS SDK clients - must be declared before imports due to jest hoisting
const mockEc2Send = jest.fn();
const mockEcsSend = jest.fn();
const mockElbSend = jest.fn();
const mockLogsSend = jest.fn();

jest.mock('@aws-sdk/client-ec2', () => {
  return {
    EC2Client: jest.fn().mockImplementation(() => ({ send: mockEc2Send })),
    DescribeInstancesCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeInstances' })),
    StopInstancesCommand: jest.fn((params: any) => ({ ...params, _type: 'StopInstances' })),
    DescribeAddressesCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeAddresses' })),
    ReleaseAddressCommand: jest.fn((params: any) => ({ ...params, _type: 'ReleaseAddress' })),
    DescribeVolumesCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeVolumes' })),
  };
});

jest.mock('@aws-sdk/client-ecs', () => {
  return {
    ECSClient: jest.fn().mockImplementation(() => ({ send: mockEcsSend })),
    ListClustersCommand: jest.fn((params: any) => ({ ...params, _type: 'ListClusters' })),
    ListTasksCommand: jest.fn((params: any) => ({ ...params, _type: 'ListTasks' })),
    StopTaskCommand: jest.fn((params: any) => ({ ...params, _type: 'StopTask' })),
  };
});

jest.mock('@aws-sdk/client-elastic-load-balancing-v2', () => {
  return {
    ElasticLoadBalancingV2Client: jest.fn().mockImplementation(() => ({ send: mockElbSend })),
    DescribeLoadBalancersCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeLoadBalancers' })),
    DescribeTargetGroupsCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeTargetGroups' })),
    DescribeTargetHealthCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeTargetHealth' })),
  };
});

jest.mock('@aws-sdk/client-cloudwatch-logs', () => {
  return {
    CloudWatchLogsClient: jest.fn().mockImplementation(() => ({ send: mockLogsSend })),
    DescribeLogGroupsCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeLogGroups' })),
    PutRetentionPolicyCommand: jest.fn((params: any) => ({ ...params, _type: 'PutRetentionPolicy' })),
  };
});

import { filterMemberAccounts, validateSessionDuration } from '../lambda/watchdog/handler';
import { stopEc2Instances, stopEcsTasks } from '../lambda/watchdog/actions/compute';
import { releaseUnattachedEips, filterUnattachedEips } from '../lambda/watchdog/actions/network';
import { findUnusedEbsVolumes, findEmptyAlbs, filterAvailableVolumes, isAlbEmpty } from '../lambda/watchdog/actions/reporting';
import { enforceLogRetention, filterLogGroupsWithoutRetention } from '../lambda/watchdog/actions/logs';
import { compileReport } from '../lambda/watchdog/report';
import { AccountResult, FailedAccount } from '../lambda/watchdog/types';

const mockCredentials = {
  AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  SessionToken: 'FwoGZXIvYXdzEBYaDH...',
};

describe('Watchdog Lambda Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ─── Account Discovery ──────────────────────────────────────────────────────

  describe('filterMemberAccounts', () => {
    test('excludes the management account from the list', () => {
      const accounts = [
        { Id: '000000000000', Name: 'management' },
        { Id: '111111111111', Name: 'dev' },
        { Id: '222222222222', Name: 'staging' },
      ];

      const result = filterMemberAccounts(accounts, '000000000000');

      expect(result).toHaveLength(2);
      expect(result.map((a) => a.Id)).toEqual(['111111111111', '222222222222']);
    });

    test('preserves original order of remaining accounts', () => {
      const accounts = [
        { Id: '333333333333', Name: 'prod' },
        { Id: '000000000000', Name: 'management' },
        { Id: '111111111111', Name: 'dev' },
        { Id: '222222222222', Name: 'staging' },
      ];

      const result = filterMemberAccounts(accounts, '000000000000');

      expect(result.map((a) => a.Id)).toEqual([
        '333333333333',
        '111111111111',
        '222222222222',
      ]);
    });

    test('returns all accounts when management account is not in the list', () => {
      const accounts = [
        { Id: '111111111111', Name: 'dev' },
        { Id: '222222222222', Name: 'staging' },
      ];

      const result = filterMemberAccounts(accounts, '000000000000');

      expect(result).toHaveLength(2);
    });

    test('returns empty array when only management account exists', () => {
      const accounts = [{ Id: '000000000000', Name: 'management' }];

      const result = filterMemberAccounts(accounts, '000000000000');

      expect(result).toHaveLength(0);
    });

    test('returns empty array for empty input', () => {
      const result = filterMemberAccounts([], '000000000000');

      expect(result).toHaveLength(0);
    });
  });

  // ─── Session Duration Validation ───────────────────────────────────────────

  describe('validateSessionDuration', () => {
    test('accepts exactly 3600 seconds', () => {
      expect(() => validateSessionDuration(3600)).not.toThrow();
    });

    test('accepts values less than 3600', () => {
      expect(() => validateSessionDuration(900)).not.toThrow();
      expect(() => validateSessionDuration(1)).not.toThrow();
    });

    test('rejects values greater than 3600', () => {
      expect(() => validateSessionDuration(3601)).toThrow(
        'Session duration 3601 exceeds maximum allowed value of 3600 seconds',
      );
    });

    test('rejects large values', () => {
      expect(() => validateSessionDuration(7200)).toThrow();
    });
  });

  // ─── EC2 Stop Module ────────────────────────────────────────────────────────

  describe('stopEc2Instances', () => {
    test('stops all running EC2 instances and returns their IDs', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Reservations: [
          {
            Instances: [
              { InstanceId: 'i-abc123' },
              { InstanceId: 'i-def456' },
            ],
          },
        ],
        NextToken: undefined,
      });
      // StopInstances calls
      mockEc2Send.mockResolvedValueOnce({});
      mockEc2Send.mockResolvedValueOnce({});

      const result = await stopEc2Instances(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['i-abc123', 'i-def456']);
      expect(mockEc2Send).toHaveBeenCalledTimes(3);
    });

    test('returns empty array when no running instances exist', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Reservations: [],
        NextToken: undefined,
      });

      const result = await stopEc2Instances(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockEc2Send).toHaveBeenCalledTimes(1);
    });

    test('handles pagination when listing instances', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Reservations: [{ Instances: [{ InstanceId: 'i-page1' }] }],
        NextToken: 'token-1',
      });
      mockEc2Send.mockResolvedValueOnce({
        Reservations: [{ Instances: [{ InstanceId: 'i-page2' }] }],
        NextToken: undefined,
      });
      // StopInstances calls
      mockEc2Send.mockResolvedValueOnce({});
      mockEc2Send.mockResolvedValueOnce({});

      const result = await stopEc2Instances(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['i-page1', 'i-page2']);
      expect(mockEc2Send).toHaveBeenCalledTimes(4);
    });

    test('logs failure and continues when an instance stop fails', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Reservations: [
          { Instances: [{ InstanceId: 'i-ok' }, { InstanceId: 'i-fail' }, { InstanceId: 'i-ok2' }] },
        ],
        NextToken: undefined,
      });
      mockEc2Send.mockResolvedValueOnce({}); // i-ok succeeds
      mockEc2Send.mockRejectedValueOnce(new Error('UnauthorizedOperation')); // i-fail fails
      mockEc2Send.mockResolvedValueOnce({}); // i-ok2 succeeds

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await stopEc2Instances(mockCredentials, 'us-east-1');

      expect(result).toEqual(['i-ok', 'i-ok2']);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to stop EC2 instance:', {
        instanceId: 'i-fail',
        region: 'us-east-1',
        error: 'UnauthorizedOperation',
      });

      consoleErrorSpy.mockRestore();
    });

    test('returns empty array when DescribeInstances fails', async () => {
      mockEc2Send.mockRejectedValueOnce(new Error('NetworkError'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await stopEc2Instances(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  // ─── ECS Stop Module ────────────────────────────────────────────────────────

  describe('stopEcsTasks', () => {
    test('stops all running tasks across clusters', async () => {
      // ListClusters
      mockEcsSend.mockResolvedValueOnce({
        clusterArns: ['arn:aws:ecs:eu-west-1:111:cluster/my-cluster'],
        nextToken: undefined,
      });
      // ListTasks for the cluster
      mockEcsSend.mockResolvedValueOnce({
        taskArns: ['arn:aws:ecs:eu-west-1:111:task/my-cluster/task-1'],
        nextToken: undefined,
      });
      // StopTask
      mockEcsSend.mockResolvedValueOnce({});

      const result = await stopEcsTasks(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['arn:aws:ecs:eu-west-1:111:task/my-cluster/task-1']);
      expect(mockEcsSend).toHaveBeenCalledTimes(3);
    });

    test('returns empty array when no clusters exist', async () => {
      mockEcsSend.mockResolvedValueOnce({
        clusterArns: [],
        nextToken: undefined,
      });

      const result = await stopEcsTasks(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockEcsSend).toHaveBeenCalledTimes(1);
    });

    test('returns empty array when clusters have no running tasks', async () => {
      mockEcsSend.mockResolvedValueOnce({
        clusterArns: ['arn:aws:ecs:eu-west-1:111:cluster/empty-cluster'],
        nextToken: undefined,
      });
      mockEcsSend.mockResolvedValueOnce({
        taskArns: [],
        nextToken: undefined,
      });

      const result = await stopEcsTasks(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockEcsSend).toHaveBeenCalledTimes(2);
    });

    test('logs failure and continues when a task stop fails', async () => {
      mockEcsSend.mockResolvedValueOnce({
        clusterArns: ['arn:aws:ecs:eu-west-1:111:cluster/cl1'],
        nextToken: undefined,
      });
      mockEcsSend.mockResolvedValueOnce({
        taskArns: ['task-ok', 'task-fail'],
        nextToken: undefined,
      });
      mockEcsSend.mockResolvedValueOnce({}); // task-ok succeeds
      mockEcsSend.mockRejectedValueOnce(new Error('TaskNotFound')); // task-fail fails

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await stopEcsTasks(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['task-ok']);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to stop ECS task:', expect.objectContaining({
        taskArn: 'task-fail',
        error: 'TaskNotFound',
      }));

      consoleErrorSpy.mockRestore();
    });

    test('returns empty array when ListClusters fails', async () => {
      mockEcsSend.mockRejectedValueOnce(new Error('AccessDenied'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await stopEcsTasks(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  // ─── EIP Release Module ─────────────────────────────────────────────────────

  describe('releaseUnattachedEips', () => {
    test('releases EIPs without network interface association', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Addresses: [
          { AllocationId: 'eipalloc-1', NetworkInterfaceId: undefined, AssociationId: undefined },
          { AllocationId: 'eipalloc-2', NetworkInterfaceId: 'eni-123', AssociationId: 'assoc-1' },
          { AllocationId: 'eipalloc-3', NetworkInterfaceId: undefined, AssociationId: undefined },
        ],
      });
      // ReleaseAddress calls for unattached
      mockEc2Send.mockResolvedValueOnce({});
      mockEc2Send.mockResolvedValueOnce({});

      const result = await releaseUnattachedEips(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['eipalloc-1', 'eipalloc-3']);
      expect(mockEc2Send).toHaveBeenCalledTimes(3); // 1 describe + 2 releases
    });

    test('returns empty array when all EIPs are attached', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Addresses: [
          { AllocationId: 'eipalloc-1', NetworkInterfaceId: 'eni-1', AssociationId: 'assoc-1' },
        ],
      });

      const result = await releaseUnattachedEips(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockEc2Send).toHaveBeenCalledTimes(1);
    });

    test('returns empty array when no EIPs exist', async () => {
      mockEc2Send.mockResolvedValueOnce({ Addresses: [] });

      const result = await releaseUnattachedEips(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
    });

    test('logs failure and continues when a release fails', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Addresses: [
          { AllocationId: 'eipalloc-ok' },
          { AllocationId: 'eipalloc-fail' },
          { AllocationId: 'eipalloc-ok2' },
        ],
      });
      mockEc2Send.mockResolvedValueOnce({}); // ok
      mockEc2Send.mockRejectedValueOnce(new Error('AuthFailure')); // fail
      mockEc2Send.mockResolvedValueOnce({}); // ok2

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await releaseUnattachedEips(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['eipalloc-ok', 'eipalloc-ok2']);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to release Elastic IP:', expect.objectContaining({
        allocationId: 'eipalloc-fail',
        error: 'AuthFailure',
      }));

      consoleErrorSpy.mockRestore();
    });

    test('returns empty array when DescribeAddresses fails', async () => {
      mockEc2Send.mockRejectedValueOnce(new Error('ServiceUnavailable'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await releaseUnattachedEips(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  describe('filterUnattachedEips', () => {
    test('filters EIPs with no NetworkInterfaceId and no AssociationId', () => {
      const addresses = [
        { AllocationId: 'eip-1', NetworkInterfaceId: undefined, AssociationId: undefined },
        { AllocationId: 'eip-2', NetworkInterfaceId: 'eni-1', AssociationId: 'assoc-1' },
        { AllocationId: 'eip-3' }, // no fields at all -> unattached
      ];

      const result = filterUnattachedEips(addresses);

      expect(result).toHaveLength(2);
      expect(result[0].AllocationId).toBe('eip-1');
      expect(result[1].AllocationId).toBe('eip-3');
    });
  });

  // ─── EBS/ALB Reporting Module ───────────────────────────────────────────────

  describe('findUnusedEbsVolumes', () => {
    test('returns volumes in available state with correct fields', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Volumes: [
          { VolumeId: 'vol-1', Size: 100, State: 'available' },
          { VolumeId: 'vol-2', Size: 500, State: 'available' },
        ],
      });

      const result = await findUnusedEbsVolumes(mockCredentials, 'eu-west-1');

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ volumeId: 'vol-1', sizeGiB: 100, region: 'eu-west-1' });
      expect(result[1]).toEqual({ volumeId: 'vol-2', sizeGiB: 500, region: 'eu-west-1' });
    });

    test('returns empty array when no available volumes exist', async () => {
      mockEc2Send.mockResolvedValueOnce({ Volumes: [] });

      const result = await findUnusedEbsVolumes(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
    });

    test('returns empty array on DescribeVolumes failure', async () => {
      mockEc2Send.mockRejectedValueOnce(new Error('RequestLimitExceeded'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await findUnusedEbsVolumes(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to enumerate EBS volumes:', expect.objectContaining({
        region: 'eu-west-1',
      }));

      consoleErrorSpy.mockRestore();
    });
  });

  describe('findEmptyAlbs', () => {
    test('identifies ALBs where all target groups have zero targets', async () => {
      // DescribeLoadBalancers
      mockElbSend.mockResolvedValueOnce({
        LoadBalancers: [
          { LoadBalancerArn: 'arn:alb-1', LoadBalancerName: 'empty-alb', Type: 'application' },
          { LoadBalancerArn: 'arn:alb-2', LoadBalancerName: 'active-alb', Type: 'application' },
        ],
      });
      // DescribeTargetGroups for empty-alb
      mockElbSend.mockResolvedValueOnce({
        TargetGroups: [{ TargetGroupArn: 'arn:tg-1' }],
      });
      // DescribeTargetHealth for tg-1 (no targets)
      mockElbSend.mockResolvedValueOnce({
        TargetHealthDescriptions: [],
      });
      // DescribeTargetGroups for active-alb
      mockElbSend.mockResolvedValueOnce({
        TargetGroups: [{ TargetGroupArn: 'arn:tg-2' }],
      });
      // DescribeTargetHealth for tg-2 (has targets)
      mockElbSend.mockResolvedValueOnce({
        TargetHealthDescriptions: [{ Target: { Id: 'i-123' } }],
      });

      const result = await findEmptyAlbs(mockCredentials, 'eu-west-1');

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        albName: 'empty-alb',
        albArn: 'arn:alb-1',
        region: 'eu-west-1',
      });
    });

    test('returns empty array when no ALBs exist', async () => {
      mockElbSend.mockResolvedValueOnce({ LoadBalancers: [] });

      const result = await findEmptyAlbs(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
    });

    test('ignores non-application load balancers', async () => {
      mockElbSend.mockResolvedValueOnce({
        LoadBalancers: [
          { LoadBalancerArn: 'arn:nlb-1', LoadBalancerName: 'my-nlb', Type: 'network' },
        ],
      });

      const result = await findEmptyAlbs(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockElbSend).toHaveBeenCalledTimes(1);
    });

    test('returns empty array on DescribeLoadBalancers failure', async () => {
      mockElbSend.mockRejectedValueOnce(new Error('Throttling'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await findEmptyAlbs(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });

    test('ALB with no target groups is reported as empty', async () => {
      mockElbSend.mockResolvedValueOnce({
        LoadBalancers: [
          { LoadBalancerArn: 'arn:alb-no-tg', LoadBalancerName: 'orphan-alb', Type: 'application' },
        ],
      });
      // DescribeTargetGroups returns empty
      mockElbSend.mockResolvedValueOnce({ TargetGroups: [] });

      const result = await findEmptyAlbs(mockCredentials, 'eu-west-1');

      expect(result).toHaveLength(1);
      expect(result[0].albName).toBe('orphan-alb');
    });
  });

  describe('filterAvailableVolumes', () => {
    test('returns only volumes in available state', () => {
      const volumes = [
        { VolumeId: 'vol-1', State: 'available' },
        { VolumeId: 'vol-2', State: 'in-use' },
        { VolumeId: 'vol-3', State: 'available' },
        { VolumeId: 'vol-4', State: 'creating' },
      ];

      const result = filterAvailableVolumes(volumes as any);

      expect(result).toHaveLength(2);
      expect(result[0].VolumeId).toBe('vol-1');
      expect(result[1].VolumeId).toBe('vol-3');
    });
  });

  describe('isAlbEmpty', () => {
    test('returns true when all target groups have zero targets', () => {
      const tgs = [
        { targetGroupArn: 'arn:tg-1', targets: 0 },
        { targetGroupArn: 'arn:tg-2', targets: 0 },
      ];
      expect(isAlbEmpty(tgs)).toBe(true);
    });

    test('returns false when any target group has targets', () => {
      const tgs = [
        { targetGroupArn: 'arn:tg-1', targets: 0 },
        { targetGroupArn: 'arn:tg-2', targets: 1 },
      ];
      expect(isAlbEmpty(tgs)).toBe(false);
    });

    test('returns true when there are no target groups', () => {
      expect(isAlbEmpty([])).toBe(true);
    });
  });

  // ─── Log Group Retention Module ─────────────────────────────────────────────

  describe('enforceLogRetention', () => {
    test('sets retention on log groups without a policy', async () => {
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [
          { logGroupName: '/aws/lambda/fn1', retentionInDays: undefined },
          { logGroupName: '/aws/lambda/fn2', retentionInDays: 7 },
          { logGroupName: '/aws/lambda/fn3', retentionInDays: undefined },
        ],
        nextToken: undefined,
      });
      // PutRetentionPolicy calls
      mockLogsSend.mockResolvedValueOnce({});
      mockLogsSend.mockResolvedValueOnce({});

      const result = await enforceLogRetention(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['/aws/lambda/fn1', '/aws/lambda/fn3']);
      expect(mockLogsSend).toHaveBeenCalledTimes(3); // 1 describe + 2 put
    });

    test('returns empty array when all log groups have retention set', async () => {
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [
          { logGroupName: '/aws/lambda/fn1', retentionInDays: 30 },
          { logGroupName: '/aws/lambda/fn2', retentionInDays: 90 },
        ],
        nextToken: undefined,
      });

      const result = await enforceLogRetention(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockLogsSend).toHaveBeenCalledTimes(1); // Only describe
    });

    test('returns empty array when no log groups exist', async () => {
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [],
        nextToken: undefined,
      });

      const result = await enforceLogRetention(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
    });

    test('handles pagination for log groups', async () => {
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [{ logGroupName: '/group-1', retentionInDays: undefined }],
        nextToken: 'next-page',
      });
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [{ logGroupName: '/group-2', retentionInDays: undefined }],
        nextToken: undefined,
      });
      // PutRetentionPolicy calls
      mockLogsSend.mockResolvedValueOnce({});
      mockLogsSend.mockResolvedValueOnce({});

      const result = await enforceLogRetention(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['/group-1', '/group-2']);
      expect(mockLogsSend).toHaveBeenCalledTimes(4); // 2 describe + 2 put
    });

    test('logs failure and continues when a putRetentionPolicy fails', async () => {
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [
          { logGroupName: '/ok-group', retentionInDays: undefined },
          { logGroupName: '/fail-group', retentionInDays: undefined },
          { logGroupName: '/ok-group2', retentionInDays: undefined },
        ],
        nextToken: undefined,
      });
      mockLogsSend.mockResolvedValueOnce({}); // ok
      mockLogsSend.mockRejectedValueOnce(new Error('ResourceNotFoundException')); // fail
      mockLogsSend.mockResolvedValueOnce({}); // ok2

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await enforceLogRetention(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['/ok-group', '/ok-group2']);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to set retention policy on log group:',
        expect.objectContaining({
          logGroupName: '/fail-group',
          error: 'ResourceNotFoundException',
        }),
      );

      consoleErrorSpy.mockRestore();
    });
  });

  describe('filterLogGroupsWithoutRetention', () => {
    test('returns only log groups with undefined retentionInDays', () => {
      const groups = [
        { logGroupName: '/a', retentionInDays: undefined },
        { logGroupName: '/b', retentionInDays: 30 },
        { logGroupName: '/c', retentionInDays: undefined },
        { logGroupName: '/d', retentionInDays: 1 },
      ];

      const result = filterLogGroupsWithoutRetention(groups as any);

      expect(result).toHaveLength(2);
      expect(result[0].logGroupName).toBe('/a');
      expect(result[1].logGroupName).toBe('/c');
    });

    test('does not modify groups with any retention value including very small', () => {
      const groups = [
        { logGroupName: '/a', retentionInDays: 1 },
        { logGroupName: '/b', retentionInDays: 365 },
      ];

      const result = filterLogGroupsWithoutRetention(groups as any);

      expect(result).toHaveLength(0);
    });
  });

  // ─── Error Resilience ───────────────────────────────────────────────────────

  describe('Error Resilience', () => {
    test('EC2: one instance stop failure does not prevent stopping others', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Reservations: [
          { Instances: [{ InstanceId: 'i-1' }, { InstanceId: 'i-2' }, { InstanceId: 'i-3' }] },
        ],
        NextToken: undefined,
      });
      mockEc2Send.mockResolvedValueOnce({}); // i-1 ok
      mockEc2Send.mockRejectedValueOnce(new Error('Fail')); // i-2 fail
      mockEc2Send.mockResolvedValueOnce({}); // i-3 ok

      jest.spyOn(console, 'error').mockImplementation();

      const result = await stopEc2Instances(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['i-1', 'i-3']);
      (console.error as jest.Mock).mockRestore();
    });

    test('ECS: one task stop failure does not prevent stopping others', async () => {
      mockEcsSend.mockResolvedValueOnce({
        clusterArns: ['arn:cluster-1'],
        nextToken: undefined,
      });
      mockEcsSend.mockResolvedValueOnce({
        taskArns: ['task-a', 'task-b', 'task-c'],
        nextToken: undefined,
      });
      mockEcsSend.mockResolvedValueOnce({}); // task-a ok
      mockEcsSend.mockRejectedValueOnce(new Error('Fail')); // task-b fail
      mockEcsSend.mockResolvedValueOnce({}); // task-c ok

      jest.spyOn(console, 'error').mockImplementation();

      const result = await stopEcsTasks(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['task-a', 'task-c']);
      (console.error as jest.Mock).mockRestore();
    });

    test('EIP: one release failure does not prevent releasing others', async () => {
      mockEc2Send.mockResolvedValueOnce({
        Addresses: [
          { AllocationId: 'eip-1' },
          { AllocationId: 'eip-2' },
          { AllocationId: 'eip-3' },
        ],
      });
      mockEc2Send.mockResolvedValueOnce({}); // eip-1 ok
      mockEc2Send.mockRejectedValueOnce(new Error('Fail')); // eip-2 fail
      mockEc2Send.mockResolvedValueOnce({}); // eip-3 ok

      jest.spyOn(console, 'error').mockImplementation();

      const result = await releaseUnattachedEips(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['eip-1', 'eip-3']);
      (console.error as jest.Mock).mockRestore();
    });

    test('Logs: one putRetentionPolicy failure does not prevent updating others', async () => {
      mockLogsSend.mockResolvedValueOnce({
        logGroups: [
          { logGroupName: '/g1', retentionInDays: undefined },
          { logGroupName: '/g2', retentionInDays: undefined },
          { logGroupName: '/g3', retentionInDays: undefined },
        ],
        nextToken: undefined,
      });
      mockLogsSend.mockResolvedValueOnce({}); // g1 ok
      mockLogsSend.mockRejectedValueOnce(new Error('Fail')); // g2 fail
      mockLogsSend.mockResolvedValueOnce({}); // g3 ok

      jest.spyOn(console, 'error').mockImplementation();

      const result = await enforceLogRetention(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['/g1', '/g3']);
      (console.error as jest.Mock).mockRestore();
    });
  });

  // ─── Report Compilation ─────────────────────────────────────────────────────

  describe('Report Compilation', () => {
    test('compiles report with correct per-account counts from multiple regions', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111111111111',
          accountName: 'dev',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: ['i-1', 'i-2'],
              ecsTasksStopped: ['task-1'],
              rdsInstancesStopped: ['db-1'],
              rdsClustersStopped: ['aurora-1'],
              eipsReleased: ['eip-1'],
              logGroupsUpdated: ['/log1', '/log2'],
              unusedEbsVolumes: [{ volumeId: 'vol-1', sizeGiB: 50, region: 'eu-west-1' }],
              emptyAlbs: [{ albName: 'alb-1', albArn: 'arn:alb-1', region: 'eu-west-1' }],
              errors: [],
            },
            {
              region: 'us-east-1',
              ec2Stopped: ['i-3'],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: ['eip-2', 'eip-3'],
              logGroupsUpdated: [],
              unusedEbsVolumes: [],
              emptyAlbs: [],
              errors: ['Some error'],
            },
          ],
        },
      ];

      const failedAccounts: FailedAccount[] = [
        { accountId: '222222222222', accountName: 'staging', error: 'Role not found' },
      ];

      const report = compileReport(accountResults, failedAccounts, 3);

      expect(report.totalAccounts).toBe(3);
      expect(report.processedAccounts).toBe(1);
      expect(report.failedAccounts).toHaveLength(1);
      expect(report.failedAccounts[0].accountId).toBe('222222222222');

      const summary = report.accountResults[0];
      expect(summary.ec2StoppedCount).toBe(3);
      expect(summary.ecsTasksStoppedCount).toBe(1);
      expect(summary.rdsInstancesStoppedCount).toBe(1);
      expect(summary.rdsClustersStoppedCount).toBe(1);
      expect(summary.eipsReleasedCount).toBe(3);
      expect(summary.logGroupsUpdatedCount).toBe(2);
      expect(summary.unusedEbsVolumes).toHaveLength(1);
      expect(summary.emptyAlbs).toHaveLength(1);
      expect(summary.errors).toHaveLength(1);
    });

    test('compiles report from multiple accounts', () => {
      const accountResults: AccountResult[] = [
        {
          accountId: '111',
          accountName: 'acct1',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: ['i-1'],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [],
              emptyAlbs: [],
              errors: [],
            },
          ],
        },
        {
          accountId: '222',
          accountName: 'acct2',
          roleAssumptionSuccess: true,
          regions: [
            {
              region: 'eu-west-1',
              ec2Stopped: ['i-2', 'i-3'],
              ecsTasksStopped: [],
              rdsInstancesStopped: [],
              rdsClustersStopped: [],
              eipsReleased: [],
              logGroupsUpdated: [],
              unusedEbsVolumes: [],
              emptyAlbs: [],
              errors: [],
            },
          ],
        },
      ];

      const report = compileReport(accountResults, [], 2);

      expect(report.processedAccounts).toBe(2);
      expect(report.accountResults).toHaveLength(2);
      expect(report.accountResults[0].ec2StoppedCount).toBe(1);
      expect(report.accountResults[1].ec2StoppedCount).toBe(2);
    });

    test('handles empty results correctly', () => {
      const report = compileReport([], [], 0);

      expect(report.totalAccounts).toBe(0);
      expect(report.processedAccounts).toBe(0);
      expect(report.failedAccounts).toHaveLength(0);
      expect(report.accountResults).toHaveLength(0);
      expect(report.executionTime).toBeDefined();
    });

    test('report includes failed accounts with error details', () => {
      const failedAccounts: FailedAccount[] = [
        { accountId: '111', accountName: 'a1', error: 'Access denied' },
        { accountId: '222', accountName: 'a2', error: 'Role does not exist' },
      ];

      const report = compileReport([], failedAccounts, 4);

      expect(report.failedAccounts).toHaveLength(2);
      expect(report.failedAccounts[0].error).toBe('Access denied');
      expect(report.failedAccounts[1].error).toBe('Role does not exist');
      expect(report.totalAccounts).toBe(4);
    });
  });
});
