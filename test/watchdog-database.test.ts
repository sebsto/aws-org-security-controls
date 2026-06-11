// Mock RDS client - must be declared before imports due to jest hoisting
const mockSend = jest.fn();
jest.mock('@aws-sdk/client-rds', () => {
  return {
    RDSClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
    DescribeDBInstancesCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeDBInstances' })),
    StopDBInstanceCommand: jest.fn((params: any) => ({ ...params, _type: 'StopDBInstance' })),
    DescribeDBClustersCommand: jest.fn((params: any) => ({ ...params, _type: 'DescribeDBClusters' })),
    StopDBClusterCommand: jest.fn((params: any) => ({ ...params, _type: 'StopDBCluster' })),
  };
});

import { stopRdsInstances, stopRdsClusters } from '../lambda/watchdog/actions/database';

const mockCredentials = {
  AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  SessionToken: 'FwoGZXIvYXdzEBYaDH...',
};

describe('Watchdog Database Module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('stopRdsInstances', () => {
    test('stops all available RDS instances and returns their identifiers', async () => {
      mockSend.mockResolvedValueOnce({
        DBInstances: [
          { DBInstanceIdentifier: 'db-prod-1', DBInstanceStatus: 'available' },
          { DBInstanceIdentifier: 'db-dev-2', DBInstanceStatus: 'stopped' },
          { DBInstanceIdentifier: 'db-test-3', DBInstanceStatus: 'available' },
        ],
        Marker: undefined,
      });
      // StopDBInstance calls
      mockSend.mockResolvedValueOnce({});
      mockSend.mockResolvedValueOnce({});

      const result = await stopRdsInstances(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['db-prod-1', 'db-test-3']);
      expect(mockSend).toHaveBeenCalledTimes(3); // 1 describe + 2 stops
    });

    test('returns empty array when no instances are available', async () => {
      mockSend.mockResolvedValueOnce({
        DBInstances: [
          { DBInstanceIdentifier: 'db-1', DBInstanceStatus: 'stopped' },
          { DBInstanceIdentifier: 'db-2', DBInstanceStatus: 'creating' },
        ],
        Marker: undefined,
      });

      const result = await stopRdsInstances(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockSend).toHaveBeenCalledTimes(1); // Only describe
    });

    test('returns empty array when no instances exist', async () => {
      mockSend.mockResolvedValueOnce({
        DBInstances: [],
        Marker: undefined,
      });

      const result = await stopRdsInstances(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
    });

    test('handles pagination when listing instances', async () => {
      mockSend.mockResolvedValueOnce({
        DBInstances: [
          { DBInstanceIdentifier: 'db-page1', DBInstanceStatus: 'available' },
        ],
        Marker: 'next-page-token',
      });
      mockSend.mockResolvedValueOnce({
        DBInstances: [
          { DBInstanceIdentifier: 'db-page2', DBInstanceStatus: 'available' },
        ],
        Marker: undefined,
      });
      // StopDBInstance calls
      mockSend.mockResolvedValueOnce({});
      mockSend.mockResolvedValueOnce({});

      const result = await stopRdsInstances(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['db-page1', 'db-page2']);
      expect(mockSend).toHaveBeenCalledTimes(4); // 2 describe + 2 stops
    });

    test('logs failure and continues when an instance stop fails', async () => {
      mockSend.mockResolvedValueOnce({
        DBInstances: [
          { DBInstanceIdentifier: 'db-ok', DBInstanceStatus: 'available' },
          { DBInstanceIdentifier: 'db-fail', DBInstanceStatus: 'available' },
          { DBInstanceIdentifier: 'db-ok2', DBInstanceStatus: 'available' },
        ],
        Marker: undefined,
      });
      // First stop succeeds
      mockSend.mockResolvedValueOnce({});
      // Second stop fails
      mockSend.mockRejectedValueOnce(new Error('InvalidDBInstanceState'));
      // Third stop succeeds
      mockSend.mockResolvedValueOnce({});

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await stopRdsInstances(mockCredentials, 'us-east-1');

      expect(result).toEqual(['db-ok', 'db-ok2']);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to stop RDS instance:', {
        instanceId: 'db-fail',
        region: 'us-east-1',
        error: 'InvalidDBInstanceState',
      });

      consoleErrorSpy.mockRestore();
    });
  });

  describe('stopRdsClusters', () => {
    test('stops all available Aurora clusters and returns their identifiers', async () => {
      mockSend.mockResolvedValueOnce({
        DBClusters: [
          { DBClusterIdentifier: 'aurora-prod', Status: 'available' },
          { DBClusterIdentifier: 'aurora-stopped', Status: 'stopped' },
          { DBClusterIdentifier: 'aurora-dev', Status: 'available' },
        ],
        Marker: undefined,
      });
      // StopDBCluster calls
      mockSend.mockResolvedValueOnce({});
      mockSend.mockResolvedValueOnce({});

      const result = await stopRdsClusters(mockCredentials, 'eu-west-1');

      expect(result).toEqual(['aurora-prod', 'aurora-dev']);
      expect(mockSend).toHaveBeenCalledTimes(3); // 1 describe + 2 stops
    });

    test('returns empty array when no clusters are available', async () => {
      mockSend.mockResolvedValueOnce({
        DBClusters: [
          { DBClusterIdentifier: 'aurora-1', Status: 'stopped' },
        ],
        Marker: undefined,
      });

      const result = await stopRdsClusters(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    test('returns empty array when no clusters exist', async () => {
      mockSend.mockResolvedValueOnce({
        DBClusters: [],
        Marker: undefined,
      });

      const result = await stopRdsClusters(mockCredentials, 'eu-west-1');

      expect(result).toEqual([]);
    });

    test('handles pagination when listing clusters', async () => {
      mockSend.mockResolvedValueOnce({
        DBClusters: [
          { DBClusterIdentifier: 'cluster-page1', Status: 'available' },
        ],
        Marker: 'next-token',
      });
      mockSend.mockResolvedValueOnce({
        DBClusters: [
          { DBClusterIdentifier: 'cluster-page2', Status: 'available' },
        ],
        Marker: undefined,
      });
      // StopDBCluster calls
      mockSend.mockResolvedValueOnce({});
      mockSend.mockResolvedValueOnce({});

      const result = await stopRdsClusters(mockCredentials, 'eu-central-1');

      expect(result).toEqual(['cluster-page1', 'cluster-page2']);
      expect(mockSend).toHaveBeenCalledTimes(4); // 2 describe + 2 stops
    });

    test('logs failure and continues when a cluster stop fails', async () => {
      mockSend.mockResolvedValueOnce({
        DBClusters: [
          { DBClusterIdentifier: 'cluster-ok', Status: 'available' },
          { DBClusterIdentifier: 'cluster-fail', Status: 'available' },
        ],
        Marker: undefined,
      });
      // First stop succeeds
      mockSend.mockResolvedValueOnce({});
      // Second stop fails
      mockSend.mockRejectedValueOnce(new Error('InvalidDBClusterStateFault'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const result = await stopRdsClusters(mockCredentials, 'eu-west-3');

      expect(result).toEqual(['cluster-ok']);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to stop RDS cluster:', {
        clusterId: 'cluster-fail',
        region: 'eu-west-3',
        error: 'InvalidDBClusterStateFault',
      });

      consoleErrorSpy.mockRestore();
    });
  });
});
