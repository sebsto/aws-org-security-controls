export interface AccountResult {
  accountId: string;
  accountName: string;
  roleAssumptionSuccess: boolean;
  regions: RegionResult[];
}

export interface RegionResult {
  region: string;
  ec2Stopped: string[];
  ecsTasksStopped: string[];
  rdsInstancesStopped: string[];
  rdsClustersStopped: string[];
  eipsReleased: string[];
  logGroupsUpdated: string[];
  unusedEbsVolumes: VolumeInfo[];
  emptyAlbs: AlbInfo[];
  errors: string[];
}

export interface VolumeInfo {
  volumeId: string;
  sizeGiB: number;
  region: string;
}

export interface AlbInfo {
  albName: string;
  albArn: string;
  region: string;
}

export interface ExecutionReport {
  executionTime: string;
  totalAccounts: number;
  processedAccounts: number;
  failedAccounts: FailedAccount[];
  accountResults: AccountSummary[];
}

export interface AccountSummary {
  accountId: string;
  accountName: string;
  ec2StoppedCount: number;
  ecsTasksStoppedCount: number;
  rdsInstancesStoppedCount: number;
  rdsClustersStoppedCount: number;
  eipsReleasedCount: number;
  logGroupsUpdatedCount: number;
  unusedEbsVolumes: VolumeInfo[];
  emptyAlbs: AlbInfo[];
  errors: string[];
}

export interface FailedAccount {
  accountId: string;
  accountName: string;
  error: string;
}
