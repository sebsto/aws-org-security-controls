import { CloudTrailEventBridgeEvent, EmailMessage, Formatter } from './types';

/**
 * Helper to extract common fields from an event for use in formatted messages.
 */
function commonFields(event: CloudTrailEventBridgeEvent) {
  return {
    source: event.source ?? 'unknown',
    timestamp: event.time ?? 'unknown',
    account: event.account ?? 'unknown',
    region: event.region ?? 'unknown',
    principalArn: event.detail?.userIdentity?.arn ?? 'unknown',
    eventName: event.detail?.eventName ?? 'unknown',
    sourceIp: event.detail?.sourceIPAddress ?? 'unknown',
  };
}

/**
 * Helper to wrap content in a standard HTML email template.
 */
function htmlBody(title: string, contentRows: string): string {
  return `<html>
<body>
<h2>${title}</h2>
<table border="0" cellpadding="4" cellspacing="0">
${contentRows}
</table>
</body>
</html>`;
}

function row(label: string, value: string): string {
  return `<tr><td><strong>${label}:</strong></td><td>${value}</td></tr>`;
}

// --- Formatter 1: Root Console Login ---
const rootConsoleLoginFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return (
      event.source === 'aws.signin' &&
      event.detail?.eventName === 'ConsoleLogin' &&
      event.detail?.userIdentity?.type === 'Root'
    );
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    return {
      subject: `[CRITICAL] Root Console Login Detected - Account ${f.account}`,
      body: htmlBody(
        'Root Console Login Detected',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Source IP', f.sourceIp)
      ),
    };
  },
};

// --- Formatter 2: Console Login Without MFA ---
const consoleLoginNoMfaFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return (
      event.source === 'aws.signin' &&
      event.detail?.eventName === 'ConsoleLogin' &&
      event.detail?.additionalEventData?.MFAUsed === 'No'
    );
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    return {
      subject: `[SECURITY] Console Login Without MFA - Account ${f.account}`,
      body: htmlBody(
        'Console Login Without MFA',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Source IP', f.sourceIp) +
          row('MFA Used', 'No')
      ),
    };
  },
};

// --- Formatter: Identity Center Login Without MFA ---
const identityCenterLoginNoMfaFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return (
      event.source === 'aws.signin' &&
      event.detail?.eventName === 'UserAuthentication' &&
      (event.detail?.additionalEventData as Record<string, unknown>)?.CredentialType ===
        'PASSWORD'
    );
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const additional = event.detail?.additionalEventData as Record<string, unknown>;
    const loginTo = additional?.LoginTo ?? 'unknown';
    return {
      subject: `[SECURITY] Identity Center Login Without MFA - Account ${f.account}`,
      body: htmlBody(
        'Identity Center (SSO) Login Without MFA',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Region', f.region) +
          row('Source IP', f.sourceIp) +
          row('Login Target', String(loginTo)) +
          row('Credential Type', 'PASSWORD (single factor)')
      ),
    };
  },
};

// --- Formatter 3: Login Failure ---
const loginFailureFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return (
      event.source === 'aws.signin' &&
      event.detail?.eventName === 'ConsoleLogin' &&
      (event.detail?.responseElements as Record<string, unknown>)?.ConsoleLogin === 'Failure'
    );
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const errorMessage =
      (event.detail?.additionalEventData as Record<string, unknown>)?.LoginTo ?? 'unknown';
    return {
      subject: `[SECURITY] Console Login Failure - Account ${f.account}`,
      body: htmlBody(
        'Console Login Failure',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Source IP', f.sourceIp) +
          row('Login Target', String(errorMessage))
      ),
    };
  },
};

// --- Formatter 4: CloudTrail StopLogging ---
const cloudTrailStopLoggingFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.cloudtrail' && event.detail?.eventName === 'StopLogging';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const trailArn =
      (event.detail?.requestParameters as Record<string, unknown>)?.name ?? 'unknown';
    return {
      subject: `[CRITICAL] CloudTrail Logging Stopped - Account ${f.account}`,
      body: htmlBody(
        'CloudTrail Logging Stopped',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Trail', String(trailArn))
      ),
    };
  },
};

// --- Formatter 5: CloudTrail DeleteTrail ---
const cloudTrailDeleteTrailFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.cloudtrail' && event.detail?.eventName === 'DeleteTrail';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const trailArn =
      (event.detail?.requestParameters as Record<string, unknown>)?.name ?? 'unknown';
    return {
      subject: `[CRITICAL] CloudTrail Trail Deleted - Account ${f.account}`,
      body: htmlBody(
        'CloudTrail Trail Deleted',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Trail', String(trailArn))
      ),
    };
  },
};

// --- Formatter 6: CloudTrail UpdateTrail ---
const cloudTrailUpdateTrailFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.cloudtrail' && event.detail?.eventName === 'UpdateTrail';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const trailArn =
      (event.detail?.requestParameters as Record<string, unknown>)?.name ?? 'unknown';
    return {
      subject: `[WARNING] CloudTrail Trail Updated - Account ${f.account}`,
      body: htmlBody(
        'CloudTrail Trail Updated',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Trail', String(trailArn))
      ),
    };
  },
};

// --- Formatter 7: CloudTrail PutEventSelectors ---
const cloudTrailPutEventSelectorsFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.cloudtrail' && event.detail?.eventName === 'PutEventSelectors';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const trailArn =
      (event.detail?.requestParameters as Record<string, unknown>)?.trailName ?? 'unknown';
    return {
      subject: `[WARNING] CloudTrail Event Selectors Modified - Account ${f.account}`,
      body: htmlBody(
        'CloudTrail Event Selectors Modified',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Trail', String(trailArn))
      ),
    };
  },
};

// --- Formatter 8: IAM User Created ---
const iamUserCreatedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.iam' && event.detail?.eventName === 'CreateUser';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const userName =
      (event.detail?.requestParameters as Record<string, unknown>)?.userName ?? 'unknown';
    return {
      subject: `[SECURITY] IAM User Created - Account ${f.account}`,
      body: htmlBody(
        'IAM User Created',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('New User Name', String(userName))
      ),
    };
  },
};

// --- Formatter 9: Access Key Created ---
const accessKeyCreatedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.iam' && event.detail?.eventName === 'CreateAccessKey';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const userName =
      (event.detail?.requestParameters as Record<string, unknown>)?.userName ?? 'unknown';
    return {
      subject: `[SECURITY] Access Key Created - Account ${f.account}`,
      body: htmlBody(
        'Access Key Created',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Target User', String(userName))
      ),
    };
  },
};

// --- Formatter 10: Login Profile Attached ---
const loginProfileAttachedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.iam' && event.detail?.eventName === 'CreateLoginProfile';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const userName =
      (event.detail?.requestParameters as Record<string, unknown>)?.userName ?? 'unknown';
    return {
      subject: `[SECURITY] Login Profile Created - Account ${f.account}`,
      body: htmlBody(
        'Login Profile Created',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Target User', String(userName))
      ),
    };
  },
};

// --- Formatter 11: MFA Device Deactivated ---
const mfaDeviceDeactivatedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.iam' && event.detail?.eventName === 'DeactivateMFADevice';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const userName =
      (event.detail?.requestParameters as Record<string, unknown>)?.userName ?? 'unknown';
    const serialNumber =
      (event.detail?.requestParameters as Record<string, unknown>)?.serialNumber ?? 'unknown';
    return {
      subject: `[SECURITY] MFA Device Deactivated - Account ${f.account}`,
      body: htmlBody(
        'MFA Device Deactivated',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Target User', String(userName)) +
          row('Device Serial', String(serialNumber))
      ),
    };
  },
};

// --- Formatter 12: SSO User Created ---
const ssoUserCreatedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.sso-directory' && event.detail?.eventName === 'CreateUser';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const userName =
      (event.detail?.requestParameters as Record<string, unknown>)?.userName ?? 'unknown';
    return {
      subject: `[INFO] Identity Center User Created - Account ${f.account}`,
      body: htmlBody(
        'Identity Center (SSO) User Created',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('New User Name', String(userName))
      ),
    };
  },
};

// --- Formatter 13: Security Group Ingress Opened ---
const securityGroupIngressOpenedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.ec2' && event.detail?.eventName === 'AuthorizeSecurityGroupIngress';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const params = event.detail?.requestParameters as Record<string, unknown>;
    const groupId = params?.groupId ?? 'unknown';
    return {
      subject: `[SECURITY] Security Group Ingress Rule Added - Account ${f.account}`,
      body: htmlBody(
        'Security Group Ingress Rule Added',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Security Group ID', String(groupId))
      ),
    };
  },
};

// --- Formatter 14: Cost Anomaly Detected ---
const costAnomalyDetectedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.ce' && event['detail-type'] === 'AWS Cost Anomaly Detection Alert';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const detail = event.detail as Record<string, unknown>;
    const anomalyId = detail?.anomalyId ?? 'unknown';
    const totalImpact = detail?.totalImpact ?? 'unknown';
    return {
      subject: `[COST] Cost Anomaly Detected - Account ${f.account}`,
      body: htmlBody(
        'AWS Cost Anomaly Detected',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Anomaly ID', String(anomalyId)) +
          row('Total Impact', String(totalImpact))
      ),
    };
  },
};

// --- Formatter 15: Budget Threshold Breached ---
const budgetThresholdBreachedFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.budgets' && event['detail-type'] === 'Budget Notification';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const detail = event.detail as Record<string, unknown>;
    const budgetName = detail?.budgetName ?? 'unknown';
    const budgetType = detail?.budgetType ?? 'unknown';
    return {
      subject: `[COST] Budget Threshold Breached - Account ${f.account}`,
      body: htmlBody(
        'Budget Threshold Breached',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Budget Name', String(budgetName)) +
          row('Budget Type', String(budgetType))
      ),
    };
  },
};

// --- Formatter 16: Access Analyzer Finding ---
const accessAnalyzerFindingFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return (
      event.source === 'aws.access-analyzer' &&
      event['detail-type'] === 'Access Analyzer Finding'
    );
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    const detail = event.detail as Record<string, unknown>;
    const resourceType = detail?.resourceType ?? 'unknown';
    const resource = detail?.resource ?? 'unknown';
    const status = detail?.status ?? 'unknown';
    return {
      subject: `[SECURITY] Access Analyzer Finding - Account ${f.account}`,
      body: htmlBody(
        'IAM Access Analyzer Finding',
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Resource Type', String(resourceType)) +
          row('Resource', String(resource)) +
          row('Status', String(status))
      ),
    };
  },
};

// --- Formatter 17: Organization Event (catch-all for aws.organizations) ---
const organizationEventFormatter: Formatter = {
  canHandle(event: CloudTrailEventBridgeEvent): boolean {
    return event.source === 'aws.organizations';
  },
  format(event: CloudTrailEventBridgeEvent): EmailMessage {
    const f = commonFields(event);
    return {
      subject: `[ORG] Organization Event: ${f.eventName} - Account ${f.account}`,
      body: htmlBody(
        `Organization Event: ${f.eventName}`,
        row('Event Source', f.source) +
          row('Timestamp', f.timestamp) +
          row('Account', f.account) +
          row('Principal ARN', f.principalArn) +
          row('Region', f.region) +
          row('Event Name', f.eventName) +
          row('Source IP', f.sourceIp)
      ),
    };
  },
};

/**
 * Ordered array of all formatters.
 * Order matters: more specific formatters come first.
 * The Organizations formatter is last among specific formatters since it's a catch-all for aws.organizations.
 */
export const formatters: Formatter[] = [
  // Sign-in events (most specific first: Root > NoMFA > Failure)
  rootConsoleLoginFormatter,
  consoleLoginNoMfaFormatter,
  identityCenterLoginNoMfaFormatter,
  loginFailureFormatter,
  // CloudTrail tampering events
  cloudTrailStopLoggingFormatter,
  cloudTrailDeleteTrailFormatter,
  cloudTrailUpdateTrailFormatter,
  cloudTrailPutEventSelectorsFormatter,
  // IAM events
  iamUserCreatedFormatter,
  accessKeyCreatedFormatter,
  loginProfileAttachedFormatter,
  mfaDeviceDeactivatedFormatter,
  // SSO events
  ssoUserCreatedFormatter,
  // EC2 events
  securityGroupIngressOpenedFormatter,
  // Cost events (non-CloudTrail, match on detail-type)
  costAnomalyDetectedFormatter,
  budgetThresholdBreachedFormatter,
  // Access Analyzer (non-CloudTrail, match on detail-type)
  accessAnalyzerFindingFormatter,
  // Organizations catch-all (must be last)
  organizationEventFormatter,
];

/**
 * Selects the first formatter that can handle the given event.
 * Returns undefined if no formatter matches (caller should use generic fallback).
 */
export function selectFormatter(
  event: CloudTrailEventBridgeEvent
): Formatter | undefined {
  return formatters.find((f) => f.canHandle(event));
}
