export interface Formatter {
  canHandle(event: CloudTrailEventBridgeEvent): boolean;
  format(event: CloudTrailEventBridgeEvent): EmailMessage;
}

export interface EmailMessage {
  subject: string;
  body: string;
}

export interface CloudTrailEventBridgeEvent {
  version: '0';
  id: string;
  source: string;
  account: string;
  time: string;
  region: string;
  'detail-type': string;
  detail: {
    eventVersion: string;
    eventSource: string;
    eventName: string;
    awsRegion: string;
    sourceIPAddress: string;
    userAgent: string;
    userIdentity: {
      type: string;
      principalId: string;
      arn: string;
      accountId: string;
    };
    requestParameters: Record<string, unknown>;
    responseElements: Record<string, unknown>;
    additionalEventData?: Record<string, unknown>;
    [key: string]: unknown;
  };
}
