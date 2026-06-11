# Implementation Plan: org-security-controls

## Overview

This plan implements an AWS Organizations security and cost-control system using AWS CDK (TypeScript). The stack deploys SCPs, an organization-level CloudTrail trail, EventBridge rules for real-time alerting, a Notifier Lambda for formatted email alerts, and a Watchdog Lambda for weekly cost-control enforcement across member accounts. All resources deploy in the management account (123456789012).

## Tasks

- [x] 1. Project scaffolding and core interfaces
  - [x] 1.1 Initialize CDK project structure and install dependencies
    - Initialize a CDK TypeScript project with `aws-cdk-lib`, `constructs`, `@aws-sdk/client-ses`, `@aws-sdk/client-sts`, `@aws-sdk/client-ec2`, `@aws-sdk/client-ecs`, `@aws-sdk/client-rds`, `@aws-sdk/client-elastic-load-balancing-v2`, `@aws-sdk/client-cloudwatch-logs`, `@aws-sdk/client-organizations`
    - Install dev dependencies: `fast-check`, `@types/aws-lambda`, `jest`, `ts-jest`, `@types/jest`, `aws-cdk-lib/assertions`
    - Create directory structure: `lib/`, `lambda/notifier/`, `lambda/watchdog/`, `test/`
    - _Requirements: 8.1, 10.1, 14.1_
  - [x] 1.2 Define shared TypeScript interfaces and types
    - Create `lib/types.ts` with `ScpEngineProps`, `OrgTrailProps`, `EventBridgeRulesProps` interfaces
    - Create `lambda/notifier/types.ts` with `Formatter`, `EmailMessage`, `CloudTrailEventBridgeEvent` interfaces
    - Create `lambda/watchdog/types.ts` with `AccountResult`, `RegionResult`, `VolumeInfo`, `AlbInfo`, `ExecutionReport`, `AccountSummary`, `FailedAccount` interfaces
    - _Requirements: 8.4, 13.1, 21.1, 21.2_

- [x] 2. SCP Engine construct
  - [x] 2.1 Implement the SCP Engine construct (`lib/scp-engine.ts`)
    - Implement `buildDenyServicesPolicy()` function that produces a valid IAM policy document with Version `2012-10-17` and exactly 7 deny statements with unique Sids: `DenyOutsideApprovedRegions`, `DenyUnapprovedRdsClasses`, `DenyExpensiveEc2Types`, `DenyCloudTrailTampering`, `DenyRootUserActions`, `DenyIamUserCreation`, `DenyBedrockUnauthorized`
    - Implement region restriction statement using `aws:RequestedRegion` condition key, excluding global services (IAM, STS, Organizations, CloudFront, Route 53, Support, Budgets)
    - Implement RDS class restriction using `rds:DatabaseClass` condition with `StringNotEquals` for allowed classes
    - Implement EC2 type restriction using `ec2:InstanceType` condition with `StringLike` for blocked patterns
    - Implement CloudTrail tampering prevention with optional break-glass role exclusion via `ArnNotLike` condition
    - Implement root user denial using `aws:PrincipalArn` condition matching `arn:aws:iam::*:root`
    - Implement IAM user creation denial for `iam:CreateUser`, `iam:CreateLoginProfile`, `iam:CreateAccessKey`
    - Implement Bedrock gating using `ArnNotLike` on `aws:PrincipalArn`; omit condition when allowlist is empty (deny all)
    - Add synthesis-time validation: throw error if `approvedRegions` is empty; throw error if serialized policy > 5120 characters
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 3.1, 3.2, 4.1, 4.2, 4.3, 5.1, 5.2, 6.1, 6.2, 7.1, 7.2, 7.3, 7.4, 8.1, 8.2, 8.3, 8.4_
  - [x] 2.2 Implement the EnforceMFA policy in SCP Engine
    - Build separate `EnforceMFA` policy that denies all actions when `aws:MultiFactorAuthPresent` is false using `BoolIfExists` operator
    - Exclude MFA self-service actions: `iam:CreateVirtualMFADevice`, `iam:EnableMFADevice`, `iam:GetUser`, `iam:ListMFADevices`, `iam:ListVirtualMFADevices`, `iam:ResyncMFADevice`
    - Create `CfnPolicy` resources for both DenyServices and EnforceMFA, attach to organization root via `targetIds`
    - _Requirements: 9.1, 9.2, 9.3_
  - [x] 2.3 Write property test: SCP Policy Construction Correctness
    - **Property 1: SCP Policy Construction Correctness**
    - Use fast-check to generate random `ScpEngineProps`: region lists (1-10 valid region codes), RDS class lists, EC2 block patterns, Bedrock ARN lists (0-20), optional break-glass ARN
    - Assert output has Version `2012-10-17`, exactly 7 statements, unique Sids, and correct condition references for each input
    - Minimum 100 iterations
    - **Validates: Requirements 1.1, 2.1, 3.1, 4.3, 7.1, 8.1, 8.4**
  - [x] 2.4 Write property test: SCP Size Validation
    - **Property 2: SCP Size Validation**
    - Use fast-check to generate configurations with varying string lengths to test the 5120-char boundary
    - Assert that policies > 5120 chars throw synthesis error; policies ≤ 5120 chars do not throw
    - Minimum 100 iterations
    - **Validates: Requirements 8.2**
  - [x] 2.5 Write CDK assertion tests for SCP Engine
    - Verify synthesized template contains two `AWS::Organizations::Policy` resources
    - Verify DenyServices policy content field contains valid JSON with 7 statements
    - Verify EnforceMFA policy content field contains MFA condition
    - Verify both policies target the organization root ID
    - _Requirements: 8.1, 8.4, 9.1_

- [x] 3. Organization Trail construct
  - [x] 3.1 Implement the Organization Trail construct (`lib/org-trail.ts`)
    - Create S3 bucket with bucket policy allowing CloudTrail writes from the organization (`o-xxxxxxxxxx`)
    - Configure bucket with lifecycle rules, encryption, and block public access
    - Create CloudTrail trail with `IsOrganizationTrail: true`, `IsMultiRegionTrail: true`, management events enabled (read + write)
    - EventBridge integration is automatic when management events are captured
    - _Requirements: 10.1, 10.2, 10.3, 10.4_
  - [x] 3.2 Write CDK assertion tests for Organization Trail
    - Verify template contains `AWS::CloudTrail::Trail` resource with organization and multi-region flags
    - Verify S3 bucket policy allows CloudTrail from organization
    - Verify management event selectors are configured
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

- [x] 4. EventBridge Rules construct
  - [x] 4.1 Implement the EventBridge Rules construct (`lib/eventbridge-rules.ts`)
    - Define 17 EventBridge rules on the default bus, each with explicit `source`, `detail-type`, and `detail` matching
    - Rules: RootConsoleLogin, ConsoleLoginNoMFA, LoginFailure, CloudTrailStopLogging, CloudTrailDeleteTrail, CloudTrailUpdateTrail, CloudTrailPutEventSelectors, IamUserCreated, AccessKeyCreated, LoginProfileAttached, MfaDeviceDeactivated, SsoUserCreated, SecurityGroupIngressOpened, CostAnomalyDetected, BudgetThresholdBreached, AccessAnalyzerFinding, OrganizationEvent
    - Configure each rule with retry policy: 3 attempts, 24h retention
    - Grant invoke permission on Notifier Lambda for each rule
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_
  - [x] 4.2 Write CDK assertion tests for EventBridge Rules
    - Verify template contains 17 `AWS::Events::Rule` resources
    - Verify each rule has correct event pattern with explicit source and detail-type
    - Verify each rule targets the Notifier Lambda with retry configuration
    - Verify Lambda permissions are granted for each rule
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Notifier Lambda implementation
  - [x] 6.1 Implement Notifier Lambda handler (`lambda/notifier/handler.ts`)
    - Implement main handler that receives EventBridge event, selects formatter, formats message, sends via SES
    - Handle missing `RECIPIENT_EMAIL` env var: log error, skip delivery
    - Handle SES delivery failure: log error with event type, timestamp, and failure reason
    - Handle unknown event type: use generic formatter with raw JSON
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_
  - [x] 6.2 Implement Notifier Lambda formatters (`lambda/notifier/formatters.ts`)
    - Implement `Formatter` interface with `canHandle()` and `format()` methods
    - Create 17 formatters, one per event type, each producing an `EmailMessage` with subject and HTML body
    - Each formatted message must contain: event source, timestamp, affected account, acting principal ARN, and event-specific details
    - Implement generic fallback formatter for unknown events
    - Implement formatter selection logic that iterates formatters and selects the one whose `canHandle()` returns true
    - _Requirements: 13.1, 13.2, 13.3_
  - [x] 6.3 Write property test: Formatter Selection Correctness
    - **Property 3: Formatter Selection Correctness**
    - Use fast-check to generate events with random source/eventName from the known set of 17 types
    - Assert exactly one formatter's `canHandle()` returns true for each generated event
    - Minimum 100 iterations
    - **Validates: Requirements 12.1, 13.1**
  - [x] 6.4 Write property test: Formatted Message Completeness
    - **Property 4: Formatted Message Completeness**
    - Use fast-check to generate events with random field values (strings, timestamps, account IDs)
    - Assert every formatted EmailMessage body contains event source, timestamp, affected account, principal ARN, and at least one event-specific field
    - Minimum 100 iterations
    - **Validates: Requirements 13.2**
  - [x] 6.5 Write unit tests for Notifier Lambda
    - Test handler with each of the 17 event types using example payloads
    - Test generic fallback for unknown event type
    - Test missing RECIPIENT_EMAIL env var behavior
    - Test SES delivery failure logging
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 13.1, 13.2, 13.3_

- [x] 7. Watchdog Lambda implementation
  - [x] 7.1 Implement Watchdog Lambda core handler and account discovery (`lambda/watchdog/handler.ts`)
    - Implement main handler triggered by EventBridge scheduled event
    - Call Organizations `ListAccounts` to get member accounts, filtering out management account (123456789012)
    - Assume `OrganizationAccountAccessRole` in each member account with 3600s session duration
    - Handle role assumption failures: log and continue to next account
    - Handle Organizations ListAccounts failure: log and abort
    - Iterate each account × each approved region to execute action modules
    - Compile execution report and send via SES
    - _Requirements: 14.3, 15.1, 15.2, 15.3, 21.1, 21.3, 21.4, 21.5_
  - [x] 7.2 Implement EC2 and ECS stop module (`lambda/watchdog/actions/compute.ts`)
    - Enumerate running EC2 instances (`instance-state-name: running`) across approved regions, issue `StopInstances` for each
    - Enumerate ECS clusters, list tasks in RUNNING status, issue `StopTask` for each
    - Handle individual stop failures: log and continue
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_
  - [x] 7.3 Implement RDS stop module (`lambda/watchdog/actions/database.ts`)
    - Enumerate RDS DB instances with status `available`, issue `StopDBInstance` for each
    - Enumerate Aurora DB clusters with status `available`, issue `StopDBCluster` for each
    - Handle individual stop failures: log and continue
    - _Requirements: 17.1, 17.2, 17.3, 17.4_
  - [x] 7.4 Implement EIP release module (`lambda/watchdog/actions/network.ts`)
    - Enumerate all Elastic IPs, release those with no associated network interface (no `AssociationId` or `NetworkInterfaceId`)
    - Handle individual release failures: log and continue
    - _Requirements: 18.1, 18.2, 18.3_
  - [x] 7.5 Implement EBS and ALB reporting module (`lambda/watchdog/actions/reporting.ts`)
    - Enumerate EBS volumes, identify those in `available` state, collect volumeId, sizeGiB, region
    - Enumerate ALBs, check target groups for registered targets, identify empty ALBs (all TGs have zero targets)
    - Handle enumeration failures: log and continue
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5_
  - [x] 7.6 Implement log group retention module (`lambda/watchdog/actions/logs.ts`)
    - Enumerate CloudWatch log groups, call `putRetentionPolicy` with 30 days only for groups where `retentionInDays` is absent/undefined
    - Never modify log groups that already have any retention policy set
    - Handle individual failures: log and continue
    - _Requirements: 20.1, 20.2, 20.3, 20.4_
  - [x] 7.7 Implement execution report compiler (`lambda/watchdog/report.ts`)
    - Compile `ExecutionReport` from all `AccountResult` objects
    - Include total/processed counts, per-account/per-region breakdowns, failed accounts with errors, all resource entries
    - Format as HTML email and send via SES
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5_
  - [x] 7.8 Write property test: Management Account Exclusion
    - **Property 5: Management Account Exclusion**
    - Use fast-check to generate random account lists (1-50 accounts) always including management account ID `123456789012`
    - Assert filtered list excludes management account while preserving all other accounts in original order
    - Minimum 100 iterations
    - **Validates: Requirements 15.1**
  - [x] 7.9 Write property test: Session Duration Constraint
    - **Property 6: Session Duration Constraint**
    - Use fast-check to generate random positive integers (1-7200) as duration values
    - Assert: accepts exactly 3600, rejects any value > 3600
    - Minimum 100 iterations
    - **Validates: Requirements 15.2**
  - [x] 7.10 Write property test: EIP Release Filtering
    - **Property 7: EIP Release Filtering**
    - Use fast-check to generate random EIP lists with/without AssociationId/NetworkInterfaceId
    - Assert: releases if and only if EIP has no associated network interface; never releases associated EIPs
    - Minimum 100 iterations
    - **Validates: Requirements 18.2**
  - [x] 7.11 Write property test: Resource Waste Identification
    - **Property 8: Resource Waste Identification**
    - Use fast-check to generate EBS volumes (states: available, in-use, creating, deleting) and ALB/TG configurations (0-5 targets per TG)
    - Assert: reports exactly volumes in `available` state; reports ALBs where every TG has zero targets
    - Minimum 100 iterations
    - **Validates: Requirements 19.1, 19.2**
  - [x] 7.12 Write property test: Report Entry Field Completeness
    - **Property 9: Report Entry Field Completeness**
    - Use fast-check to generate random volume/ALB data with varying string field lengths
    - Assert: each EBS entry contains volumeId, sizeGiB, accountId, region; each ALB entry contains albName, accountId, region
    - Minimum 100 iterations
    - **Validates: Requirements 19.3, 19.4**
  - [x] 7.13 Write property test: Log Group Retention Enforcement Logic
    - **Property 10: Log Group Retention Enforcement Logic**
    - Use fast-check to generate random log group lists with `retentionInDays` as undefined or random positive integers
    - Assert: calls `putRetentionPolicy` only for groups where `retentionInDays` is undefined; never for groups with existing retention
    - Minimum 100 iterations
    - **Validates: Requirements 20.2, 20.3**
  - [x] 7.14 Write property test: Execution Report Compilation Correctness
    - **Property 11: Execution Report Compilation Correctness**
    - Use fast-check to generate random `AccountResult` arrays (including failed accounts)
    - Assert: total count matches input, per-account counts match sum of action arrays, failed accounts list is complete, all resource entries present
    - Minimum 100 iterations
    - **Validates: Requirements 21.1, 21.2, 21.5**
  - [x] 7.15 Write unit tests for Watchdog Lambda
    - Test account discovery with mock Organizations API response (verifies management account exclusion)
    - Test each action module with mocked AWS SDK responses (EC2, ECS, RDS, EIP, EBS, ALB, CloudWatch Logs)
    - Test error resilience: one resource failure does not stop processing of remaining resources
    - Test report compilation with sample AccountResult data
    - _Requirements: 15.1, 15.2, 15.3, 16.1, 16.3, 17.1, 17.3, 18.1, 18.3, 19.1, 19.5, 20.1, 20.4, 21.1_

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. CDK Stack wiring
  - [x] 9.1 Implement the main CDK stack (`lib/org-security-controls-stack.ts`)
    - Instantiate SCP Engine construct with configuration for approved regions, allowed RDS classes, blocked EC2 types, Bedrock allowlist, organization root ID
    - Instantiate Organization Trail construct with organization ID
    - Create Notifier Lambda (Node.js 20.x, bundled from `lambda/notifier/`), set `RECIPIENT_EMAIL` and `SENDER_EMAIL` env vars, grant SES send permissions
    - Create Watchdog Lambda (Node.js 20.x, bundled from `lambda/watchdog/`, 900s timeout), set `RECIPIENT_EMAIL`, `SENDER_EMAIL`, `APPROVED_REGIONS`, `CROSS_ACCOUNT_ROLE_NAME` env vars, grant SES send, Organizations listAccounts, and STS assumeRole permissions
    - Instantiate EventBridge Rules construct with reference to Notifier Lambda
    - Create EventBridge scheduled rule (Friday cron at configurable UTC time) targeting Watchdog Lambda with invoke permission
    - _Requirements: 10.1, 11.2, 12.4, 14.1, 14.2, 14.3, 14.4, 15.2_
  - [x] 9.2 Write CDK assertion tests for the main stack
    - Verify template contains all expected resources: 2 SCP policies, CloudTrail trail, S3 bucket, 17 EventBridge rules, 2 Lambda functions, scheduled rule
    - Verify Lambda environment variables are set correctly
    - Verify IAM permissions: Notifier Lambda has SES access, Watchdog Lambda has SES + Organizations + STS access
    - Verify Watchdog Lambda timeout is 900 seconds
    - Verify scheduled rule cron expression targets Friday
    - _Requirements: 14.1, 14.2, 14.4_

- [x] 10. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using fast-check (minimum 100 iterations each)
- Unit tests validate specific examples and edge cases
- CDK assertion tests verify synthesized CloudFormation template correctness
- All Lambda code uses AWS SDK v3 for Node.js 20.x
- Management account: 123456789012, Organization: o-xxxxxxxxxx, Member account: 987654321098

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["2.1", "3.1", "4.1"] },
    { "id": 3, "tasks": ["2.2", "3.2", "4.2", "6.1"] },
    { "id": 4, "tasks": ["2.3", "2.4", "2.5", "6.2"] },
    { "id": 5, "tasks": ["6.3", "6.4", "6.5", "7.1"] },
    { "id": 6, "tasks": ["7.2", "7.3", "7.4", "7.5", "7.6"] },
    { "id": 7, "tasks": ["7.7"] },
    { "id": 8, "tasks": ["7.8", "7.9", "7.10", "7.11", "7.12", "7.13", "7.14", "7.15"] },
    { "id": 9, "tasks": ["9.1"] },
    { "id": 10, "tasks": ["9.2"] }
  ]
}
```
