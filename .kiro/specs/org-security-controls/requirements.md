# Requirements Document

## Introduction

This document defines the requirements for an AWS CDK project that implements an AWS Organizations security and cost-control system. The system consists of three main components: Service Control Policies (SCPs) for preventive guardrails, an EventBridge-based real-time security notification pipeline, and a scheduled "Watchdog" Lambda for cost control enforcement across member accounts.

## Glossary

- **CDK_Stack**: An AWS CDK stack that synthesizes and deploys the security and cost-control infrastructure
- **SCP_Engine**: The component responsible for defining and attaching Service Control Policies to the AWS Organization
- **Notifier_Lambda**: The single AWS Lambda function that receives security events and dispatches formatted alerts via email
- **Watchdog_Lambda**: The scheduled AWS Lambda function that assumes a cross-account role into member accounts and enforces cost-control actions
- **EventBridge_Rules**: The set of Amazon EventBridge rules that match specific CloudTrail management events and route them to the Notifier Lambda
- **Formatter**: A module within the Notifier Lambda that selects and applies the appropriate message template for a given event type
- **Organization_Trail**: An organization-level CloudTrail trail that captures management events across all accounts and delivers them to EventBridge on the default event bus
- **Organization_Bus**: The default EventBridge event bus in the management account, which receives CloudTrail management events once the Organization_Trail is configured
- **Approved_Regions**: The set of four AWS regions permitted for resource deployment (configurable)
- **Allowed_RDS_Classes**: The set of permitted RDS instance classes (db.t3.micro, db.t3.small, db.t4g.micro, db.t4g.small)
- **Blocked_EC2_Types**: EC2 instance types denied by policy — replaced by allowlist approach: only types in `Allowed_EC2_Types` are permitted
- **Allowed_EC2_Types**: The set of permitted EC2 instance types (t4g.nano, t4g.micro)
- **Identity_Center_MFA**: The MFA configuration applied to AWS Identity Center (SSO) that enforces multi-factor authentication at the identity provider level for all human users
- **OrganizationAccountAccessRole**: The IAM role in each member account that the Watchdog Lambda assumes for cross-account operations

## Requirements

### Requirement 1: Region Restriction SCP

**User Story:** As a cloud security administrator, I want to restrict resource creation to approved regions only, so that workloads cannot be deployed in unapproved regions.

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement that denies all actions on resources outside the Approved_Regions, excluding global services that do not operate in a specific region (such as IAM, STS, Organizations, CloudFront, Route 53, Support, and Budgets)
2. WHEN a principal attempts to create or modify a resource in a region not in the Approved_Regions list, THE SCP_Engine policy SHALL deny the request using the `aws:RequestedRegion` condition key
3. THE SCP_Engine SHALL allow the Approved_Regions to be configurable via CDK context or construct properties, with a default value of 4 regions as defined in the project configuration
4. IF the Approved_Regions list is explicitly set to empty, THEN THE SCP_Engine SHALL raise a synthesis-time error indicating that at least 1 approved region must be specified, regardless of any default configuration existing elsewhere in the system

### Requirement 2: RDS Instance Class Restriction SCP

**User Story:** As a cost-control administrator, I want to restrict RDS instance classes to small and micro tiers only, so that teams cannot provision expensive database instances.

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement that denies `rds:CreateDBInstance`, `rds:ModifyDBInstance`, `rds:CreateDBCluster`, `rds:RestoreDBInstanceFromDBSnapshot`, and `rds:RestoreDBInstanceToPointInTime` actions when the `rds:DatabaseClass` condition key does not match the Allowed_RDS_Classes (db.t3.micro, db.t3.small, db.t4g.micro, db.t4g.small)
2. WHEN a principal attempts to create, modify, or restore an RDS instance or cluster with a class not in the Allowed_RDS_Classes, THE SCP_Engine policy SHALL deny the request
3. THE SCP_Engine SHALL allow the Allowed_RDS_Classes list to be configurable via CDK context or construct properties

### Requirement 3: EC2 Instance Type Restriction SCP

**User Story:** As a cost-control administrator, I want to allow only t4g.nano and t4g.micro EC2 instance types, so that teams cannot launch any other instance type without exception.

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement that denies `ec2:RunInstances` when the `ec2:InstanceType` condition key does not match the Allowed_EC2_Types list (t4g.nano, t4g.micro) using a `StringNotEquals` condition operator
2. WHEN a principal attempts to launch an EC2 instance with a type not in the Allowed_EC2_Types list, THE SCP_Engine policy SHALL deny the request
3. THE SCP_Engine SHALL allow the Allowed_EC2_Types list to be configurable via CDK context or construct properties

### Requirement 4: CloudTrail Tampering Prevention SCP

**User Story:** As a security administrator, I want to prevent any principal from disabling or modifying CloudTrail, so that audit logs remain intact.

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement that denies `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, and `cloudtrail:PutEventSelectors` actions on all CloudTrail resources (resource scope: `*`)
2. WHEN a principal attempts to perform any of the denied CloudTrail actions listed in criterion 1, THE SCP_Engine policy SHALL deny the request regardless of any identity-based policies attached to the principal
3. IF an exempt principal (as defined in the SCP condition key) attempts a denied CloudTrail action, THEN THE SCP_Engine SHALL still deny the request unless the principal matches a designated break-glass role ARN specified in the policy condition
4. THE SCP_Engine SHALL apply the deny effect unconditionally to the specified CloudTrail actions, with no conditions that could weaken the denial other than the optional break-glass role exclusion defined in criterion 3

### Requirement 5: Root User Action Denial SCP

**User Story:** As a security administrator, I want to deny all actions performed by the root user across the organization, so that root access cannot be used for operational tasks.

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement with Effect Deny that denies all actions (`*`) on all resources (`*`) when the condition `aws:PrincipalArn` matches the pattern `arn:aws:iam::*:root`
2. WHEN the root user attempts any action in a member account, THE SCP_Engine policy SHALL deny the request regardless of the action, service, or resource targeted
3. IF the root user attempts an action in the management account, THEN THE SCP_Engine policy SHALL not apply (SCPs do not govern the management account)

### Requirement 6: IAM User Creation Denial SCP

**User Story:** As a security administrator, I want to prevent creation of IAM users, so that all human access goes through Identity Center (SSO).

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement that denies `iam:CreateUser`, `iam:CreateLoginProfile`, and `iam:CreateAccessKey` actions
2. WHEN a principal attempts to create an IAM user, attach a login profile, or create an access key, THE SCP_Engine policy SHALL deny the request

### Requirement 7: Bedrock Access Gating SCP

**User Story:** As a security administrator, I want to restrict Amazon Bedrock access to specific authorized users only, so that generative AI usage is controlled.

#### Acceptance Criteria

1. THE SCP_Engine SHALL define a DenyServices policy statement that denies all `bedrock:*` actions unless the principal's ARN matches an entry in the Bedrock allowlist, using the `aws:PrincipalArn` condition key with `ArnNotLike` operator
2. WHEN a principal whose ARN does not match any entry in the Bedrock allowlist attempts a Bedrock action, THE SCP_Engine policy SHALL deny the request
3. THE SCP_Engine SHALL allow the Bedrock authorized principal list to be configurable via CDK context or construct properties, accepting 0 to 20 IAM principal ARN patterns as entries (an empty list denies all Bedrock access)
4. IF the Bedrock allowlist is empty or not provided, THEN THE SCP_Engine SHALL deny all `bedrock:*` actions for all principals in the organization

### Requirement 8: DenyServices Policy Bundling

**User Story:** As a cloud administrator, I want all denial statements bundled into a single SCP, so that I stay within the Organizations SCP-per-target limit.

#### Acceptance Criteria

1. THE SCP_Engine SHALL bundle all seven denial statements (region restriction, RDS class, EC2 type, CloudTrail tampering, root user, IAM user creation, Bedrock gating) into a single policy named "DenyServices", where each statement has a unique Sid identifying its purpose
2. THE SCP_Engine SHALL validate during CDK synthesis that the combined policy document does not exceed 5120 characters (the SCP size limit)
3. IF the combined policy exceeds 5120 characters, THEN THE SCP_Engine SHALL raise a synthesis-time error with a message indicating the current policy size in characters and the 5120-character maximum
4. THE SCP_Engine SHALL produce a valid IAM policy document containing a Version field and a Statement array with exactly seven deny statements

### Requirement 9: Identity Center MFA Enforcement

**User Story:** As a security administrator, I want Identity Center configured to require MFA for all users, so that human access is protected by a second factor at the authentication layer.

#### Acceptance Criteria

1. THE CDK_Stack SHALL configure Identity Center authentication settings to require MFA for all users during sign-in
2. IF a user attempts to sign in without MFA configured, THEN Identity Center SHALL prompt them to register an MFA device before allowing access
3. THE Identity Center MFA configuration SHALL accept authenticator apps and hardware security keys as MFA methods

### Requirement 10: Organization CloudTrail Trail

**User Story:** As a security administrator, I want an organization-level CloudTrail trail that captures management events across all accounts, so that security-relevant activities flow to EventBridge for real-time alerting.

#### Acceptance Criteria

1. THE CDK_Stack SHALL create an organization-level CloudTrail trail that captures management events for all accounts in the organization
2. THE CDK_Stack SHALL configure the trail to deliver events to the default EventBridge event bus in the management account (account 401955065246), conditional on management event capture being enabled
3. THE CDK_Stack SHALL create an S3 bucket for trail log storage with appropriate bucket policy allowing CloudTrail writes from the organization
4. THE CDK_Stack SHALL enable the trail for all regions to capture events regardless of where they originate

### Requirement 11: EventBridge Rule Definitions

**User Story:** As a security administrator, I want EventBridge rules with precise pattern matching that filter events before invoking Lambda, so that costs are minimized and only relevant events trigger notifications.

#### Acceptance Criteria

1. THE EventBridge_Rules SHALL define one rule per event pattern on the default event bus, each matching exactly one of the following event patterns:
   - Root console login
   - Console login without MFA
   - Login failure
   - CloudTrail StopLogging
   - CloudTrail DeleteTrail
   - CloudTrail UpdateTrail
   - CloudTrail PutEventSelectors
   - IAM user created
   - Access key created
   - Login profile attached
   - MFA device deactivated
   - Identity Center user created
   - Security group ingress opened
   - Cost anomaly detected
   - Budget threshold breached
   - Access Analyzer finding published
   - Organization-level event
2. WHEN an event matching any defined rule pattern is published to the default event bus, THE EventBridge_Rules SHALL deliver the event to the Notifier_Lambda as the rule target
3. THE EventBridge_Rules SHALL perform all filtering at the rule pattern level using explicit values for `source`, `detail-type`, and/or `detail.eventName` fields, so that the Notifier_Lambda is never invoked for irrelevant events (cost minimization: no Lambda invocations for non-matching events)
4. THE EventBridge_Rules SHALL NOT use wildcard characters in patterns; each rule SHALL match only its specific event type
5. IF the Notifier_Lambda invocation fails or is throttled, THEN THE EventBridge_Rules SHALL retry delivery up to 3 times over a maximum retention period of 24 hours

### Requirement 12: Notifier Lambda Event Processing

**User Story:** As a security administrator, I want a single Lambda function that processes all security events and dispatches formatted alerts via email, so that notification logic is centralized.

#### Acceptance Criteria

1. WHEN the Notifier_Lambda receives an event, THE Notifier_Lambda SHALL inspect the event and select the appropriate Formatter based on the event type
2. WHEN the Notifier_Lambda has formatted an alert, THE Notifier_Lambda SHALL send the alert to the SES email destination
3. IF the Notifier_Lambda fails to deliver to the SES email destination, THEN THE Notifier_Lambda SHALL log an error message indicating the event type, timestamp, and failure reason
4. THE Notifier_Lambda SHALL accept the SES recipient email address as an environment variable
5. IF the SES recipient email address environment variable is missing or empty at invocation time, THEN THE Notifier_Lambda SHALL log an error indicating the missing configuration and skip delivery

### Requirement 13: Notifier Lambda Formatter Selection

**User Story:** As a developer, I want each event type to have a dedicated formatting template, so that alerts are human-readable and contextually rich.

#### Acceptance Criteria

1. WHEN the Notifier_Lambda receives an event, THE Formatter SHALL select a formatting template that matches the event type based on the `source` and `detail.eventName` fields
2. THE Formatter SHALL produce a human-readable message containing the event source, timestamp, affected account, affected principal, and event-specific details
3. IF no specific Formatter matches the event type, THEN THE Formatter SHALL use a generic template that includes the raw event details in JSON format

### Requirement 14: Watchdog Lambda Scheduling

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to run on a weekly schedule every Friday, so that cost-saving actions are applied regularly.

#### Acceptance Criteria

1. THE CDK_Stack SHALL configure an EventBridge scheduled rule that triggers the Watchdog_Lambda every Friday at a configurable time of day expressed in UTC (default: 18:00 UTC)
2. THE CDK_Stack SHALL configure the Watchdog_Lambda with a timeout of 900 seconds to accommodate cross-account processing across all member accounts and Approved_Regions
3. WHEN the scheduled rule triggers, THE Watchdog_Lambda SHALL execute its cost-control workflow (cross-account access, EC2/ECS stop, RDS stop, EIP release, EBS/ALB reporting, log group retention enforcement, and execution report delivery)
4. THE CDK_Stack SHALL grant the EventBridge scheduled rule permission to invoke the Watchdog_Lambda

### Requirement 15: Watchdog Lambda Cross-Account Access

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to assume a role into every member account, so that it can inspect and act on resources across the organization.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda executes, THE Watchdog_Lambda SHALL retrieve the list of member accounts from the Organization, excluding the management account
2. THE Watchdog_Lambda SHALL assume the OrganizationAccountAccessRole in each member account with a session duration of exactly 3600 seconds; IF a role assumption request specifies a duration exceeding 3600 seconds, THEN THE Watchdog_Lambda SHALL reject the request
3. IF the Watchdog_Lambda fails to assume the role in a member account, THEN THE Watchdog_Lambda SHALL log the failure including the account ID and error message, and continue processing remaining accounts

### Requirement 16: Watchdog Lambda EC2 and ECS Stop

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to stop running EC2 instances and ECS tasks in member accounts, so that idle compute resources do not accumulate costs.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all EC2 instances in the "running" state across all Approved_Regions
2. WHEN the Watchdog_Lambda has enumerated running EC2 instances in a member account, THE Watchdog_Lambda SHALL issue a stop command for each running EC2 instance found
3. IF the Watchdog_Lambda fails to stop an individual EC2 instance, THEN THE Watchdog_Lambda SHALL log the instance identifier and failure reason and continue processing remaining instances
4. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all ECS clusters across all Approved_Regions and list all tasks in the "RUNNING" status within each cluster
5. WHEN the Watchdog_Lambda has enumerated running ECS tasks in a member account, THE Watchdog_Lambda SHALL issue a stop command for each running ECS task found
6. IF the Watchdog_Lambda fails to stop an individual ECS task, THEN THE Watchdog_Lambda SHALL log the task identifier and failure reason and continue processing remaining tasks

### Requirement 17: Watchdog Lambda RDS Stop

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to stop running RDS instances in member accounts, so that idle database resources do not accumulate costs.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all RDS DB instances with a status of "available" across all Approved_Regions
2. WHEN the Watchdog_Lambda finds RDS DB instances with a status of "available" in a member account, THE Watchdog_Lambda SHALL stop each instance
3. IF the Watchdog_Lambda fails to stop an RDS instance, THEN THE Watchdog_Lambda SHALL log the failure including the instance identifier and region, mark the account operation as failed requiring retry or manual intervention, and continue processing remaining instances
4. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all Aurora DB clusters with a status of "available" across all Approved_Regions and stop each cluster; THE Watchdog_Lambda SHALL only stop clusters after proper account assumption and enumeration is confirmed

### Requirement 18: Watchdog Lambda EIP Release

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to release unattached Elastic IP addresses, so that unused EIPs do not accumulate costs.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all Elastic IP addresses across all Approved_Regions
2. WHEN the Watchdog_Lambda identifies an Elastic IP address that has no associated network interface, THE Watchdog_Lambda SHALL release that Elastic IP address
3. IF the Watchdog_Lambda fails to release an Elastic IP address, THEN THE Watchdog_Lambda SHALL log the failure including the allocation ID and region, and continue processing remaining Elastic IP addresses

### Requirement 19: Watchdog Lambda EBS and ALB Reporting

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to report unused EBS volumes and empty ALBs, so that I have visibility into wasted resources.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all EBS volumes across all Approved_Regions and identify volumes in the "available" state (not attached to any instance)
2. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all Application Load Balancers across all Approved_Regions and identify ALBs where no target group has any registered target
3. THE Watchdog_Lambda SHALL include each unused EBS volume in its execution report with the volume identifier, size in GiB, associated account, and region
4. THE Watchdog_Lambda SHALL include each empty ALB in its execution report with the ALB name, associated account, and region
5. IF the Watchdog_Lambda fails to enumerate EBS volumes or ALBs in a given region, THEN THE Watchdog_Lambda SHALL log the failure and continue processing remaining regions

### Requirement 20: Watchdog Lambda Log Group Retention

**User Story:** As a cost-control administrator, I want the Watchdog Lambda to enforce a 30-day retention policy on log groups that lack one, so that logs do not accumulate indefinitely.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda assumes into a member account, THE Watchdog_Lambda SHALL enumerate all CloudWatch log groups across all Approved_Regions
2. WHEN a log group has no retention policy configured (retentionInDays is absent), THE Watchdog_Lambda SHALL set the retention policy to 30 days
3. WHILE a log group already has a retention policy set to any value, THE Watchdog_Lambda SHALL leave the existing retention policy unchanged regardless of whether the configured period is shorter or longer than 30 days
4. IF the Watchdog_Lambda fails to set the retention policy on a log group, THEN THE Watchdog_Lambda SHALL log the failure including the log group name and region, and continue processing remaining log groups

### Requirement 21: Watchdog Lambda Execution Report

**User Story:** As a cost-control administrator, I want a summary report after each Watchdog Lambda run, so that I know what actions were taken across the organization.

#### Acceptance Criteria

1. WHEN the Watchdog_Lambda completes its execution (including partial execution where some accounts failed role assumption), THE Watchdog_Lambda SHALL produce a summary report listing all actions taken, organized per account and per region
2. THE Watchdog_Lambda SHALL include in the report: counts of EC2 instances stopped, ECS tasks stopped, RDS instances stopped, EIPs released, log groups updated, unused EBS volumes found, and empty ALBs found, with each count broken down per account and per region
3. WHEN the Watchdog_Lambda has produced the summary report, THE Watchdog_Lambda SHALL deliver the report via SES email using the same configuration as the Notifier_Lambda
4. IF SES delivery returns an explicit failure status, THEN THE Watchdog_Lambda SHALL log the failure details; pending delivery states SHALL NOT be logged as failures
5. THE Watchdog_Lambda SHALL include in the report the list of member accounts where role assumption failed, indicating which accounts could not be processed
