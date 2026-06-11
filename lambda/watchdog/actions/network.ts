import {
  EC2Client,
  DescribeAddressesCommand,
  ReleaseAddressCommand,
  Address,
} from '@aws-sdk/client-ec2';

/**
 * Filters Elastic IP addresses to return only those that are unattached.
 * An EIP is considered unattached if it has no NetworkInterfaceId AND no AssociationId.
 */
export function filterUnattachedEips(addresses: Address[]): Address[] {
  return addresses.filter(
    (addr) => !addr.NetworkInterfaceId && !addr.AssociationId,
  );
}

/**
 * Enumerates all Elastic IPs in the given region and releases those
 * with no associated network interface.
 * Logs and continues on individual release failures.
 * Returns array of released allocation IDs.
 */
export async function releaseUnattachedEips(
  credentials: any,
  region: string,
): Promise<string[]> {
  const ec2Client = new EC2Client({
    region,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
    },
  });

  // Enumerate all Elastic IPs
  let addresses: Address[] = [];
  try {
    const response = await ec2Client.send(new DescribeAddressesCommand({}));
    addresses = response.Addresses || [];
  } catch (error: any) {
    console.error('Failed to describe Elastic IPs:', {
      region,
      error: error.message,
    });
    return [];
  }

  // Filter to unattached EIPs
  const unattached = filterUnattachedEips(addresses);

  // Release each unattached EIP
  const released: string[] = [];
  for (const eip of unattached) {
    const allocationId = eip.AllocationId;
    if (!allocationId) {
      continue;
    }

    try {
      await ec2Client.send(
        new ReleaseAddressCommand({ AllocationId: allocationId }),
      );
      released.push(allocationId);
    } catch (error: any) {
      console.error('Failed to release Elastic IP:', {
        allocationId,
        region,
        error: error.message,
      });
    }
  }

  return released;
}
