import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { CloudTrailEventBridgeEvent, Formatter, EmailMessage } from './types';
import { formatters } from './formatters';

const sesClient = new SESClient({});

/**
 * Returns the array of all registered formatters.
 */
export function getFormatters(): Formatter[] {
  return formatters;
}

/**
 * Selects the appropriate formatter for the given event.
 * Returns undefined if no formatter matches.
 */
export function selectFormatter(
  event: CloudTrailEventBridgeEvent,
  formatters: Formatter[]
): Formatter | undefined {
  return formatters.find((f) => f.canHandle(event));
}

/**
 * Generic formatter for unknown event types.
 * Produces an EmailMessage with raw JSON details.
 */
export function genericFormat(event: CloudTrailEventBridgeEvent): EmailMessage {
  const eventName = event.detail?.eventName ?? 'Unknown';
  const source = event.source ?? 'unknown';

  return {
    subject: `[Security Alert] Unknown event: ${source}/${eventName}`,
    body: `
<html>
<body>
<h2>Security Alert: Unrecognized Event</h2>
<p><strong>Source:</strong> ${source}</p>
<p><strong>Event Name:</strong> ${eventName}</p>
<p><strong>Time:</strong> ${event.time}</p>
<p><strong>Account:</strong> ${event.account}</p>
<p><strong>Region:</strong> ${event.region}</p>
<h3>Raw Event Details</h3>
<pre>${JSON.stringify(event, null, 2)}</pre>
</body>
</html>`.trim(),
  };
}

/**
 * Main Lambda handler for the Notifier function.
 * Receives EventBridge events, selects a formatter, formats the message, and sends via SES.
 */
export async function handler(event: CloudTrailEventBridgeEvent): Promise<void> {
  const recipientEmail = process.env.RECIPIENT_EMAIL;
  const senderEmail = process.env.SENDER_EMAIL || 'noreply@example.com';

  if (!recipientEmail) {
    console.error('Missing RECIPIENT_EMAIL configuration');
    return;
  }

  const formatters = getFormatters();
  const formatter = selectFormatter(event, formatters);

  let message: EmailMessage;
  if (formatter) {
    message = formatter.format(event);
  } else {
    message = genericFormat(event);
  }

  try {
    await sesClient.send(
      new SendEmailCommand({
        Source: senderEmail,
        Destination: {
          ToAddresses: [recipientEmail],
        },
        Message: {
          Subject: { Data: message.subject },
          Body: {
            Html: { Data: message.body },
          },
        },
      })
    );
  } catch (error) {
    const eventType = `${event.source}/${event.detail?.eventName ?? 'Unknown'}`;
    const timestamp = event.time;
    const reason = error instanceof Error ? error.message : String(error);
    console.error(
      `SES delivery failed: eventType=${eventType}, timestamp=${timestamp}, reason=${reason}`
    );
  }
}
