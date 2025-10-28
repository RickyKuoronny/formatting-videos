const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require('@aws-sdk/client-sqs');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const { loadSecrets } = require('./secrets');

await loadSecrets(); // injects secrets into process.env
const awsRegion = process.env.AWS_REGION || 'ap-southeast-2';
const queueUrl = process.env.NOTIFY_QUEUE_URL;
const fromAddr = process.env.SES_EMAIL_FROM;

if (!queueUrl) throw new Error('NOTIFY_QUEUE_URL required');

const sqs = new SQSClient({ region: awsRegion });
const ses = new SESClient({ region: awsRegion });

async function sendEmail(to, subject, body) {
  if (!fromAddr) {
    console.log('notifier-service (no SES):', { to, subject, body });
    return;
  }
  const cmd = new SendEmailCommand({
    Source: fromAddr,
    Destination: { ToAddresses: [to] },
    Message: {
      Subject: { Data: subject },
      Body: { Text: { Data: body } }
    }
  });
  await ses.send(cmd);
}

async function processMessage(msg) {
  const body = JSON.parse(msg.Body || '{}');
  const jobId = body.jobId;
  const outputKey = body.outputKey || body.output;
  const user = body.user || process.env.NOTIFY_DEFAULT_RECIPIENT;
  const subject = `Video processed: ${jobId}`;
  const url = outputKey ? `s3://${process.env.S3_BUCKET || process.env.S3_BUCKET_NAME}/${outputKey}` : 'unknown';
  const text = `Job ${jobId} completed. Output: ${url}`;

  await sendEmail(user, subject, text).catch(err => console.error('notifier-service: email failed', err));
  console.log('notifier-service: notified', jobId, user);
}

async function loop() {
  while (true) {
    try {
      const resp = await sqs.send(new ReceiveMessageCommand({
        QueueUrl: queueUrl,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 20
      }));
      if (!resp.Messages || resp.Messages.length === 0) continue;
      const msg = resp.Messages[0];
      try {
        await processMessage(msg);
        await sqs.send(new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: msg.ReceiptHandle }));
      } catch (err) {
        console.error('notifier-service: message processing error', err);
      }
    } catch (err) {
      console.error('notifier-service: loop error', err);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

loop().catch(err => { console.error('notifier-service fatal', err); process.exit(1); });
