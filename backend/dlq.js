const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require('@aws-sdk/client-sqs');
const { loadSecrets } = require('./secrets'); // adjust relative path if needed
const { saveLog } = require('./dynamo');      // reuse your saveLog helper
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs');

async function main() {
  await loadSecrets(); // ensures env populated in your setup

  const awsRegion = process.env.AWS_REGION || 'ap-southeast-2';
  const dlqUrl = process.env.DLQ_QUEUE_URL; // set this to the DLQ URL created above
  const s3Bucket = process.env.S3_BUCKET || process.env.S3_BUCKET_NAME;
  if (!dlqUrl) throw new Error('DLQ_QUEUE_URL is required');

  const sqs = new SQSClient({ region: awsRegion });
  const s3 = new S3Client({ region: awsRegion });

  console.log('DLQ handler started, polling', dlqUrl);

  while (true) {
    try {
      const resp = await sqs.send(new ReceiveMessageCommand({
        QueueUrl: dlqUrl,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 20,
        AttributeNames: ['All'],
        MessageAttributeNames: ['All']
      }));

      if (!resp.Messages || resp.Messages.length === 0) continue;
      const msg = resp.Messages[0];

      // Save / record the failing message for later inspection
      const body = msg.Body || '';
      const receipt = msg.ReceiptHandle || '';
      const receiveCount = (msg.Attributes && msg.Attributes.ApproximateReceiveCount) || 'unknown';
      const timestamp = new Date().toISOString();

      // Save a human-readable log in DynamoDB using your saveLog API
      try {
        const record = {
          jobId: null,
          filename: `dlq-${Date.now()}`,
          startedAt: timestamp,
          completedAt: timestamp,
          status: 'dlq',
          error: `Moved to DLQ; receiveCount=${receiveCount}`,
          user: 'system',
          metadata: { originalMessage: body }
        };
        // adapt saveLog signature if necessary
        await saveLog(record);
        console.log('DLQ handler: saved dlq record to logs');
      } catch (e) {
        console.error('DLQ handler: saveLog failed', e);
      }

      // Optionally upload original message to S3 for later offline debugging
      if (s3Bucket) {
        const key = `dlq/${Date.now()}-msg.json`;
        try {
          await s3.send(new PutObjectCommand({
            Bucket: s3Bucket,
            Key: key,
            Body: Buffer.from(body),
            ContentType: 'application/json'
          }));
          console.log('DLQ handler: uploaded original message to s3:', key);
        } catch (e) {
          console.error('DLQ handler: upload to s3 failed', e);
        }
      }

      // Notify via console or SES (you can integrate SES or SNS here)
      console.warn('DLQ handler: message moved to DLQ:', { receiveCount, body });

      // Delete message from DLQ after recording/alerting
      await sqs.send(new DeleteMessageCommand({ QueueUrl: dlqUrl, ReceiptHandle: receipt }));
      console.log('DLQ handler: deleted message from DLQ');

    } catch (err) {
      console.error('DLQ handler error', err);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

main().catch(err => { console.error('DLQ handler fatal', err); process.exit(1); });