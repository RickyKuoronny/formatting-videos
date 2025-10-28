const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require('@aws-sdk/client-sqs');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { spawn } = require('child_process');
const { loadSecrets } = require('./secrets');

const fs = require('fs');
const path = require('path');
const os = require('os');

const { uploadFile } = require('./s3');
const { saveMetadata } = require('./dynamo');
  

await loadSecrets(); // injects secrets into process.env
const awsRegion = process.env.AWS_REGION || 'ap-southeast-2';
const queueUrl = process.env.THUMB_QUEUE_URL;
const bucket = process.env.S3_BUCKET || process.env.S3_BUCKET_NAME;

if (!queueUrl) throw new Error('THUMB_QUEUE_URL required');

const s3 = new S3Client({ region: awsRegion });
const sqs = new SQSClient({ region: awsRegion });

async function processMessage(msg) {
  const body = JSON.parse(msg.Body || '{}');
  const jobId = body.jobId || body.id;
  const outputKey = body.outputKey || body.output || body.outputFile;
  if (!jobId || !outputKey) {
    console.warn('thumbnail-service: missing jobId/outputKey', body);
    return;
  }
  console.log('thumbnail-service: processing', jobId, outputKey);

  const tmp = os.tmpdir();
  const inPath = path.join(tmp, `in-${Date.now()}.mp4`);
  const outPath = path.join(tmp, `thumb-${Date.now()}.jpg`);

  // download object
  const getCmd = new GetObjectCommand({ Bucket: bucket, Key: outputKey });
  const r = await s3.send(getCmd);
  await new Promise((resolve, reject) => {
    const ws = fs.createWriteStream(inPath);
    r.Body.pipe(ws).on('finish', resolve).on('error', reject);
  });

  // ffmpeg to extract thumbnail
  await new Promise((resolve, reject) => {
    const ff = spawn('ffmpeg', ['-y', '-i', inPath, '-ss', '00:00:01.000', '-vframes', '1', '-q:v', '2', outPath]);
    ff.on('error', reject);
    ff.on('close', code => code === 0 ? resolve() : reject(new Error('ffmpeg failed')));
  });

  const thumbKey = `${jobId}/thumb-${Date.now()}.jpg`;
  await uploadFile(thumbKey, fs.createReadStream(outPath), 'image/jpeg').catch(err => {
    console.error('thumbnail-service: upload failed', err);
    throw err;
  });

  // save metadata record
  await saveMetadata(thumbKey, { jobId, type: 'thumbnail', key: thumbKey }).catch(console.error);

  try { fs.unlinkSync(inPath); } catch (e) {}
  try { fs.unlinkSync(outPath); } catch (e) {}

  console.log('thumbnail-service: completed', jobId, thumbKey);
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
        console.error('thumbnail-service: message processing error', err);
      }
    } catch (err) {
      console.error('thumbnail-service: loop error', err);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

loop().catch(err => { console.error('thumbnail-service fatal', err); process.exit(1); });