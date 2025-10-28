const { execFile, spawn } = require('child_process');
const { PassThrough, pipeline } = require('stream');
const crypto = require('crypto');

const { getPresignedUrl, uploadFile } = require('./s3'); // existing helpers
const { saveLog, saveMetadata } = require('./dynamo');
const { loadSecrets } = require('./secrets');

let sqsClient;
let queueUrl;

const POLL_WAIT_SECONDS = 20; // long-poll
const VISIBILITY_TIMEOUT = parseInt(process.env.SQS_VISIBILITY_TIMEOUT || '300', 10); // seconds

async function init() {
  // load secrets from Secrets Manager (injects into process.env)
  await loadSecrets();

  // now read env vars populated from the secret
  const { SQS_QUEUE_URL, AWS_REGION } = process.env;
  if (!SQS_QUEUE_URL) throw new Error('SQS_QUEUE_URL required in secrets or env');

  sqsClient = new (require('@aws-sdk/client-sqs').SQSClient)({ region: AWS_REGION || 'ap-southeast-2' });
  queueUrl = SQS_QUEUE_URL;

  // start polling after init
  pollLoop().catch(err => { console.error('Worker fatal error:', err); process.exit(1); });
}

async function processMessage(msg) {
  const body = JSON.parse(msg.Body);
  const { jobId, inputKey, resolution, user, startedAt } = body;
  const outputKey = `${jobId}/output-${Date.now()}.mp4`;
  const presignedInput = await getPresignedUrl(inputKey, 60); // short-lived GET url

  // build ffmpeg args (similar to server logic)
  const scaleArg = (() => {
    if (!resolution) return null;
    const m = resolution.match(/^(\d+|\?)x(\d+|\?)$/);
    if (!m) return null;
    const w = m[1] === '?' ? -1 : parseInt(m[1], 10);
    const h = m[2] === '?' ? -1 : parseInt(m[2], 10);
    return `scale=${w}:${h}`;
  })();

  const args = [
    '-i', presignedInput,
    '-hide_banner', '-loglevel', 'error',
    ...(scaleArg ? ['-vf', scaleArg] : []),
    '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '23',
    '-c:a', 'aac', '-b:a', '128k',
    '-movflags', 'frag_keyframe+empty_moov',
    '-f', 'mp4',
    'pipe:1'
  ];

  console.log(`Worker: processing job ${jobId} input=${inputKey} -> ${outputKey}`);
  const ff = spawn('ffmpeg', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  ff.stderr.on('data', d => stderr += d.toString());

  const pass = new PassThrough();
  const uploadPromise = uploadFile(outputKey, pass, 'video/mp4');

  pipeline(ff.stdout, pass, (err) => {
    if (err) console.error('Worker pipeline error:', err);
  });

  const code = await new Promise((resolve) => ff.on('close', code => resolve(code)));

  const completedAt = new Date().toISOString();
  if (code !== 0) {
    console.error(`ffmpeg failed for job ${jobId}:`, stderr);
    await saveLog({ jobId, input: inputKey, output: outputKey, resolution, startedAt, completedAt, status: 'failed', error: stderr, user });
    // do not delete message so it can be retried (or you can implement DLQ)
    return;
  }

  await uploadPromise;

  // Save metadata using ffprobe (use presigned URL for output)
  try {
    const presignedOutput = await getPresignedUrl(outputKey, 60);
    const ffprobeArgs = ['-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', presignedOutput];
    execFile('ffprobe', ffprobeArgs, (err, stdout) => {
      if (!err) {
        const metaRaw = JSON.parse(stdout);
        const metadata = {
          filename: outputKey,
          codec: metaRaw.streams[0]?.codec_name || null,
          bitrate: metaRaw.format?.bit_rate || null,
          duration: metaRaw.format?.duration || null
        };
        saveMetadata(outputKey, metadata).catch(console.error);
      }
    });
  } catch (err) {
    console.error('ffprobe failed:', err);
  }

  await saveLog({ jobId, input: inputKey, output: outputKey, resolution, startedAt, completedAt, status: 'done', user });

  // delete message from queue
  await sqsClient.send(new DeleteMessageCommand({
    QueueUrl: queueUrl,
    ReceiptHandle: msg.ReceiptHandle
  }));

  console.log(`Worker: job ${jobId} complete`);
}

async function pollLoop() {
  while (true) {
    try {
      const data = await sqsClient.send(new ReceiveMessageCommand({
        QueueUrl: queueUrl,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: POLL_WAIT_SECONDS,
        VisibilityTimeout: VISIBILITY_TIMEOUT,
        MessageAttributeNames: ['All']
      }));

      if (!data.Messages || data.Messages.length === 0) continue;

      const msg = data.Messages[0];

      // Optionally extend visibility during long jobs:
      // periodically call ChangeMessageVisibilityCommand if needed.

      await processMessage(msg);
    } catch (err) {
      console.error('Worker poll error:', err);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

// replace final call with init()
init();