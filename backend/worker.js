const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand, ChangeMessageVisibilityCommand, SendMessageCommand } = require('@aws-sdk/client-sqs');
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
  await loadSecrets(); // injects secrets into process.env

  const awsRegion = process.env.AWS_REGION || 'ap-southeast-2';
  const { SQS_QUEUE_URL } = process.env;
  if (!SQS_QUEUE_URL) throw new Error('SQS_QUEUE_URL required in secrets or env');

  sqsClient = new SQSClient({ region: awsRegion });
  queueUrl = SQS_QUEUE_URL;

  pollLoop().catch(err => { console.error('Worker fatal error:', err); process.exit(1); });
}

async function processMessage(msg) {
  const body = JSON.parse(msg.Body);
  const { jobId, inputKey, resolution, user, startedAt } = body;
  const outputKey = `${jobId}/output-${Date.now()}.mp4`;
  const presignedInput = await getPresignedUrl(inputKey, 60); // short-lived GET url

  // Build ffmpeg args
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

  const code = await new Promise(resolve => ff.on('close', resolve));
  const completedAt = new Date().toISOString();

  if (code !== 0) {
    console.error(`ffmpeg failed for job ${jobId}:`, stderr);
    await saveLog({
      jobId,
      input: inputKey,
      output: outputKey,
      resolution,
      startedAt,
      completedAt,
      status: 'failed',
      error: stderr,
      user
    });
    return; // do not delete message so it can be retried
  }

  await uploadPromise;

  // Get metadata and save final log
  try {
    const presignedOutput = await getPresignedUrl(outputKey, 60);
    const ffprobeArgs = ['-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', presignedOutput];

    const metadata = await new Promise(resolve => {
      execFile('ffprobe', ffprobeArgs, (err, stdout) => {
        if (err) return resolve({});
        try {
          const metaRaw = JSON.parse(stdout);
          resolve({
            codec: metaRaw.streams[0]?.codec_name || null,
            bitrate: metaRaw.format?.bit_rate || null,
            duration: metaRaw.format?.duration || null,
            width: metaRaw.streams[0]?.width || null,
            height: metaRaw.streams[0]?.height || null
          });
        } catch {
          resolve({});
        }
      });
    });

    // Save final job log including metadata
    const logsQueueUrl = process.env.LOGS_QUEUE_URL;
    const sqsClientLocal = new SQSClient({ region: process.env.AWS_REGION || 'ap-southeast-2' });
    const logRecord = {
      jobId,
      input: inputKey,
      output: outputKey,
      outputKey: outputKey,
      outputFile: outputKey,
      s3Key: outputKey,
      resolution,
      startedAt,
      completedAt,
      status: 'done',
      user
    };
    if (logsQueueUrl) {
      try {
        await sqsClientLocal.send(new SendMessageCommand({
          QueueUrl: logsQueueUrl,
          MessageBody: JSON.stringify(logRecord),
          MessageAttributes: { source: { DataType: 'String', StringValue: 'worker' } }
        }));
        console.log(`Worker: enqueued log for job ${jobId} to logs queue`);
      } catch (err) {
        console.error('Worker: failed to enqueue log', err);
      }
    } else {
      try { await saveLog(logRecord); console.log(`Worker: fallback saved log for job ${jobId}`); } catch (err) { console.error('Worker: fallback saveLog failed', err); }
    }

    console.log(`Worker: saved log for job ${jobId} with metadata`);

    // Delete SQS message after everything is done
    await sqsClient.send(new DeleteMessageCommand({
      QueueUrl: queueUrl,
      ReceiptHandle: msg.ReceiptHandle
    }));

    console.log(`Worker: job ${jobId} complete`);

  } catch (err) {
    console.error('ffprobe or saveLog failed:', err);
  }
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