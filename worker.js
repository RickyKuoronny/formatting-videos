const { Consumer } = require('sqs-consumer');
const { spawn, execFile } = require('child_process');
const { Readable, PassThrough, pipeline } = require('stream');
const path = require('path');
const fs = require('fs');

const { uploadFile, getFileStream, getPresignedUrl } = require('./backend/s3');
const { saveMetadata, saveLog } = require('./backend/dynamo');
const { loadSecrets } = require('./backend/secrets');
const { loadAppConfig } = require('./backend/paramStore');

// Helper: build ffmpeg args for scale preserving aspect ratio if ? used.
// Accepts resolution like "1280x720", "1280x?", "?x720"
function buildScaleArg(res) {
    if (!res) return null;
    const match = res.match(/^(\d+|\?)x(\d+|\?)$/);
    if (!match) return null;
    const w = match[1], h = match[2];
    if (w === '?' && h === '?') return null; // nothing to do
    // If one side is ?, use -1 in ffmpeg to preserve aspect
    const width = w === '?' ? -1 : parseInt(w, 10);
    const height = h === '?' ? -1 : parseInt(h, 10);
    return `scale=${width}:${height}`;
}

async function processVideo(message) {
    const { inputFile, resolution, user, originalname } = JSON.parse(message.Body);
    const outName = path.basename(originalname, path.extname(originalname)) + '-converted.mp4';
    const startedAt = new Date().toISOString();

    console.log(`[${startedAt}] Processing ${inputFile} for user ${user}`);

    const scaleArg = buildScaleArg(resolution);

    const args = [
        '-i', 'pipe:0',
        '-hide_banner',
        '-loglevel', 'error',
        ...(scaleArg ? ['-vf', scaleArg] : []),
        '-c:v', 'libx264',
        '-preset', 'veryfast',
        '-crf', '23',
        '-c:a', 'aac',
        '-b:a', '128k',
        '-movflags', 'frag_keyframe+empty_moov',
        '-f', 'mp4',
        'pipe:1'
    ];

    console.log('FFmpeg args:', args.join(' '));

    const ff = spawn('ffmpeg', args);
    let ffErr = '';
    ff.stderr.on('data', d => ffErr += d.toString());
    ff.stdin.on('error', err => { if (err.code !== 'EPIPE') console.error('FFmpeg stdin error:', err); });

    const inStream = await getFileStream(inputFile);
    pipeline(inStream, ff.stdin, err => {
        if (err && err.code !== 'EPIPE') console.error('Pipeline error (stdin):', err);
    });

    const passThrough = new PassThrough();
    const uploadPromise = uploadFile(outName, passThrough, 'video/mp4')
        .catch(err => console.error('S3 upload failed:', err));
    ff.stdout.pipe(passThrough);

    ff.on('close', async code => {
        const completedAt = new Date().toISOString();
        const logEntry = {
            input: originalname,
            output: outName,
            resolution,
            startedAt,
            completedAt,
            user
        };

        await saveLog(logEntry);

        if (code !== 0) {
            console.error(`[${completedAt}] FFmpeg failed for ${outName}:`, ffErr);
            return;
        }

        await uploadPromise;
        console.log(`[${completedAt}] Successfully processed and uploaded ${outName}`);

        const presignedUrl = await getPresignedUrl(outName);

        const ffprobeArgs = [
            '-v', 'quiet',
            '-print_format', 'json',
            '-show_format',
            '-show_streams',
            presignedUrl
        ];

        execFile('ffprobe', ffprobeArgs, (err, stdout) => {
            if (err) {
                console.error('Failed to generate metadata:', err);
                return;
            }

            const metaRaw = JSON.parse(stdout);
            const metadata = {
                filename: outName,
                codec: metaRaw.streams[0]?.codec_name || null,
                bitrate: metaRaw.format?.bit_rate || null
            };

            saveMetadata(outName, metadata).catch(console.error);
        });
    });

    ff.on('error', err => {
        console.error('FFmpeg process error:', err);
    });
}

async function startWorker() {
    await loadSecrets();
    const config = await loadAppConfig();

    if (!config.sqsQueueUrl) {
        console.error("SQS_QUEUE_URL is not configured in Parameter Store. The worker cannot start.");
        process.exit(1);
    }

    const app = Consumer.create({
        queueUrl: config.sqsQueueUrl,
        handleMessage: processVideo,
        sqs: new (require('@aws-sdk/client-sqs').SQSClient)({
            region: config.region || process.env.AWS_REGION
        }),
        batchSize: 1,
        visibilityTimeout: 300 // 5 minutes, should be longer than max processing time
    });

    app.on('error', (err) => {
        console.error("SQS Consumer error:", err.message);
    });

    app.on('processing_error', (err) => {
        console.error("Processing error:", err.message);
    });
    
    app.on('stopped', () => {
        console.log("Worker has stopped.");
    });

    app.start();
    console.log(`Worker started, polling queue: ${config.sqsQueueUrl}`);
}

startWorker().catch(err => {
    console.error("Failed to start worker:", err);
    process.exit(1);
});
