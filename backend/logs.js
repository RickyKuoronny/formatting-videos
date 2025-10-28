const express = require('express');
const os = require('os');
const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require('@aws-sdk/client-sqs');
const { loadSecrets } = require('./secrets'); // optional for loading env/secrets
const { saveLog, getLogs } = require('./dynamo');

const AWS_REGION = process.env.AWS_REGION || 'ap-southeast-2';
const LOGS_QUEUE_URL = process.env.LOGS_QUEUE_URL;
const PORT = process.env.PORT || 4000;

if (!LOGS_QUEUE_URL) {
  console.error('LOGS_QUEUE_URL is required');
  process.exit(1);
}

const sqs = new SQSClient({ region: AWS_REGION });
const app = express();
app.use(express.json());

async function dlqConsumerLoop() {
  while (true) {
    try {
      const resp = await sqs.send(new ReceiveMessageCommand({
        QueueUrl: LOGS_QUEUE_URL,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 20,
        AttributeNames: ['All'],
        MessageAttributeNames: ['All']
      }));
      if (!resp.Messages || resp.Messages.length === 0) continue;

      const msg = resp.Messages[0];
      let body;
      try { body = JSON.parse(msg.Body || '{}'); } catch (e) { body = { raw: msg.Body }; }

      try {
        // save to Dynamo (saveLog should accept the same shape used by server/worker)
        await saveLog(body);
        console.log('logs-writer: saved log for job', body.jobId || '(none)');
      } catch (err) {
        console.error('logs-writer: saveLog failed', err, 'messageBody=', body);
        // don't delete message so it can be retried / go to DLQ
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      // delete message when persisted
      await sqs.send(new DeleteMessageCommand({ QueueUrl: LOGS_QUEUE_URL, ReceiptHandle: msg.ReceiptHandle }));
    } catch (err) {
      console.error('logs-writer loop error', err);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

// HTTP endpoint returns same shape the frontend expects
app.get('/logs', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      sort = "startedAt:desc",
      user,
      resolution
    } = req.query;

    // fetch all logs from Dynamo (getLogs should return array)
    let logs = await getLogs();

    if (user) logs = logs.filter(l => l.user && l.user.toLowerCase() === String(user).toLowerCase());
    if (resolution) logs = logs.filter(l => l.resolution === resolution);

    // sort
    const [sortField, sortOrder] = String(sort).split(':');
    logs.sort((a, b) => {
      if (a[sortField] < b[sortField]) return sortOrder === "asc" ? -1 : 1;
      if (a[sortField] > b[sortField]) return sortOrder === "asc" ? 1 : -1;
      return 0;
    });

    const total = logs.length;
    const startIndex = (page - 1) * limit;
    const paginatedLogs = logs.slice(startIndex, startIndex + parseInt(limit));

    const cores = os.cpus().length;
    const loadAvg = os.loadavg();
    const cpuUsagePercent = loadAvg.map(avg => Math.min((avg / cores) * 100, 100));
    const cpuInfo = os.cpus().map(cpu => ({ model: cpu.model, speed: cpu.speed, times: cpu.times }));

    res.json({
      success: true,
      cpu: { cores, cpuUsagePercent, cpuInfo },
      logs: paginatedLogs,
      pagination: { total, page: parseInt(page), limit: parseInt(limit), totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('logs endpoint error', err);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

async function start() {
  await loadSecrets().catch(()=>{}); // optional: if you need secrets in env
  // start sqs consumer loop (background)
  dlqConsumerLoop().catch(err => console.error('consumer loop crashed', err));
  // start http server for frontend
  app.listen(PORT, '0.0.0.0', () => console.log(`logs-writer listening on ${PORT}`));
}

start().catch(err => { console.error('logs-writer fatal', err); process.exit(1); });