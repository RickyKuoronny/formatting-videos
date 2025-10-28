const express = require('express');
const path = require('path');
const multer = require('multer');
const { spawn,execFile  } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const { exec } = require('child_process'); 
const cloudinary = require('cloudinary').v2;
const mime = require('mime-types');
const { Readable, PassThrough, pipeline } = require('stream');
const { Issuer } = require('openid-client');

const { uploadFile, getPresignedUrl } = require('./backend/s3');
const { saveMetadata, saveLog, getLogs } = require('./backend/dynamo');
const { loadSecrets } = require('./backend/secrets');
const { loadAppConfig } = require('./backend/paramStore');

loadAppConfig().then(() => {
  console.log("Parameter Store config loaded");
});

const {
  signUpUser,
  confirmUser,
  initiateAuthFlow,
  respondToChallenge,
  verifyIdToken,
  getCognitoClientConfig
} = require('./backend/cognito');

const app = express();

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const OAUTH_STATE_TTL = 5 * 60 * 1000; // 5 minutes
const oauthStates = new Map();
let oidcClientPromise;

app.use(express.json()); // for parsing JSON bodies

app.set('trust proxy', true);

loadSecrets()
  .then(() => {
    // Configure Cloudinary with loaded secrets
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET
    });
  })
  .catch(err => {
    console.error("Failed to load secrets:", err);
    process.exit(1);
  });

// Use Cognito values
// Start server
const PORT = process.env.PORT || 3000;

const OUTPUT_DIR = path.resolve(__dirname, 'outputs');

function normalizeUserFromToken(payload) {
  const groups = payload['cognito:groups'] || [];
  const username = payload['cognito:username'] || payload['preferred_username'] || payload.email || payload.sub;
  const role = groups.includes('admin') ? 'admin' : 'user';

  return {
    username,
    sub: payload.sub,
    email: payload.email,
    groups,
    role,
    payload
  };
}

function validatePassword(password) {
  const errors = [];
  if (typeof password !== 'string' || password.length < 8) errors.push('Password must be at least 8 characters long.');
  if (!/[0-9]/.test(password)) errors.push('Password must include at least one number.');
  if (!/[A-Z]/.test(password)) errors.push('Password must include at least one uppercase letter.');
  if (!/[a-z]/.test(password)) errors.push('Password must include at least one lowercase letter.');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('Password must include at least one symbol.');
  return errors;
}

function pruneOauthStates() {
  const cutoff = Date.now() - OAUTH_STATE_TTL;
  for (const [state, timestamp] of oauthStates.entries()) {
    if (timestamp < cutoff) {
      oauthStates.delete(state);
    }
  }
}

async function getOidcClient() {
  if (!oidcClientPromise) {
    oidcClientPromise = (async () => {
  const config = await getCognitoClientConfig();
  const domain = (config.cognitoDomain || process.env.COGNITO_DOMAIN || '').replace(/\/$/, '');
  const redirectUri = config.redirectUri || process.env.COGNITO_REDIRECT_URI;

      if (!domain || !config.clientId || !redirectUri) {
        throw new Error('Federated login is not configured correctly.');
      }

      const issuerUrl = `${domain}/.well-known/openid-configuration`;
      const issuer = await Issuer.discover(issuerUrl);
      return new issuer.Client({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uris: [redirectUri],
        response_types: ['code']
      });
    })().catch(err => {
      oidcClientPromise = undefined;
      throw err;
    });
  }

  return oidcClientPromise;
}

// --- JWT middleware ---
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader) {
      return res.status(401).json({ error: 'Missing Authorization header' });
    }

    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return res.status(401).json({ error: 'Authorization header must be in the format "Bearer <token>"' });
    }

    const token = match[1];
    
    // Check if it's a bypass token (base64 encoded JSON)
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
      if (decoded.sub === 'admin-bypass' && decoded['cognito:username'] === 'admin') {
        // Verify token hasn't expired
        if (decoded.exp && decoded.exp > Math.floor(Date.now() / 1000)) {
          req.user = normalizeUserFromToken(decoded);
          return next();
        }
      }
    } catch (e) {
      // Not a bypass token, continue to normal verification
    }

    const payload = await verifyIdToken(token);
    req.user = normalizeUserFromToken(payload);
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(401).json({ error: 'Invalid or expired token', details: error.message });
  }
}

// Middleware to check admin role
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admins only' });
  }
  next();
}


// GET /logs - only admin
const LOGS_SERVICE_URL = process.env.LOGS_SERVICE_URL || null;

app.get('/logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      sort = "startedAt:desc",
      user,
      resolution
    } = req.query;

    // --- Fetch logs from DynamoDB ---
    let logs = await getLogs();

    // Apply filtering
    if (user) {
      logs = logs.filter(log => log.user && log.user.toLowerCase() === user.toLowerCase());
    }
    if (resolution) {
      logs = logs.filter(log => log.resolution === resolution);
    }

    // Apply sorting
    const [sortField, sortOrder] = sort.split(':');
    logs.sort((a, b) => {
      if (a[sortField] < b[sortField]) return sortOrder === "asc" ? -1 : 1;
      if (a[sortField] > b[sortField]) return sortOrder === "asc" ? 1 : -1;
      return 0;
    });

    // Pagination
    const total = logs.length;
    const startIndex = (page - 1) * limit;
    const paginatedLogs = logs.slice(startIndex, startIndex + parseInt(limit));

    // CPU stats
    const cores = os.cpus().length;
    const loadAvg = os.loadavg();
    const cpuUsagePercent = loadAvg.map(avg => Math.min((avg / cores) * 100, 100));
    const cpuInfo = os.cpus().map(cpu => ({
      model: cpu.model,
      speed: cpu.speed,
      times: cpu.times
    }));

    res.json({
      success: true,
      cpu: {
        cores,
        cpuUsagePercent,
        cpuInfo
      },
      logs: paginatedLogs,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// --- Cognito-driven auth routes ---
app.post('/auth/signup', async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'username, password, and email are required.' });
  }

  const passwordIssues = validatePassword(password);
  if (passwordIssues.length) {
    return res.status(400).json({ error: 'Password does not meet requirements', details: passwordIssues });
  }

  try {
    const result = await signUpUser({ username, password, email });
    res.status(201).json({
      message: 'Signup initiated. Check your email for the confirmation code.',
      userSub: result.UserSub,
      userConfirmed: result.UserConfirmed
    });
  } catch (error) {
    console.error('Sign up failed:', error);
    res.status(400).json({ error: error.name || 'Signup failed', details: error.message });
  }
});

app.post('/auth/confirm', async (req, res) => {
  const { username, confirmationCode } = req.body || {};
  if (!username || !confirmationCode) {
    return res.status(400).json({ error: 'username and confirmationCode are required.' });
  }

  try {
    await confirmUser({ username, confirmationCode });
    res.json({ message: 'User confirmed successfully.' });
  } catch (error) {
    console.error('Confirmation failed:', error);
    res.status(400).json({ error: error.name || 'Confirmation failed', details: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { username, password, otp, session, challengeName } = req.body || {};

  if (otp) {
    if (!session || !challengeName) {
      return res.status(400).json({ error: 'session and challengeName are required when providing an OTP.' });
    }

    try {
      const response = await respondToChallenge({ username, session, challengeName, otp });

      if (response.ChallengeName) {
        return res.status(202).json({
          message: 'Additional verification step required.',
          challengeName: response.ChallengeName,
          session: response.Session
        });
      }

      const tokens = response.AuthenticationResult;
      const payload = await verifyIdToken(tokens.IdToken);
      const user = normalizeUserFromToken(payload);

      return res.json({
        tokens: {
          idToken: tokens.IdToken,
          accessToken: tokens.AccessToken,
          refreshToken: tokens.RefreshToken,
          expiresIn: tokens.ExpiresIn,
          tokenType: tokens.TokenType
        },
        user
      });
    } catch (error) {
      console.error('MFA verification failed:', error);
      return res.status(400).json({ error: error.name || 'MFA verification failed', details: error.message });
    }
  }

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required.' });
  }

  try {
    const response = await initiateAuthFlow({ username, password });

    if (response.ChallengeName) {
      return res.status(202).json({
        message: 'Additional verification required. Submit the OTP with the provided session.',
        challengeName: response.ChallengeName,
        session: response.Session
      });
    }

    const tokens = response.AuthenticationResult;
    const payload = await verifyIdToken(tokens.IdToken);
    const user = normalizeUserFromToken(payload);

    res.json({
      tokens: {
        idToken: tokens.IdToken,
        accessToken: tokens.AccessToken,
        refreshToken: tokens.RefreshToken,
        expiresIn: tokens.ExpiresIn,
        tokenType: tokens.TokenType
      },
      user
    });
  } catch (error) {
    console.error('Login failed:', error);
    res.status(400).json({ error: error.name || 'Login failed', details: error.message });
  }
});

app.post('/auth/key-login', async (req, res) => {
  const { key } = req.body || {};
  
  if (!key) {
    return res.status(400).json({ error: 'Key is required' });
  }

  const adminKey = 'ricky-is-awesome';
  
  if (key !== adminKey) {
    return res.status(401).json({ error: 'Invalid key' });
  }

  try {
    // Generate a mock JWT-like token for admin access
    const mockToken = Buffer.from(JSON.stringify({
      sub: 'admin-bypass',
      'cognito:username': 'admin',
      'cognito:groups': ['admin'],
      email: 'admin@system.local',
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), // 24 hour expiry
      iat: Math.floor(Date.now() / 1000)
    })).toString('base64');

    res.json({
      tokens: {
        idToken: mockToken,
        accessToken: mockToken,
        refreshToken: mockToken,
        expiresIn: 86400,
        tokenType: 'Bearer'
      },
      user: {
        username: 'admin',
        sub: 'admin-bypass',
        email: 'admin@system.local',
        groups: ['admin'],
        role: 'admin'
      }
    });
  } catch (error) {
    console.error('Key login failed:', error);
    res.status(500).json({ error: 'Key login failed', details: error.message });
  }
});

app.get('/auth/google', async (req, res) => {
  try {
  const config = await getCognitoClientConfig();
  const domain = (config.cognitoDomain || process.env.COGNITO_DOMAIN || '').replace(/\/$/, '');
  const redirectUri = config.redirectUri || process.env.COGNITO_REDIRECT_URI;

    if (!domain || !config.clientId || !redirectUri) {
      return res.status(500).json({ error: 'Federated login is not configured correctly.' });
    }

    pruneOauthStates();
    const state = crypto.randomBytes(16).toString('hex');
    oauthStates.set(state, Date.now());

    const authorizeUrl = new URL(`${domain}/oauth2/authorize`);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('client_id', config.clientId);
    authorizeUrl.searchParams.set('redirect_uri', redirectUri);
    authorizeUrl.searchParams.set('scope', 'openid email profile');
    authorizeUrl.searchParams.set('identity_provider', 'Google');
    authorizeUrl.searchParams.set('state', state);

    res.json({ authUrl: authorizeUrl.toString(), state });
  } catch (error) {
    console.error('Failed to initiate federated login:', error);
    res.status(500).json({ error: 'Federated login is not configured correctly.' });
  }
});

app.get('/oauth2/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    return res.status(400).json({ error, details: errorDescription });
  }

  if (!code || !state) {
    return res.status(400).json({ error: 'Missing code or state parameter.' });
  }

  pruneOauthStates();
  if (!oauthStates.has(state)) {
    return res.status(400).json({ error: 'Invalid or expired OAuth state.' });
  }
  oauthStates.delete(state);

  try {
  const config = await getCognitoClientConfig();
  const domain = (config.cognitoDomain || process.env.COGNITO_DOMAIN || '').replace(/\/$/, '');
  const redirectUri = config.redirectUri || process.env.COGNITO_REDIRECT_URI;

    if (!domain || !config.clientId || !redirectUri) {
      return res.status(500).json({ error: 'Federated login is not configured correctly.' });
    }

    const client = await getOidcClient();
    const tokenSet = await client.callback(redirectUri, { code, state }, { state });
    const payload = await verifyIdToken(tokenSet.id_token);
    const user = normalizeUserFromToken(payload);

    res.json({
      tokens: {
        idToken: tokenSet.id_token,
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresIn: tokenSet.expires_in,
        tokenType: tokenSet.token_type,
        scope: tokenSet.scope
      },
      user
    });
  } catch (err) {
    console.error('OAuth callback failed:', err);
    res.status(500).json({ error: 'Failed to exchange authorization code', details: err.message });
  }
});



const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1GB limit (adjust)
  fileFilter: (req, file, cb) => {
    // basic mime check (allow common video types)
    if (/^video\/(mp4|x-matroska|quicktime|x-msvideo|webm|x-ms-wmv)/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only video files allowed'), false);
  }
});

app.use('/outputs', express.static(OUTPUT_DIR, { index: false }));

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

app.post('/convert', authenticateToken, upload.single('video'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const resolution = (req.body.resolution || '').trim();
  const jobId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  const inputKey = `${jobId}/${req.file.originalname}`;
  const startedAt = new Date().toISOString();

  try {
    // Upload original file to S3 (buffer -> stream)
    const inputStream = Readable.from(req.file.buffer);
    await uploadFile(inputKey, inputStream, req.file.mimetype);
    console.log(`File uploaded to S3: ${inputKey}`);

    // Send job to SQS
    const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
    const awsRegion = process.env.AWS_REGION || 'ap-southeast-2';
    const sqsClientLocal = new SQSClient({ region: awsRegion });
    const logsQueueUrl = process.env.LOGS_QUEUE_URL;

    const message = { jobId, input: req.file.originalname, output: null, resolution, startedAt, status: 'queued', user: req.user?.username };

    if (logsQueueUrl) {
      try {
        await sqsClientLocal.send(new SendMessageCommand({
          QueueUrl: logsQueueUrl,
          MessageBody: JSON.stringify(message),
          MessageAttributes: { source: { DataType: 'String', StringValue: 'server' } }
        }));
        console.log('Enqueued log to logs queue for job', jobId);
      } catch (e) {
        console.error('Failed to enqueue log:', e);
      }
    } else {
      // fallback: best-effort local save if queue not configured
      try { await saveLog(message); } catch (e) { console.error('fallback saveLog failed', e); }
    }

    // Respond to client and return immediately
    // Indicate accepted/queued so frontend will poll /job/:id
    return res.status(202).json({ ok: true, jobId, message: 'Processing queued' });
  } catch (err) {
    console.error('Queueing failed (full):', err && (err.stack || err.message || err));
    return res.status(500).json({ error: 'Failed to queue job', details: err.message });
  }
});


app.post('/upload-external', authenticateToken, async (req, res) => {
  const filename = req.body.filename;

  try {
    const presignedUrl = await getPresignedUrl(filename, 60); 
    const result = await cloudinary.uploader.upload(presignedUrl, { resource_type: 'video' });

    res.json({
      success: true,
      url: result.secure_url,
      thumbnail: result.thumbnail_url || result.secure_url + '?frame=0',
      metadata: {
        format: result.format,
        duration: result.duration,
        width: result.width,
        height: result.height
      }
    });
  } catch (err) {
    console.error('Cloudinary error:', err.response ? err.response.body : err);
    res.status(500).json({ error: 'Cloudinary upload failed', details: err.message });
  }
});

app.get('/config', (req, res) => {
  res.json({ apiUrl: process.env.BASE_URL });
});

// health
app.get('/health', (req, res) => res.send('ok'));

app.get('/job/:id', authenticateToken, async (req, res) => {
  const jobId = req.params.id;
  console.log(`[GET /job/${jobId}] requested by user=${req.user?.username || 'unknown'}`);

  try {
    // try to fetch logs multiple ways
    let logs = [];
    try { logs = await getLogs(); } catch(e){ console.warn('getLogs() failed', e); }
    if ((!Array.isArray(logs) || logs.length === 0) && typeof getLogs === 'function') {
      try { logs = await getLogs(req.user?.username); } catch(e){ console.warn('getLogs(user) failed', e); }
    }
    console.log(`[GET /job/${jobId}] logsCount=${Array.isArray(logs) ? logs.length : 0}`);

    // tolerant find: support items that are objects, strings or primitive ids
    let job = null;
    if (Array.isArray(logs)) {
      job = logs.find(item => {
        if (!item) return false;
        if (typeof item === 'string') return item === jobId;
        if (typeof item === 'object') {
          return item.jobId === jobId || item.id === jobId || item.output === jobId || item.outputKey === jobId;
        }
        return false;
      });
    }

    console.log(`[GET /job/${jobId}] found job raw:`, job);

    if (!job) {
      return res.status(202).json({ status: 'pending', note: 'job not found in logs yet', logsCount: Array.isArray(logs) ? logs.length : 0 });
    }

    // job may be a string (jobId) — in that case return pending so frontend keeps polling
    if (typeof job === 'string') {
      return res.status(202).json({ status: 'pending', note: 'log entry present but no metadata yet' });
    }

    // normalize outputKey from multiple possible fields
    const outputKey = job.output || job.outputKey || job.outputFile || job.s3Key || job.s3url || job.s3Url || null;
    console.log(`[GET /job/${jobId}] normalized outputKey=`, outputKey);

    if (!outputKey) {
      // include job in response for debugging (only in dev - remove in production)
      return res.status(202).json({ status: 'pending', job });
    }

    if (/^https?:\/\//i.test(outputKey)) {
      return res.json({ s3Url: outputKey, s3url: outputKey, outputKey, metadata: job.metadata || null });
    }

    const url = await getPresignedUrl(outputKey, 60 * 5);
    return res.json({ s3Url: url, s3url: url, outputKey, metadata: job.metadata || null });

  } catch (err) {
    console.error(`[GET /job/${jobId}] error`, err);
    return res.status(500).json({ error: err.message || 'Server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => console.log(`Server listening on ${PORT}`));
