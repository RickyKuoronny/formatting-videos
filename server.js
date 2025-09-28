require('dotenv').config();
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
const {
  signUpUser,
  confirmUser,
  initiateAuthFlow,
  respondToChallenge,
  verifyIdToken,
  cognitoClientConfig
} = require('./backend/cognito');

const app = express();

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
const COGNITO_DOMAIN = process.env.COGNITO_DOMAIN;
const COGNITO_REDIRECT_URI = process.env.COGNITO_REDIRECT_URI;

const OAUTH_STATE_TTL = 5 * 60 * 1000; // 5 minutes
const oauthStates = new Map();
let oidcClientPromise;

app.use(express.json()); // for parsing JSON bodies

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

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
    if (!COGNITO_DOMAIN || !cognitoClientConfig.clientId || !COGNITO_REDIRECT_URI) {
      throw new Error('Federated login is not configured correctly.');
    }

    const issuerUrl = `${COGNITO_DOMAIN.replace(/\/$/, '')}/.well-known/openid-configuration`;
    oidcClientPromise = Issuer.discover(issuerUrl).then((issuer) => new issuer.Client({
      client_id: cognitoClientConfig.clientId,
      client_secret: cognitoClientConfig.clientSecret,
      redirect_uris: [COGNITO_REDIRECT_URI],
      response_types: ['code']
    }));
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

app.get('/auth/google', (req, res) => {
  if (!COGNITO_DOMAIN || !cognitoClientConfig.clientId || !COGNITO_REDIRECT_URI) {
    return res.status(500).json({ error: 'Federated login is not configured correctly.' });
  }

  pruneOauthStates();
  const state = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, Date.now());

  const authorizeUrl = new URL(`${COGNITO_DOMAIN.replace(/\/$/, '')}/oauth2/authorize`);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', cognitoClientConfig.clientId);
  authorizeUrl.searchParams.set('redirect_uri', COGNITO_REDIRECT_URI);
  authorizeUrl.searchParams.set('scope', 'openid email profile');
  authorizeUrl.searchParams.set('identity_provider', 'Google');
  authorizeUrl.searchParams.set('state', state);

  res.json({ authUrl: authorizeUrl.toString(), state });
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

  if (!COGNITO_DOMAIN || !cognitoClientConfig.clientId || !COGNITO_REDIRECT_URI) {
    return res.status(500).json({ error: 'Federated login is not configured correctly.' });
  }

  try {
    const client = await getOidcClient();
    const tokenSet = await client.callback(COGNITO_REDIRECT_URI, { code, state }, { state });
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
  const scaleArg = buildScaleArg(resolution);
  const outName = path.basename(req.file.originalname, path.extname(req.file.originalname)) + '-converted.mp4';

  const startedAt = new Date().toISOString();
  console.log(`[${startedAt}] File uploaded: ${req.file.originalname} (${req.file.size} bytes)`);

  // FFmpeg args for stateless streaming
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
    '-movflags', 'frag_keyframe+empty_moov', // <— key for stateless MP4
    '-f', 'mp4',
    'pipe:1'
  ];

  console.log('FFmpeg args:', args.join(' '));

  const ff = spawn('ffmpeg', args);
  let ffErr = '';
  ff.stderr.on('data', d => ffErr += d.toString());

  // Handle stdin errors (ignore EPIPE)
  ff.stdin.on('error', err => { if (err.code !== 'EPIPE') console.error('FFmpeg stdin error:', err); });

  // Pipe uploaded buffer to FFmpeg stdin
  const bufferStream = Readable.from(req.file.buffer);
  pipeline(bufferStream, ff.stdin, err => {
    if (err && err.code !== 'EPIPE') console.error('Pipeline error (stdin):', err);
  });

  // Pipe FFmpeg output to S3 via PassThrough
  const passThrough = new PassThrough();
  const uploadPromise = uploadFile(outName, passThrough, 'video/mp4')
    .catch(err => console.error('S3 upload failed:', err));
  ff.stdout.pipe(passThrough);

  // Handle FFmpeg close
  ff.on('close', async code => {
    const completedAt = new Date().toISOString();
    const logEntry = {
      input: req.file.originalname,
      output: outName,
      resolution,
      startedAt,
      completedAt,
      user: req.user.username
    };

    await saveLog(logEntry);
    
    if (code !== 0) {
      console.error(`[${completedAt}] FFmpeg failed for ${outName}:`, ffErr);
      return res.status(500).json({ error: 'FFmpeg failed', details: ffErr });
    }

    // Wait for S3 upload to finish
    await uploadPromise;

    const presignedUrl = await getPresignedUrl(outName);

    // --- Generate metadata using ffprobe directly on S3 ---
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
        return res.json({ ok: true, s3Url: presignedUrl, outputFile: outName });
      }

      const metaRaw = JSON.parse(stdout);
      const metadata = {
        filename: outName,
        codec: metaRaw.streams[0]?.codec_name || null,
        bitrate: metaRaw.format?.bit_rate || null
      };

      saveMetadata(outName, metadata).catch(console.error);

      res.json({
        ok: true,
        s3Url: presignedUrl,
        outputFile: outName,
        metadata
      });
    });
  });

  ff.on('error', err => {
    console.error('FFmpeg process error:', err);
    res.status(500).json({ error: 'FFmpeg process failed', details: err.message });
  });
});

// Extension API cloudinary
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


// health
app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT, '0.0.0.0', () => console.log(`Server listening on ${PORT}`));
