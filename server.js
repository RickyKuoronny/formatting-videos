require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const { exec } = require('child_process'); 
const cloudinary = require('cloudinary').v2;

// AWS Cognito
const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  AuthFlowType
} = require('@aws-sdk/client-cognito-identity-provider');
const { CognitoJwtVerifier } = require('aws-jwt-verify');

const app = express();

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
const REGION = process.env.REGION || 'ap-southeast-2';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;

const missingEnv = ['COGNITO_USER_POOL_ID', 'COGNITO_CLIENT_ID']
  .filter((key) => !process.env[key]);

if (missingEnv.length) {
  console.error(`Missing required Cognito configuration: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });

const USER_PASSWORD_AUTH_FLOW =
  AuthFlowType && typeof AuthFlowType === 'object' && AuthFlowType.USER_PASSWORD_AUTH
    ? AuthFlowType.USER_PASSWORD_AUTH
    : 'USER_PASSWORD_AUTH';

const accessTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: COGNITO_USER_POOL_ID,
  tokenUse: 'access',
  clientId: COGNITO_CLIENT_ID,
});

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: COGNITO_USER_POOL_ID,
  tokenUse: 'id',
  clientId: COGNITO_CLIENT_ID,
});

function buildSecretHash(username) {
  if (!COGNITO_CLIENT_SECRET) return undefined;
  return crypto
    .createHmac('sha256', COGNITO_CLIENT_SECRET)
    .update(`${username}${COGNITO_CLIENT_ID}`)
    .digest('base64');
}

function mapCognitoError(error) {
  const statusMap = {
    UsernameExistsException: 409,
    InvalidPasswordException: 400,
    CodeMismatchException: 400,
    ExpiredCodeException: 400,
    UserNotFoundException: 404,
    NotAuthorizedException: 401,
    UserNotConfirmedException: 403,
    TooManyRequestsException: 429,
  };

  return {
    status: statusMap[error.name] || 500,
    message: error.message || 'An unexpected error occurred with Cognito.',
  };
}

app.use(express.json()); // for parsing JSON bodies

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});


const METADATA_FILE = 'metadata.json';
const LOG_FILE = path.join(__dirname, 'conversion_logs.json');
const UPLOAD_DIR = path.resolve(__dirname, 'uploads');
const OUTPUT_DIR = path.resolve(__dirname, 'outputs');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });

async function verifyJwt(token) {
  try {
    const payload = await accessTokenVerifier.verify(token);
    return { payload, tokenType: 'access' };
  } catch (accessErr) {
    const payload = await idTokenVerifier.verify(token);
    return { payload, tokenType: 'id' };
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : undefined;

  if (!token) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  verifyJwt(token)
    .then(({ payload, tokenType }) => {
      const username =
        payload['cognito:username'] ||
        payload.username ||
        payload.preferred_username ||
        payload.email ||
        'unknown';

      const rawGroups = payload['cognito:groups'];
      const groups = Array.isArray(rawGroups)
        ? rawGroups
        : rawGroups
        ? [rawGroups]
        : [];
      const role = payload['custom:role'] || (groups.includes('admin') ? 'admin' : 'user');

      req.user = {
        username,
        email: payload.email,
        tokenType,
        tokenPayload: payload,
        groups,
        role,
        isAdmin: groups.includes('admin') || role === 'admin',
      };
      next();
    })
    .catch((err) => {
      console.error('Token verification failed', err);
      res.status(401).json({ error: 'Invalid or expired token' });
    });
}

// Middleware to check admin role
function requireAdmin(req, res, next) {
  if (req.user?.isAdmin) {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden: Admins only' });
}


// --- Logs ---
// Utility to append log
function appendLog(entry) {
  const logEntry = JSON.stringify(entry) + '\n'; // one JSON object per line
  fs.appendFile(LOG_FILE, logEntry, (err) => {
    if (err) console.error('Failed to write log:', err);
  });
}


// GET /logs - only admin
app.get('/logs', authenticateToken, requireAdmin, (req, res) => {
  try {
    // Extract query parameters with defaults
    const {
      page = 1,
      limit = 10,
      sort = "startedAt:desc",
      user,
      resolution
    } = req.query;

    // Read logs from file
    fs.readFile(LOG_FILE, 'utf8', (err, data) => {
      if (err) return res.status(500).json({ error: 'Failed to read logs' });

      // Parse logs from JSON lines
      let logs = data.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));

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

      // Get total logs count **after filtering**
      const total = logs.length;

      // Apply pagination
      const startIndex = (page - 1) * limit;
      const paginatedLogs = logs.slice(startIndex, startIndex + parseInt(limit));

      // CPU stats remain unchanged
      const cores = os.cpus().length;
      const loadAvg = os.loadavg(); // [1min, 5min, 15min]
      const cpuUsagePercent = loadAvg.map(avg => Math.min((avg / cores) * 100, 100));
      const cpuInfo = os.cpus().map(cpu => ({
        model: cpu.model,
        speed: cpu.speed,
        times: cpu.times
      }));

      // Send structured JSON response
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
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const id = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
    const ext = path.extname(file.originalname) || '.mp4';
    cb(null, `${id}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1GB limit (adjust)
  fileFilter: (req, file, cb) => {
    // basic mime check (allow common video types)
    if (/^video\/(mp4|x-matroska|quicktime|x-msvideo|webm|x-ms-wmv)/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only video files allowed'), false);
  }
});


// --- Signing up user route ---
app.post('/auth/signup', async (req, res) => {
  const { username, password, email } = req.body || {};

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'username, password and email are required' });
  }

  const commandInput = {
    ClientId: COGNITO_CLIENT_ID,
    Username: username,
    Password: password,
    UserAttributes: [{ Name: 'email', Value: email }],
  };

  const secretHash = buildSecretHash(username);
  if (secretHash) {
    commandInput.SecretHash = secretHash;
  }

  try {
    const result = await cognitoClient.send(new SignUpCommand(commandInput));
    res.status(201).json({
      message: 'Sign-up successful. Please check your email for the confirmation code.',
      userSub: result.UserSub,
      userConfirmed: result.UserConfirmed,
    });
  } catch (error) {
    console.error('Sign-up failed:', error);
    const { status, message } = mapCognitoError(error);
    res.status(status).json({ error: message, code: error.name });
  }
});

// --- Confirming user route ---
app.post('/auth/confirm', async (req, res) => {
  const { username, confirmationCode } = req.body || {};

  if (!username || !confirmationCode) {
    return res.status(400).json({ error: 'username and confirmationCode are required' });
  }

  const commandInput = {
    ClientId: COGNITO_CLIENT_ID,
    Username: username,
    ConfirmationCode: confirmationCode,
  };

  const secretHash = buildSecretHash(username);
  if (secretHash) {
    commandInput.SecretHash = secretHash;
  }

  try {
    await cognitoClient.send(new ConfirmSignUpCommand(commandInput));
    res.json({ message: 'User confirmed successfully.' });
  } catch (error) {
    console.error('Confirmation failed:', error);
    const { status, message } = mapCognitoError(error);
    res.status(status).json({ error: message, code: error.name });
  }
});

// --- Authenticating user route ---
async function handleAuthLogin(req, res) {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const authParameters = {
    USERNAME: username,
    PASSWORD: password,
  };

  const secretHash = buildSecretHash(username);
  if (secretHash) {
    authParameters.SECRET_HASH = secretHash;
  }

  const commandInput = {
    AuthFlow: USER_PASSWORD_AUTH_FLOW,
    AuthParameters: authParameters,
    ClientId: COGNITO_CLIENT_ID,
  };

  try {
    const result = await cognitoClient.send(new InitiateAuthCommand(commandInput));
    const authResult = result.AuthenticationResult || {};

    res.json({
      message: 'Authentication successful.',
      tokens: {
        accessToken: authResult.AccessToken,
        idToken: authResult.IdToken,
        refreshToken: authResult.RefreshToken,
        tokenType: authResult.TokenType,
        expiresIn: authResult.ExpiresIn,
      },
      challengeName: result.ChallengeName,
    });
  } catch (error) {
    console.error('Authentication failed:', error);
    const { status, message } = mapCognitoError(error);
    res.status(status).json({ error: message, code: error.name });
  }
}

app.post('/auth/login', handleAuthLogin);
app.post('/login', handleAuthLogin);


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

app.post('/convert', authenticateToken, upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const resolution = (req.body.resolution || '').trim();
  const scaleArg = buildScaleArg(resolution);

  const inputPath = req.file.path;
  const outName = path.basename(req.file.filename, path.extname(req.file.filename)) + '-converted.mp4';
  const outputPath = path.join(OUTPUT_DIR, outName);

  const startedAt = new Date().toISOString();
  console.log(`[${startedAt}] File uploaded: ${req.file.originalname} (${req.file.size} bytes)`);

  const args = ['-i', inputPath, '-y', '-hide_banner', '-loglevel', 'error'];
  if (scaleArg) args.push('-vf', scaleArg);
  args.push('-c:v', 'libx264', '-preset', 'veryfast', '-crf', '23', '-c:a', 'aac', '-b:a', '128k', outputPath);

  console.log(`[${new Date().toISOString()}] Starting FFmpeg conversion for ${req.file.originalname} -> ${outName}`);
  const ff = spawn('ffmpeg', args);

  let ffErr = '';

  ff.stderr.on('data', (d) => { ffErr += d.toString(); });

  ff.on('close', (code) => {
    try { fs.unlinkSync(inputPath); } catch {}

    const completedAt = new Date().toISOString();
    const logEntry = {
      input: req.file.filename,
      output: outName,
      resolution,
      startedAt,
      completedAt,
      user: (req.user && req.user.username) || 'unknown'
    };
    appendLog(logEntry); // write to log file

    if (code === 0 && fs.existsSync(outputPath)) {
      console.log(`[${completedAt}] FFmpeg finished conversion: ${outName}`);

      // --- Generate metadata using ffprobe ---
      const ffprobeCmd = `ffprobe -v quiet -print_format json -show_format -show_streams "${outputPath}"`;
      exec(ffprobeCmd, (err, stdout) => {
        if (err) {
          console.error('Failed to generate metadata:', err);
          return res.json({ ok: true, download: `/outputs/${outName}` });
        }

        const metaRaw = JSON.parse(stdout);
        const metadata = {
          filename: outName,
          codec: metaRaw.streams[0].codec_name,
          bitrate: metaRaw.format.bit_rate
        };

        // --- Append to metadata.json ---
        let allMeta = [];
        if (fs.existsSync(METADATA_FILE)) {
          allMeta = JSON.parse(fs.readFileSync(METADATA_FILE, 'utf8'));
        }
        allMeta.push(metadata);
        fs.writeFileSync(METADATA_FILE, JSON.stringify(allMeta, null, 2));

        // --- Respond with download link + metadata ---
        res.json({
          ok: true,
          download: `/outputs/${outName}`,
          outputFile: outName,
          metadata
        });
      });

    } else {
      console.error(`[${completedAt}] FFmpeg failed for ${outName}:`, ffErr);
      res.status(500).json({ error: 'FFmpeg failed', details: ffErr });
    }
  });
});

// Extension API cloudinary
app.post('/upload-external', authenticateToken, async (req, res) => {
  const filename = req.body.filename;
  const filePath = path.join(OUTPUT_DIR, filename);

  if (!fs.existsSync(filePath)) {
    console.error(`File not found at: ${filePath}`);
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    const result = await cloudinary.uploader.upload(filePath, { resource_type: 'video' });

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
