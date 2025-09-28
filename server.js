require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const multer = require('multer');
const { spawn, execFile } = require('child_process');
const crypto = require('crypto');
const os = require('os');
const cloudinary = require('cloudinary').v2;
const mime = require('mime-types');
const { Readable, PassThrough, pipeline } = require('stream');
const { Issuer, generators } = require('openid-client');
const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  AdminListGroupsForUserCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { CognitoJwtVerifier } = require('aws-jwt-verify');

const { uploadFile, getPresignedUrl } = require('./backend/s3');
const { saveMetadata, saveLog, getLogs } = require('./backend/dynamo');

const app = express();

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;
const OUTPUT_DIR = path.resolve(__dirname, 'outputs');

const cognitoRegion = process.env.REGION;
const cognitoClientId = process.env.COGNITO_CLIENT_ID;
const cognitoClientSecret = process.env.COGNITO_CLIENT_SECRET;
const cognitoUserPoolId = process.env.COGNITO_USER_POOL_ID;

if (!cognitoClientId || !cognitoUserPoolId) {
  console.warn('Cognito configuration incomplete: ensure COGNITO_CLIENT_ID and COGNITO_USER_POOL_ID are set.');
}

const cognitoClient = new CognitoIdentityProviderClient({ region: cognitoRegion });

const sessionSecret = JWT_SECRET;

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: cognitoUserPoolId,
  tokenUse: 'id',
  clientId: cognitoClientId
});

const accessTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: cognitoUserPoolId,
  tokenUse: 'access',
  clientId: cognitoClientId
});

function generateSecretHash(username) {
  if (!cognitoClientSecret || !cognitoClientId) return undefined;
  return crypto
    .createHmac('sha256', cognitoClientSecret)
    .update(`${username}${cognitoClientId}`)
    .digest('base64');
}

async function fetchGroupsForUser(username) {
  if (!username || !cognitoUserPoolId) return [];
  try {
    const command = new AdminListGroupsForUserCommand({
      UserPoolId: cognitoUserPoolId,
      Username: username
    });
    const response = await cognitoClient.send(command);
    return (response.Groups || []).map(group => group.GroupName);
  } catch (err) {
    console.warn('Unable to fetch Cognito groups for user', username, err?.message || err);
    return [];
  }
}

app.use(express.json());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// -- Cognito quick setup from AWS COGNITO example code ---
let client;
// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover(process.env.COGNITO_ISSUER);
    client = new issuer.Client({
        client_id: process.env.COGNITO_CLIENT_ID,
        client_secret: process.env.COGNITO_CLIENT_SECRET,
        redirect_uris: [process.env.COGNITO_REDIRECT_URI],
        response_types: ['code']
    });
};
initializeClient().catch(console.error);

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

app.use(express.urlencoded({ extended: false }));

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  if (!client) {
    return res.status(503).json({ error: 'Identity provider not initialised yet. Please try again in a moment.' });
  }

  const nonce = generators.nonce();
  const state = generators.state();

  req.session.nonce = nonce;
  req.session.state = state;

  const baseAuthUrl = client.authorizationUrl({
    scope: 'openid email phone profile',
    state,
    nonce
  });

  const provider = req.query.provider;
  const redirectUrl = provider
    ? `${baseAuthUrl}&identity_provider=${encodeURIComponent(provider)}`
    : baseAuthUrl;

  res.redirect(redirectUrl);
});

app.get('/login/google', (req, res) => {
  res.redirect('/login?provider=Google');
});

function getPathFromURL(urlString) {
  try {
    const url = new URL(urlString);
    return url.pathname;
  } catch (error) {
    console.error('Invalid URL:', error);
    return '/oauth2/callback';
  }
}

const redirectPath = getPathFromURL(process.env.COGNITO_REDIRECT_URI);

app.get(redirectPath, async (req, res) => {
  if (!client) {
    return res.status(503).json({ error: 'Identity provider not initialised yet.' });
  }

  try {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
      process.env.COGNITO_REDIRECT_URI,
      params,
      {
        nonce: req.session.nonce,
        state: req.session.state
      }
    );

    const idClaims = tokenSet.id_token
      ? await idTokenVerifier.verify(tokenSet.id_token)
      : null;

    let groups = idClaims?.['cognito:groups'] || [];
    if ((!groups || groups.length === 0) && idClaims?.['cognito:username']) {
      groups = await fetchGroupsForUser(idClaims['cognito:username']);
    }

    const role = groups && groups.includes('Admin')
      ? 'admin'
      : (groups && groups.length > 0 ? groups[0] : 'user');

    req.session.tokenSet = {
      idToken: tokenSet.id_token,
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      expiresAt: tokenSet.expires_at
    };
    req.session.user = {
      username: idClaims?.['cognito:username'] || idClaims?.email || null,
      email: idClaims?.email || null,
      sub: idClaims?.sub || null,
      groups,
      role
    };

    res.redirect('/');
  } catch (err) {
    console.error('Callback error:', err);
    res.redirect('/?auth=error');
  }
});

app.get('/logout', (req, res) => {
  const logoutUrl = `${process.env.COGNITO_DOMAIN}/logout?client_id=${process.env.COGNITO_CLIENT_ID}&logout_uri=${process.env.COGNITO_REDIRECT_URI}`;
  req.session.destroy(() => {
    res.redirect(logoutUrl);
  });
});
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header with Bearer token is required' });
  }

  const token = authHeader.substring('Bearer '.length).trim();

  try {
    let payload;
    try {
      payload = await idTokenVerifier.verify(token);
    } catch (idErr) {
      try {
        payload = await accessTokenVerifier.verify(token);
      } catch (accessErr) {
        console.error('JWT verification failed (ID+Access):', idErr?.message || idErr, accessErr?.message || accessErr);
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    }

    const username = payload['cognito:username'] || payload.username || payload.email || payload.sub;
    let groups = payload['cognito:groups'] || [];

    if ((!groups || groups.length === 0) && username) {
      groups = await fetchGroupsForUser(username);
    }

    const role = groups.includes('Admin') ? 'admin' : (groups[0] || 'user');

    req.user = {
      username,
      email: payload.email || null,
      sub: payload.sub || null,
      groups,
      role,
      tokenUse: payload.token_use || (payload.scope ? 'access' : 'id')
    };

    next();
  } catch (err) {
    console.error('JWT verification error:', err?.message || err);
    res.status(401).json({ error: 'Unable to verify token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admins only' });
  }
  next();
}

app.get('/auth/session', (req, res) => {
  if (!req.session?.tokenSet || !req.session?.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  res.json({
    idToken: req.session.tokenSet.idToken,
    accessToken: req.session.tokenSet.accessToken,
    refreshToken: req.session.tokenSet.refreshToken,
    expiresAt: req.session.tokenSet.expiresAt,
    user: req.session.user
  });
});

app.post('/auth/signup', async (req, res) => {
  const { username, password, email, attributes = [], clientMetadata = {} } = req.body || {};

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'username, password and email are required' });
  }

  const userAttributes = [
    { Name: 'email', Value: email },
    ...attributes
      .filter(attr => attr && attr.Name && attr.Value && attr.Name !== 'email')
  ];

  const params = {
    ClientId: cognitoClientId,
    Username: username,
    Password: password,
    UserAttributes: userAttributes,
    ClientMetadata: clientMetadata
  };

  const secretHash = generateSecretHash(username);
  if (secretHash) params.SecretHash = secretHash;

  try {
    const response = await cognitoClient.send(new SignUpCommand(params));
    res.status(201).json({
      userConfirmed: response.UserConfirmed,
      codeDeliveryDetails: response.CodeDeliveryDetails,
      userSub: response.UserSub
    });
  } catch (err) {
    console.error('Sign-up error:', err?.message || err);
    res.status(400).json({ error: err?.message || 'Failed to sign up user' });
  }
});

app.post('/auth/confirm', async (req, res) => {
  const { username, code } = req.body || {};

  if (!username || !code) {
    return res.status(400).json({ error: 'username and code are required' });
  }

  const params = {
    ClientId: cognitoClientId,
    Username: username,
    ConfirmationCode: code
  };

  const secretHash = generateSecretHash(username);
  if (secretHash) params.SecretHash = secretHash;

  try {
    await cognitoClient.send(new ConfirmSignUpCommand(params));
    res.json({ confirmed: true });
  } catch (err) {
    console.error('Confirm sign-up error:', err?.message || err);
    res.status(400).json({ error: err?.message || 'Failed to confirm user' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const authParameters = {
    USERNAME: username,
    PASSWORD: password
  };

  const secretHash = generateSecretHash(username);
  if (secretHash) authParameters.SECRET_HASH = secretHash;

  const command = new InitiateAuthCommand({
    ClientId: cognitoClientId,
    AuthFlow: 'USER_PASSWORD_AUTH',
    AuthParameters: authParameters
  });

  try {
    const response = await cognitoClient.send(command);

    if (response.ChallengeName) {
      return res.status(202).json({
        challengeName: response.ChallengeName,
        session: response.Session,
        parameters: response.ChallengeParameters,
        message: 'Additional verification required (MFA/Challenge).'
      });
    }

    const authResult = response.AuthenticationResult;
    const idClaims = await idTokenVerifier.verify(authResult.IdToken);
    let groups = idClaims['cognito:groups'] || [];

    if ((!groups || groups.length === 0) && idClaims['cognito:username']) {
      groups = await fetchGroupsForUser(idClaims['cognito:username']);
    }

    const role = groups.includes('Admin') ? 'admin' : (groups[0] || 'user');

    res.json({
      tokens: {
        idToken: authResult.IdToken,
        accessToken: authResult.AccessToken,
        refreshToken: authResult.RefreshToken,
        expiresIn: authResult.ExpiresIn,
        tokenType: authResult.TokenType
      },
      user: {
        username: idClaims['cognito:username'] || idClaims.email || null,
        email: idClaims.email || null,
        groups,
        role
      }
    });
  } catch (err) {
    console.error('Login error:', err?.message || err);
    res.status(400).json({ error: err?.message || 'Login failed' });
  }
});

app.post('/auth/challenge', async (req, res) => {
  const { username, session, challengeName, code, answers = {} } = req.body || {};

  if (!username || !session || !challengeName) {
    return res.status(400).json({ error: 'username, session and challengeName are required' });
  }

  const challengeResponses = {
    USERNAME: username,
    ...answers
  };

  const secretHash = generateSecretHash(username);
  if (secretHash) challengeResponses.SECRET_HASH = secretHash;

  if (code) {
    switch (challengeName) {
      case 'SMS_MFA':
        challengeResponses.SMS_MFA_CODE = code;
        break;
      case 'SOFTWARE_TOKEN_MFA':
        challengeResponses.SOFTWARE_TOKEN_MFA_CODE = code;
        break;
      case 'CUSTOM_CHALLENGE':
        challengeResponses.ANSWER = code;
        break;
      default:
        challengeResponses.ANSWER = code;
        break;
    }
  }

  const command = new RespondToAuthChallengeCommand({
    ClientId: cognitoClientId,
    ChallengeName: challengeName,
    Session: session,
    ChallengeResponses: challengeResponses
  });

  try {
    const response = await cognitoClient.send(command);

    if (response.ChallengeName) {
      return res.status(202).json({
        challengeName: response.ChallengeName,
        session: response.Session,
        parameters: response.ChallengeParameters,
        message: 'Additional verification required'
      });
    }

    const authResult = response.AuthenticationResult;
    const idClaims = await idTokenVerifier.verify(authResult.IdToken);
    let groups = idClaims['cognito:groups'] || [];

    if ((!groups || groups.length === 0) && idClaims['cognito:username']) {
      groups = await fetchGroupsForUser(idClaims['cognito:username']);
    }

    const role = groups.includes('Admin') ? 'admin' : (groups[0] || 'user');

    res.json({
      tokens: {
        idToken: authResult.IdToken,
        accessToken: authResult.AccessToken,
        refreshToken: authResult.RefreshToken,
        expiresIn: authResult.ExpiresIn,
        tokenType: authResult.TokenType
      },
      user: {
        username: idClaims['cognito:username'] || idClaims.email || null,
        email: idClaims.email || null,
        groups,
        role
      }
    });
  } catch (err) {
    console.error('Challenge error:', err?.message || err);
    res.status(400).json({ error: err?.message || 'Failed to respond to challenge' });
  }
});

app.post('/auth/refresh', async (req, res) => {
  const { username, refreshToken } = req.body || {};

  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  const authParameters = {
    REFRESH_TOKEN: refreshToken
  };

  if (username) {
    const secretHash = generateSecretHash(username);
    if (secretHash) authParameters.SECRET_HASH = secretHash;
  }

  const command = new InitiateAuthCommand({
    ClientId: cognitoClientId,
    AuthFlow: 'REFRESH_TOKEN_AUTH',
    AuthParameters: authParameters
  });

  try {
    const response = await cognitoClient.send(command);
    const authResult = response.AuthenticationResult;
    res.json({
      tokens: {
        idToken: authResult.IdToken,
        accessToken: authResult.AccessToken,
        expiresIn: authResult.ExpiresIn,
        tokenType: authResult.TokenType
      }
    });
  } catch (err) {
    console.error('Refresh error:', err?.message || err);
    res.status(400).json({ error: err?.message || 'Failed to refresh tokens' });
  }
});

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
