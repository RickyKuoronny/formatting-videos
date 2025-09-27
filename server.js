require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const os = require('os');
const { exec } = require('child_process'); 
const cloudinary = require('cloudinary').v2;
const mime = require('mime-types');
const { PassThrough } = require('stream');
const { Upload } = require("@aws-sdk/lib-storage");

const { uploadFile, getPresignedUrl } = require('./backend/s3');
const { saveMetadata, saveLog, getLogs } = require('./backend/dynamo');

const app = express();

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json()); // for parsing JSON bodies

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const OUTPUT_DIR = path.resolve(__dirname, 'outputs');

// --- Hard-coded users ---
const users = [
  { username: 'user1', passwordHash: bcrypt.hashSync('pass', 10), role: 'user' },
  { username: 'admin', passwordHash: bcrypt.hashSync('adminpass', 10), role: 'admin' }
];

// --- JWT middleware ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Middleware to check admin role
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden: Admins only' });
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

// --- Login route ---
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const payload = { username: user.username, role: user.role };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  res.json({ token });
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

  // FFmpeg args
  const args = ['-i', 'pipe:0', '-hide_banner', '-loglevel', 'error'];
  if (scaleArg) args.push('-vf', scaleArg);
  args.push('-c:v', 'libx264', '-preset', 'veryfast', '-crf', '23', '-c:a', 'aac', '-b:a', '128k', '-f', 'mp4', 'pipe:1');

  const ff = spawn('ffmpeg', args);
  let ffErr = '';
  ff.stderr.on('data', (d) => ffErr += d.toString());

  ff.stdin.end(req.file.buffer);

  const passThrough = new PassThrough();

  // Use @aws-sdk/lib-storage Upload helper
  const upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: outName,
      Body: passThrough,
      ContentType: 'video/mp4'
    }
  });

  ff.stdout.pipe(passThrough);

  ff.on('close', async (code) => {
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
      console.error(`[${completedAt}] FFmpeg failed:`, ffErr);
      return res.status(500).json({ error: 'FFmpeg failed', details: ffErr });
    }

    try {
      await upload.done(); // wait for streaming upload to complete
      const presignedUrl = await getPresignedUrl(outName);

      const metadata = { filename: outName };
      await saveMetadata(outName, metadata);

      res.json({
        ok: true,
        s3Url: presignedUrl,
        outputFile: outName,
        metadata
      });
    } catch (err) {
      console.error('S3 upload failed:', err);
      res.status(500).json({ error: 'S3 upload failed', details: err.message });
    }
  });

  ff.on('error', (err) => {
    console.error('FFmpeg spawn error:', err);
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
