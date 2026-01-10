/**
 * JOLT Chat Backend
 * © 2025 JOLT. All rights reserved.
 * Unauthorized copying, modification, or redistribution is prohibited.
 */

// Load environment variables from .env file if it exists
require('dotenv').config();

const axios = require('axios');
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { verifyRequestSignature, decryptPayload } = require('./security');
const MODERATION_ENABLED =
  process.env.MODERATION_ENABLED === 'true' &&
  Boolean(process.env.PERSPECTIVE_API_KEY);
const app = express();

// Security: Disable X-Powered-By header
app.disable('x-powered-by');

// Security headers
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Content Security Policy (adjust as needed)
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io; style-src 'self' 'unsafe-inline';");
  }
  next();
});

// Define DEBUG_MODE early
const DEBUG_MODE = process.env.DEBUG === 'true';

// API paths
const API_PATHS = ['/signup', '/login', '/profile/update', '/report', '/block', '/buy-coins', '/gift', '/gifts-history'];

const server = http.createServer(app);
const port = process.env.PORT || 1234;
if (!process.env.PERSPECTIVE_API_KEY) {
  console.warn('Perspective API not configured — moderation disabled');
}

// Allowed origins for CORS
// Load from environment variable (comma-separated) or use defaults
const ALLOWED_ORIGINS_ENV = process.env.ALLOWED_ORIGINS;
const ALLOWED_ORIGINS = ALLOWED_ORIGINS_ENV 
  ? ALLOWED_ORIGINS_ENV.split(',').map(orig => orig.trim())
  : [
      'https://joltchat.org',
      'https://www.joltchat.org',
      'capacitor://localhost',     // Android / iOS WebView
      'http://localhost:3000',    // local dev
      'http://127.0.0.1:5500',    // local dev
      'http://localhost:1234'     // local backend dev
    ];

// Add Netlify patterns (supports *.netlify.app and custom domains)
if (process.env.ALLOW_NETLIFY === 'true' || !ALLOWED_ORIGINS_ENV) {
  // Netlify patterns will be checked dynamically
}

// Helper function to check if origin is allowed
function isOriginAllowed(origin) {
  if (!origin || origin === 'null') {
    return true; // Allow same-origin requests and WebView
  }
  
  // Check exact matches
  if (ALLOWED_ORIGINS.includes(origin)) {
    return true;
  }
  
  // Check Netlify domains (*.netlify.app and custom domains)
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    
    // Allow Netlify domains if ALLOW_NETLIFY is true or not explicitly set
    if (process.env.ALLOW_NETLIFY === 'true' || (!ALLOWED_ORIGINS_ENV && process.env.ALLOW_NETLIFY !== 'false')) {
      // Allow *.netlify.app domains
      if (hostname.endsWith('.netlify.app')) {
        return true;
      }
      // Allow netlify.app subdomains
      if (hostname === 'netlify.app' || hostname.includes('.netlify.app')) {
        return true;
      }
    }
  } catch (e) {
    // Invalid URL, continue to check
  }
  
  // In development OR if not explicitly set to production, allow any localhost origin (different ports)
  // This ensures localhost works even if NODE_ENV is not set
  const isProduction = process.env.NODE_ENV === 'production';
  if (!isProduction) {
    try {
      const url = new URL(origin);
      const hostname = url.hostname.toLowerCase();
      // Allow localhost, 127.0.0.1, ::1, and any local IP
      if (hostname === 'localhost' || 
          hostname === '127.0.0.1' || 
          hostname === '::1' ||
          hostname.startsWith('192.168.') ||
          hostname.startsWith('10.') ||
          hostname === '0.0.0.0') {
        return true;
      }
    } catch (e) {
      // Invalid URL, continue to check
    }
  }
  
  return false;
}

// --- Socket.IO Configuration ---
const { Server } = require('socket.io');
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      // Always allow requests without origin (same-origin, mobile apps, etc.)
      if (!origin) {
        return callback(null, true);
      }
      
      if (isOriginAllowed(origin)) {
        if (DEBUG_MODE) {
          console.log(`Socket.IO CORS allowed origin: ${origin}`);
        }
        return callback(null, true);
      }
      console.warn('Socket.IO CORS blocked origin:', origin);
      return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['Content-Type', 'Authorization']
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25025,
  maxHttpBufferSize: 1e8,
  perMessageDeflate: false
});

// CORS Middleware - MUST be VERY FIRST (right after security headers) to handle OPTIONS preflight
app.use(
  cors({
    origin: (origin, callback) => {
      // Always allow requests without origin (same-origin, Postman, curl, etc.)
      if (!origin) {
        return callback(null, true);
      }
      
      if (DEBUG_MODE) {
        console.log(`CORS check - Origin: ${origin || 'null'}, Allowed: ${isOriginAllowed(origin)}`);
      }
      if (isOriginAllowed(origin)) {
        return callback(null, true);
      }
      console.warn('HTTP CORS blocked origin:', origin);
      console.warn('Current NODE_ENV:', process.env.NODE_ENV || 'not set');
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id', 'X-Requested-With', 'Accept', 'X-Request-Signature', 'X-Request-Timestamp', 'X-Request-Nonce', 'Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'],
    exposedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 200,
    preflightContinue: false
  })
);

// JSON body parser (must come after CORS)
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Webhook handlers (must be before other routes to bypass body parsing issues)
require('./payments/razorpay.webhook')(app);

// Request validation middleware
const nonceStore = new Map();

function validateApiRequest(req, res, next) {
  // Skip validation for OPTIONS requests (CORS preflight)
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  // Signature validation is optional in development (default: disabled)
  // Enable it by setting REQUIRE_API_SIGNATURE=true
  const isDevelopment = !process.env.NODE_ENV || process.env.NODE_ENV === 'development';
  const requireSignature = process.env.REQUIRE_API_SIGNATURE === 'true' || process.env.NODE_ENV === 'production';
  
  // Skip signature validation in development unless explicitly enabled
  if (!requireSignature) {
    return next();
  }
  
  // Check for request signature
  const signature = req.headers['x-request-signature'];
  const timestamp = req.headers['x-request-timestamp'];
  const nonce = req.headers['x-request-nonce'];
  
  if (!signature || !timestamp || !nonce) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  
  // Verify signature
  const payload = req.body || {};
  const verification = verifyRequestSignature(payload, parseInt(timestamp), nonce, signature);
  
  if (!verification.valid) {
    return res.status(401).json({ message: 'Invalid request signature' });
  }
  
  // Check nonce (prevent replay)
  if (nonceStore.has(nonce)) {
    return res.status(401).json({ message: 'Duplicate request' });
  }
  
  nonceStore.set(nonce, Date.now());
  
  // Clean old nonces (older than 5 minutes)
  if (nonceStore.size > 10000) {
    const now = Date.now();
    for (const [storedNonce, storedTime] of nonceStore.entries()) {
      if (now - storedTime > 5 * 60 * 1000) {
        nonceStore.delete(storedNonce);
      }
    }
  }
  
  next();
}

// Rate limiting
const rateLimit = new Map();
app.set('trust proxy', true);

// Debug logging for API requests
app.use((req, res, next) => {
  const path = req.path.split('?')[0];
  if (API_PATHS.includes(path) && DEBUG_MODE) {
    console.log(`${new Date().toISOString()} ${req.method} ${path} - Origin: ${req.headers.origin || 'none'}`);
  }
  next();
});

// Pre-check: Allow API endpoints before security checks
app.use((req, res, next) => {
  const path = req.path.split('?')[0];
  
  if (API_PATHS.includes(path)) {
    // Apply request validation for API endpoints (but only if signature is required)
    return validateApiRequest(req, res, next);
  }
  next();
});

// Security middleware: Rate limiting and bot detection
app.use((req, res, next) => {
  // Allow payment webhooks and payment routes
  if (req.path.startsWith('/razorpay') || req.path.startsWith('/paypal') || req.path.includes('webhook') || req.path.startsWith('/payments/')) {
    return next();
  }
  
  // Allow health, root, and online-count endpoints
  if (req.path === '/' || req.path === '/health' || req.path === '/online-count') {
    return next();
  }

  // Skip security checks for API endpoints
  const pathWithoutQuery = req.path.split('?')[0];
  if (API_PATHS.includes(pathWithoutQuery)) {
    return next();
  }

  const ip =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    'unknown';

  const ua = req.headers['user-agent'] || '';
  const accept = req.headers['accept'] || '';

  const now = Date.now();
  let entry = rateLimit.get(ip);

  if (!entry) {
    entry = { count: 0, ts: now };
    rateLimit.set(ip, entry);
  }

  // Reset window every 60s
  if (now - entry.ts > 60_000) {
    entry.count = 0;
    entry.ts = now;
  }

  entry.count += 1;

  // Burst protection (120 requests per minute)
  if (entry.count > 120) {
    console.warn(`HTTP rate limit hit from IP: ${ip}`);
    return res.status(429).json({
      message: 'Too many requests. Please slow down.'
    });
  }
  // Allow frontend assets
  if (req.method === 'GET' && (
    req.path.startsWith('/app') ||
    req.path.startsWith('/styles') ||
    req.path.startsWith('/dist') ||
    req.path.endsWith('.html') ||
    req.path.endsWith('.css') ||
    req.path.endsWith('.js') ||
    req.path.endsWith('.ico') ||
    req.path.endsWith('.webmanifest')
  )) {
    return next();
  }
  
  // Bot detection (disabled in development)
  const isDevelopment = !process.env.NODE_ENV || process.env.NODE_ENV === 'development';
  if (isDevelopment) {
    return next();
  }
  
  if (process.env.NODE_ENV === 'production') {
    const suspicious = (!ua || ua.length < 10) && 
                       !accept.includes('application/json') && 
                       !accept.includes('text/html');

    if (suspicious && (!ua || !accept)) {
      console.warn(`Blocked suspicious client: ${ip} ${ua || 'no-UA'} ${accept || 'no-Accept'}`);
      return res.status(403).json({ message: 'Forbidden' });
    }
  }

  // Memory cleanup
  if (rateLimit.size > 10_000) {
    for (const [k, v] of rateLimit) {
      if (now - v.ts > 120_000) rateLimit.delete(k);
    }
  }

  next();
});

// --- USERS db ---
const { loadUsers, saveUsers } = require('./users');
// ================= SESSION STORE =================
// sessionId -> { username, createdAt, execToken, ageVerified }

const sessions = new Map();

// Session TTL cleanup (30 minutes idle)
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.createdAt > 30 * 60 * 1000) {
      sessions.delete(id);
    }
  }
}, 10 * 60 * 1000);

// Active socket tracking: sessionId -> socket.id
const activeSockets = new Map();

// Reconnect throttle: sessionId -> lastConnectTimestamp
const reconnectThrottle = new Map();

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function createSession(username, ageVerified = false) {
  const sessionId = crypto.randomUUID();
  const execToken = crypto.randomBytes(32).toString('hex'); // Anti-replay token

  sessions.set(sessionId, {
    username,
    createdAt: Date.now(),
    execToken,
    ageVerified
  });

  return { sessionId, execToken };
}


function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;

  if (Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

function requireSession(req, res, next) {
  const sessionId = req.headers['x-session-id'];
  const session = getSession(sessionId);

  if (!session) {
    return res.status(401).json({ message: 'Unauthorized session' });
  }

  req.username = session.username;
  req.session = session; // Expose execToken & ageVerified
  next();
}

// --- REPORTS FEATURE ---
const reportFile = path.join(__dirname, 'reports.json');

function loadReports() {
  let raw = '[]';
  try {
    if (fs.existsSync(reportFile)) {
      raw = fs.readFileSync(reportFile, 'utf8') || '[]';
    }
    const reports = JSON.parse(raw);
    return Array.isArray(reports) ? reports : [];
  } catch (err) {
    console.error('Error loading reports.json:', err);
    const tmp = `${reportFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([], null, 2));
    fs.renameSync(tmp, reportFile);
    return [];
  }
}

function saveReports(reports) {
  const tmp = `${reportFile}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(reports, null, 2),
    { mode: 0o600 }
  );

  fs.renameSync(tmp, reportFile);
}


app.post('/report', requireSession, (req, res) => {
  const { reported, reason } = req.body;

  if (!reported) {
    return res.status(400).json({ message: 'Reported user is required.' });
  }

  const reports = loadReports();
  reports.push({
    reporter: req.username,
    reported: reported.toLowerCase(),
    reason: reason || '',
    timestamp: new Date().toISOString()
  });

  saveReports(reports);
  // Immediately disconnect reported user if online
  for (const s of io.sockets.sockets.values()) {
    if (s.username && s.username.toLowerCase() === reported.toLowerCase()) {
      s.emit('chatEnded');
      s.disconnect(true);
    }
  }
  res.json({ message: 'Report received.' });
});


// --- BLOCK FEATURE ---
const blockFile = path.join(__dirname, 'blocks.json');

function loadBlocks() {
  let raw = '[]';
  try {
    if (fs.existsSync(blockFile)) {
      raw = fs.readFileSync(blockFile, 'utf8') || '[]';
    }
    const blocks = JSON.parse(raw);
    return Array.isArray(blocks) ? blocks : [];
  } catch (err) {
    console.error('Error loading blocks.json:', err);
    const tmp = `${blockFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([], null, 2));
    fs.renameSync(tmp, blockFile);
    return [];
  }
}

function saveBlocks(blocks) {
  const tmp = `${blockFile}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(blocks, null, 2),
    { mode: 0o600 }
  );

  fs.renameSync(tmp, blockFile);
}

function isBlocked(userA, userB) {
  const a = userA.toLowerCase();
  const b = userB.toLowerCase();
  const blocks = loadBlocks();
  return blocks.some(
    blk =>
      (blk.blocker === a && blk.blocked === b) ||
      (blk.blocker === b && blk.blocked === a)
  );
}

app.post('/block', requireSession, (req, res) => {
  const { blocked } = req.body;
  const blocker = req.username.toLowerCase();

  if (!blocked) {
    return res.status(400).json({ message: 'Blocked user is required.' });
  }

  const blockedUser = blocked.toLowerCase();

  if (blockedUser === blocker) {
    return res.status(400).json({ message: 'You cannot block yourself.' });
  }

  const blocks = loadBlocks();

  // Prevent duplicate or reverse duplicate blocks
  const exists = blocks.some(
    b =>
      (b.blocker === blocker && b.blocked === blockedUser) ||
      (b.blocker === blockedUser && b.blocked === blocker)
  );

  if (!exists) {
    blocks.push({
      blocker,
      blocked: blockedUser,
      timestamp: new Date().toISOString()
    });
    saveBlocks(blocks);
  }

  res.json({ message: 'User blocked.' });
});


// --- GIFTS FEATURE (LOGGING) ---
const giftsFile = path.join(__dirname, 'gifts.json');

function loadGifts() {
  let raw = '[]';
  try {
    if (fs.existsSync(giftsFile)) {
      raw = fs.readFileSync(giftsFile, 'utf8') || '[]';
    }
    let gifts = JSON.parse(raw);
    return Array.isArray(gifts) ? gifts : [];
  } catch (err) {
    console.error('Error loading gifts.json:', err);
    const tmp = `${giftsFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([], null, 2));
    fs.renameSync(tmp, giftsFile);
    return [];
  }
}

function saveGifts(gifts) {
  const tmp = `${giftsFile}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(gifts, null, 2),
    { mode: 0o600 }
  );

  fs.renameSync(tmp, giftsFile);
}

// --- VIRTUAL GIFTS: HISTORY (last 20 gifts involving user) ---
app.get('/gifts-history', (req, res) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ message: 'Username is required.' });
  }

  try {
    const gifts = loadGifts();
    const filtered = gifts
      .filter(g => g.from === username || g.to === username)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 20);

    res.json({ gifts: filtered || [] });
  } catch (error) {
    console.error('Error loading gift history:', error);
    res.status(500).json({ message: 'Failed to load gift history', gifts: [] });
  }
});

// --- HEALTH & PROFILE ---
app.get('/', (req, res) => {
  res.send('Welcome to JOLT - Future of Random Chat!');
});

app.get('/health', (req, res) => {
  res.json({ status: 'Server is running', project: 'JOLT' });
});

// --- AUTH ---
app.post('/signup', async (req, res) => {
  const { username, password, age, bio, gender, interests } = req.body;
  if (!username || !password)
    return res.json({ message: 'Enter username & password.' });

  let users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.json({ message: 'Username exists.' });
  }
  const hash = await bcrypt.hash(password, 12);
  users.push({
    username,
    password: hash,
    age: age || '',
    bio: bio || '',
    image: '',
    gender: gender || '',
    interests: interests || [],
    coins: 0,
    paidFeatures: { filtersUnlocked: false },
    isPremium: false,
    premiumUntil: null,   // 👈 ADD THIS
    groups: []
  });
  saveUsers(users);
  res.json({ message: 'Signup successful! Login now.' });
});

app.post('/login', async (req, res) => {
  if (DEBUG_MODE) console.log('LOGIN:', req.body.username);
  const { username, password } = req.body;
  let users = loadUsers();
  const user = users.find(u => u.username === username);

  if (user && user.premiumUntil && Date.now() > user.premiumUntil) {
    user.isPremium = false;
    user.paidFeatures = { filtersUnlocked: false };
    user.premiumUntil = null;
    saveUsers(users);
  }
  if (user && (await bcrypt.compare(password, user.password))) {
    const { sessionId, execToken } = createSession(
      user.username,
      Number(user.age) >= 18
    );

    res.json({
      message: 'Login successful! Welcome to JOLT.',
      sessionId,
      execToken, // Client must send this on socket connect
      profile: {
        username: user.username,
        age: user.age || '',
        bio: user.bio || '',
        image: user.image || '',
        gender: user.gender || '',
        interests: user.interests || [],
        coins: user.coins || 0,
        isPremium: user.isPremium,
        premiumUntil: user.premiumUntil
      },
      coins: user.coins || 0,
      isPremium: user.isPremium,
      premiumUntil: user.premiumUntil
    });


  } else {
    res.json({ message: 'Invalid credentials. Try again.' });
  }
});

app.post('/profile/update', requireSession, (req, res) => {
  const {
    age,
    bio,
    image,
    gender,
    interests,
    coins,
    paidFeatures,
    isPremium,
    groups
  } = req.body;

  let users = loadUsers();
  const user = users.find(u => u.username === req.username);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  if (typeof age !== 'undefined') user.age = age;
  if (typeof bio !== 'undefined') user.bio = bio;
  if (typeof image !== 'undefined') user.image = image;
  if (typeof gender !== 'undefined') user.gender = gender;
  if (typeof interests !== 'undefined') user.interests = interests;
  if (typeof coins !== 'undefined') user.coins = coins;
  if (typeof paidFeatures !== 'undefined') user.paidFeatures = paidFeatures;
  if (typeof isPremium !== 'undefined') user.isPremium = isPremium;
  if (typeof groups !== 'undefined') user.groups = groups;

  saveUsers(users);

  res.json({
    message: 'Profile updated!',
    profile: {
      age: user.age,
      bio: user.bio,
      image: user.image,
      gender: user.gender,
      interests: user.interests,
      coins: user.coins,
      paidFeatures: user.paidFeatures,
      isPremium: user.isPremium,
      groups: user.groups
    }
  });
});


// --- VIRTUAL COINS: BUY COINS (mock payment) ---
app.post('/buy-coins', requireSession, (req, res) => {
  const { amount } = req.body;
  const coinsToAdd = Number(amount) || 0;
  if (coinsToAdd <= 0) {
    return res
      .status(400)
      .json({ message: 'Invalid coin amount.' });
  }

  let users = loadUsers();
  const user = users.find(u => u.username === req.username);
  if (!user) {
    return res.status(404).json({ message: 'User not found.' });
  }

  if (typeof user.coins !== 'number') user.coins = 0;
  user.coins += coinsToAdd;
  saveUsers(users);

  return res.json({
    message: 'Coins added successfully.',
    coins: user.coins
  });
});

// --- VIRTUAL GIFTS: SEND GIFT USING COINS ---
app.post('/gift', requireSession, (req, res) => {
  const from = req.username; // Authoritative sender
  const { to, giftType, cost } = req.body;
  const giftCost = Number(cost) || 0;

  if (!to || !giftType || giftCost <= 0) {
    return res.status(400).json({ message: 'Invalid gift request.' });
  }

  if (to === from) {
    return res.status(400).json({ message: 'You cannot gift yourself.' });
  }

  let users = loadUsers();
  const sender = users.find(u => u.username === req.username);
  const receiver = users.find(u => u.username === to);

  if (!sender || !receiver) {
    return res
      .status(404)
      .json({ message: 'Sender or receiver not found.' });
  }

  if (typeof sender.coins !== 'number') sender.coins = 0;
  if (sender.coins < giftCost) {
    return res.status(400).json({ message: 'Not enough coins.' });
  }

  // Deduct coins
  sender.coins -= giftCost;
  saveUsers(users);

  // Log gift
  const gifts = loadGifts();
  gifts.push({
    from,
    to,
    giftType,
    cost: giftCost,
    timestamp: new Date().toISOString()
  });
  saveGifts(gifts);

  // Try to notify receiver via Socket.IO (if online)
  for (const [id, s] of io.sockets.sockets) {
    if (s.username === to) {
      s.emit('gift-received', {
        from,
        giftType,
        cost: giftCost
      });
      break;
    }
  }

  return res.json({
    message: 'Gift sent successfully.',
    remainingCoins: sender.coins
  });
});

// WebRTC Partners Map
const partners = new Map();

// Queue-based matchmaking (replaces single waiting user)
const matchmakingQueue = [];

// Online users count endpoint - must be accessible without auth
// Defined after matchmakingQueue to ensure it's accessible
app.get('/online-count', (req, res) => {
  console.log('[/online-count] Request received');
  try {
    // Count active sockets (connected users) - default to 0 if null/undefined
    const onlineCount = (io && io.sockets && io.sockets.sockets) ? io.sockets.sockets.size : 0;
    // Count users in matchmaking queue - default to 0 if null/undefined
    const queuedCount = (matchmakingQueue && Array.isArray(matchmakingQueue)) ? matchmakingQueue.length : 0;
    
    // Ensure values are numbers, default to 0
    const online = Number(onlineCount) || 0;
    const queued = Number(queuedCount) || 0;
    const inChat = Math.max(0, online - queued);
    
    console.log(`[/online-count] Returning: online=${online}, queued=${queued}, inChat=${inChat}`);
    res.json({
      online: online,
      queued: queued,
      inChat: inChat
    });
  } catch (error) {
    console.error('[/online-count] Error getting online count:', error);
    res.json({
      online: 0,
      queued: 0,
      inChat: 0
    });
  }
});

// Skip history: username -> Set of recently matched/skipped usernames (with timestamps)
// Format: { username: Set of { partner: string, timestamp: number } }
const skipHistory = new Map();
const SKIP_HISTORY_TTL = 5 * 60 * 1000; // 5 minutes - don't rematch within 5 min

// Cleanup old skip history entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [username, history] of skipHistory.entries()) {
    for (const entry of history) {
      if (now - entry.timestamp > SKIP_HISTORY_TTL) {
        history.delete(entry);
      }
    }
    if (history.size === 0) {
      skipHistory.delete(username);
    }
  }
}, 60 * 1000); // Clean every minute

// In-memory moderation state + bans
// moderationState: username -> { strikes: number }
const moderationState = new Map();
// bans: usernames permanently banned by AI moderation
const bansFile = path.join(__dirname, 'bans.json');
let bans = new Set();

// Load bans safely
(function loadBans() {
  try {
    if (!fs.existsSync(bansFile)) {
      fs.writeFileSync(bansFile, JSON.stringify([], null, 2));
    }
    const raw = fs.readFileSync(bansFile, 'utf8') || '[]';
    const list = JSON.parse(raw);
    if (Array.isArray(list)) {
      bans = new Set(list.map(u => u.toLowerCase()));
    }
  } catch (err) {
    console.error('Failed to load bans.json:', err);
    bans = new Set();
  }
})();

function saveBans() {
  const tmp = `${bansFile}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify([...bans], null, 2));
  fs.renameSync(tmp, bansFile);
}

function isBanned(username) {
  return bans.has(username.toLowerCase());
}

function banUser(username, reason = '') {
  bans.add(username);

  // Invalidate all sessions for this user
  for (const [sid, sess] of sessions.entries()) {
    if (sess.username === username) {
      sessions.delete(sid);
      activeSockets.delete(sid);
      reconnectThrottle.delete(sid);
    }
  }

  logModerationEvidence({
    username,
    sessionId: null,
    socketId: null,
    decision: `ban:${reason || 'unspecified'}`,
    frame: null
  });

  console.log(
    `User banned by AI moderation: ${username} ${reason ? `(${reason})` : ''}`
  );
}

// 🔍 Stub function for AI moderation decision
// Replace this with a real API call (e.g. OpenAI image moderation).
async function analyzeFrame(text) {
  try {
    const response = await axios.post(
      'https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze',
      {
        comment: { text },
        languages: ['en'],
        requestedAttributes: {
          TOXICITY: {},
          SEVERE_TOXICITY: {},
          INSULT: {},
          THREAT: {},
          SEXUALLY_EXPLICIT: {}
        }
      },
      {
        params: {
          key: process.env.PERSPECTIVE_API_KEY
        },
        timeout: 5000
      }
    );

    const scores = response.data.attributeScores;

    const toxicity = scores.TOXICITY?.summaryScore?.value || 0;
    const severe = scores.SEVERE_TOXICITY?.summaryScore?.value || 0;
    const threat = scores.THREAT?.summaryScore?.value || 0;
    const sexual = scores.SEXUALLY_EXPLICIT?.summaryScore?.value || 0;

    if (sexual >= 0.85) return 'ban';
    if (severe >= 0.8 || threat >= 0.8) return 'strike';
    if (toxicity >= 0.7) return 'warn';

    return 'ok';
  } catch (err) {
    console.error('Perspective API error:', err.message);
    return 'ok'; // fail-open (never block chat due to API outage)
  }
}

// Moderation evidence ledger (append-only, audit-grade)
const MOD_LOG_FILE = path.join(__dirname, 'moderation-log.jsonl');

// Ensure moderation log is append-only & private
if (!fs.existsSync(MOD_LOG_FILE)) {
  fs.writeFileSync(MOD_LOG_FILE, '', { mode: 0o600 });
}

function encrypt(text) {
  const key = crypto
    .createHash('sha256')
    .update(process.env.MOD_LOG_SECRET || 'jolt-default-secret')
    .digest();

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    iv: iv.toString('hex'),
    content: encrypted,
    tag: cipher.getAuthTag().toString('hex')
  };
}

function logModerationEvidence({
  username,
  sessionId,
  socketId,
  decision,
  frame
}) {
  try {
    const frameHash = frame
      ? crypto.createHash('sha256').update(frame).digest('hex')
      : null;

    const encryptedDecision = encrypt(decision);

    fs.appendFileSync(
      MOD_LOG_FILE,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        username,
        sessionId,
        socketId,
        decision: encryptedDecision,
        frameHash
      }) + '\n'
    );
  } catch (err) {
    console.error('Moderation evidence log error:', err);
  }
}
function getModeration(username) {
  const key = username.toLowerCase();
  if (!moderationState.has(key)) {
    moderationState.set(key, { strikes: 0 });
  }
  return moderationState.get(key);
}

// ====== SOCKET.IO + PREMIUM FILTERED MATCHMAKING =====
io.use((socket, next) => {
  const { sessionId, execToken } = socket.handshake.auth || {};
  const session = getSession(sessionId);

  if (!session) {
    return next(new Error('Unauthorized socket'));
  }

  // Exec token replay protection
  if (session.execToken !== execToken) {
    return next(new Error('Invalid exec token'));
  }

  // Reconnect throttle (1 reconnect per 3s)
  const now = Date.now();
  const last = reconnectThrottle.get(sessionId) || 0;

  if (now - last < 3000) {
    return next(new Error('Reconnect throttled'));
  }

  reconnectThrottle.set(sessionId, now);

  // Single active socket per session
  const existingSocketId = activeSockets.get(sessionId);
  if (existingSocketId && existingSocketId !== socket.id) {
    const oldSocket = io.sockets.sockets.get(existingSocketId);
    if (oldSocket) {
      oldSocket.emit('session-replaced');
      oldSocket.disconnect(true);
    }
  }

  socket.username = session.username;
  socket.sessionId = sessionId;
  socket.ageVerified = session.ageVerified;

  activeSockets.set(sessionId, socket.id);

  next();
});


io.on('connection', socket => {
  console.log(
    `New connection: ${socket.id} (user=${socket.username || 'unknown'}, session=${socket.sessionId || 'n/a'})`
  );

  // Cleanup stale queue entries (ghost cleanup)
  for (let i = matchmakingQueue.length - 1; i >= 0; i--) {
    if (matchmakingQueue[i].socket.disconnected) {
      matchmakingQueue.splice(i, 1);
    }
  }

  // Prevent duplicate active socket binding
  if (socket.sessionId) {
    activeSockets.set(socket.sessionId, socket.id);
  }

  /* ================= SOCKET RATE LIMIT (ANTI-SPAM) ================= */

  const socketRate = {
    chat: { count: 0, ts: Date.now() },
    signal: { count: 0, ts: Date.now() },
    moderation: { count: 0, ts: Date.now() }
  };

  function socketThrottle(bucket, limit, windowMs) {
    const now = Date.now();
    const entry = socketRate[bucket];

    if (!entry) return true;

    if (now - entry.ts > windowMs) {
      entry.count = 0;
      entry.ts = now;
    }

    entry.count += 1;

    if (entry.count > limit) {
      console.warn(
        `Socket abuse: ${bucket} limit exceeded by ${socket.username || socket.id}`
      );
      return false;
    }

    return true;
  }

  /* ================= PARTNER CLEANUP ================= */
  function cleanupPartner(sock) {
    try {
      if (sock && sock.partner) {
        const partner = sock.partner;
        // Check if partner socket is still valid
        if (partner && partner.id) {
          try {
            partner.emit('chatEnded');
            partner.partner = null;
            partners.delete(partner.id);
          } catch (err) {
            // Partner socket might be disconnected
            console.warn('Partner socket already disconnected during cleanup');
          }
        }
      }
    } catch (err) {
      console.error('Partner cleanup error:', err);
    }

    if (sock) {
      sock.partner = null;
      if (sock.id) {
        partners.delete(sock.id);
      }
    }
  }

  /* ================= MODERATION ================= */
  let lastModerationAt = 0;

  socket.on('moderate-frame', async payload => {
    try {
      if (!socketThrottle('moderation', 10, 10_000)) return;
      if (!MODERATION_ENABLED) {
        return; // Moderation hard-disabled (safe bypass)
      }
      const username = payload?.username || socket.username;
      const text = payload?.text || '';
      const frame =
        typeof payload?.frame === 'string' ? payload.frame : null;

      if (!username) return;

      if (isBanned(username)) {
        socket.emit('ai-banned', {
          message: 'Your account is banned due to unsafe content.'
        });
        cleanupPartner(socket);
        socket.disconnect(true);
        return;
      }

      // ⏱️ Throttle: 1 request / 2 seconds per socket
      if (Date.now() - lastModerationAt < 2000) return;
      lastModerationAt = Date.now();

      const decision = await analyzeFrame(text);
      const state = getModeration(username);

      if (decision !== 'ok') {
        logModerationEvidence({
          username,
          sessionId: socket.sessionId,
          socketId: socket.id,
          decision: `ai:${decision}`,
          frame: decision === 'warn' ? null : frame
        });
      }

      if (decision === 'warn') {
        socket.emit('blur-now', { reason: 'potentially_unsafe' });
        socket.emit('content-warning', {
          message: 'Safety check: Please ensure appropriate content.'
        });
        return;
      }

      if (decision === 'strike') {
        state.strikes += 1;

        socket.emit('blur-now', { reason: 'strike_detected' });
        socket.emit('imageRejected', {
          message: 'Inappropriate content detected.',
          strike: state.strikes,
          level: 'warning'
        });

        if (state.strikes === 2) {
          socket.emit('kicked', {
            message: 'You have been kicked due to repeated unsafe content.'
          });
          cleanupPartner(socket);
          socket.disconnect(true);
          return;
        }

        if (state.strikes >= 3) {
          banUser(username, '3+ strikes');
          socket.emit('ai-banned', {
            message: 'You have been banned due to multiple violations.'
          });
          cleanupPartner(socket);
          socket.disconnect(true);
          return;
        }
      }

      if (decision === 'ban') {
        banUser(username, 'severe violation');
        socket.emit('blur-now', { reason: 'severe_violation' });
        socket.emit('ai-banned', {
          message: 'You have been banned due to severe unsafe content.'
        });
        cleanupPartner(socket);
        socket.disconnect(true);
      }
    } catch (err) {
      console.error('Moderation error:', err);
    }
  });

  /* ================= MATCHMAKING ================= */
  let lastJoinAt = 0;

  // Helper function to get skip history for a user
  function getRecentMatches(username) {
    if (!skipHistory.has(username)) {
      skipHistory.set(username, new Set());
    }
    return skipHistory.get(username);
  }

  // Helper function to add to skip history
  function addToSkipHistory(username1, username2) {
    const history1 = getRecentMatches(username1);
    const history2 = getRecentMatches(username2);
    const now = Date.now();
    history1.add(JSON.stringify({ partner: username2.toLowerCase(), timestamp: now }));
    history2.add(JSON.stringify({ partner: username1.toLowerCase(), timestamp: now }));
  }

  // Helper function to check if users were recently matched
  function wasRecentlyMatched(username1, username2) {
    const history = getRecentMatches(username1);
    for (const entry of history) {
      const parsed = JSON.parse(entry);
      if (parsed.partner === username2.toLowerCase()) {
        return true;
      }
    }
    return false;
  }

  // Helper function to find best match from queue (avoiding recent matches)
  function findBestMatch(currentUser, currentSocket, genderFilter, interestFilter, isPremium) {
    // Shuffle queue to randomize matches
    const shuffled = [...matchmakingQueue].sort(() => Math.random() - 0.5);
    
    for (let i = 0; i < shuffled.length; i++) {
      const candidate = shuffled[i];
      
      // Skip if same user
      if (candidate.username.toLowerCase() === currentUser.toLowerCase()) {
        continue;
      }
      
      // Skip if socket is disconnected
      if (candidate.socket.disconnected) {
        matchmakingQueue.splice(matchmakingQueue.indexOf(candidate), 1);
        continue;
      }
      
      // Skip if recently matched
      if (wasRecentlyMatched(currentUser, candidate.username)) {
        continue;
      }
      
      // Check filters (premium feature)
      if (candidate.isPremium && (candidate.genderFilter || candidate.interestFilter.length > 0)) {
        const candidateUser = loadUsers().find(u => u.username === candidate.username);
        if (candidateUser) {
          if (candidate.genderFilter && candidateUser.gender?.toLowerCase() !== candidate.genderFilter.toLowerCase()) {
            continue;
          }
          if (candidate.interestFilter.length > 0) {
            const userInterests = candidateUser.interests || [];
            const hasCommonInterest = candidate.interestFilter.some(interest => 
              userInterests.some(ui => ui.toLowerCase() === interest.toLowerCase())
            );
            if (!hasCommonInterest) continue;
          }
        }
      }
      
      // Check if current user matches candidate's filters
      if (isPremium && (genderFilter || interestFilter.length > 0)) {
        const currentUserData = loadUsers().find(u => u.username === currentUser);
        if (currentUserData) {
          if (genderFilter && currentUserData.gender?.toLowerCase() !== genderFilter.toLowerCase()) {
            continue;
          }
          if (interestFilter.length > 0) {
            const userInterests = currentUserData.interests || [];
            const hasCommonInterest = interestFilter.some(interest => 
              userInterests.some(ui => ui.toLowerCase() === interest.toLowerCase())
            );
            if (!hasCommonInterest) continue;
          }
        }
      }
      
      return candidate;
    }
    
    return null;
  }

  socket.on('joinChat', data => {
    if (Date.now() - lastJoinAt < 3000) {
      socket.emit('error', { message: 'Too many requests. Please wait.' });
      return;
    }
    lastJoinAt = Date.now();

    if (socket.partner) cleanupPartner(socket);

    let username, genderFilter, interestFilter;

    if (typeof data === 'string') {
      username = data;
      genderFilter = '';
      interestFilter = [];
    } else {
      username = socket.username;
      genderFilter = data?.genderFilter || '';
      interestFilter = Array.isArray(data?.interestFilter)
        ? data.interestFilter
        : [];
    }

    if (!username) {
      socket.emit('error', { message: 'Username missing.' });
      return;
    }

    if (isBanned(username)) {
      socket.emit('ai-banned', {
        message: 'Your account is banned.'
      });
      socket.disconnect(true);
      return;
    }

    const users = loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) {
      socket.emit('error', { message: 'User not found.' });
      return;
    }

    const isPremium =
      user.isPremium ||
      (user.paidFeatures && user.paidFeatures.filtersUnlocked);

    if ((genderFilter || interestFilter.length > 0) && !isPremium) {
      socket.emit('filter-locked', {
        message: 'Upgrade to premium to use filters.'
      });
      return;
    }

    // Remove user from queue if already there
    const existingIndex = matchmakingQueue.findIndex(q => q.username === username || q.socket.id === socket.id);
    if (existingIndex !== -1) {
      matchmakingQueue.splice(existingIndex, 1);
    }

    // Try to find a match
    const match = findBestMatch(username, socket, genderFilter, interestFilter, isPremium);
    
    if (!match) {
      // No match found, add to queue
      matchmakingQueue.push({
        socket,
        username,
        genderFilter,
        interestFilter,
        isPremium,
        joinedAt: Date.now()
      });
      socket.emit('waiting');
      return;
    }

    // Found a match! Remove from queue
    const matchIndex = matchmakingQueue.findIndex(q => q.socket.id === match.socket.id);
    if (matchIndex !== -1) {
      matchmakingQueue.splice(matchIndex, 1);
    }

    // Create partnership
    socket.partner = match.socket;
    match.socket.partner = socket;

    partners.set(socket.id, match.socket.id);
    partners.set(match.socket.id, socket.id);

    // Add to skip history (will be removed after chat ends or skip)
    addToSkipHistory(username, match.username);

    socket.emit('matched', match.username);
    match.socket.emit('matched', username);

    socket.emit('start-webrtc', { initiator: true });
    match.socket.emit('start-webrtc', { initiator: false });
  });

  /* ================= CHAT ================= */
  socket.on('chatMsg', msg => {
    if (!socketThrottle('chat', 40, 10_000)) return;
    if (socket.partner) socket.partner.emit('chatMsg', msg);
  });

  socket.on('endChat', () => {
    // If there was a partner, add to skip history before cleanup
    if (socket.partner && socket.username && socket.partner.username) {
      addToSkipHistory(socket.username, socket.partner.username);
    }
    cleanupPartner(socket);
  });

  /* ================= WEBRTC ================= */
  ['webrtc-offer', 'webrtc-answer', 'webrtc-ice-candidate'].forEach(evt => {
    socket.on(evt, data => {
      if (!socketThrottle('signal', 80, 10_000)) return;
      const partnerId = partners.get(socket.id);
      if (!partnerId) return;

      const partnerSocket = io.sockets.sockets.get(partnerId);
      if (!partnerSocket) {
        cleanupPartner(socket);
        return;
      }

      partnerSocket.emit(evt, {
        ...data,
        from: socket.username
      });
    });
  });

  socket.on('disconnect', () => {
    // Remove from matchmaking queue
    const queueIndex = matchmakingQueue.findIndex(q => q.socket.id === socket.id);
    if (queueIndex !== -1) {
      matchmakingQueue.splice(queueIndex, 1);
    }

    cleanupPartner(socket);

    // Remove active socket binding
    if (socket.sessionId) {
      activeSockets.delete(socket.sessionId);
    }

    console.log(`Disconnected: ${socket.id}`);
  });
});
require('./payments/razorpay')(app, requireSession);
require('./payments/paypal')(app, requireSession);
server.listen(port, () => {
  console.log(`JOLT backend with WebRTC signaling running at http://localhost:${port}`);
  console.log('Socket.IO transports: websocket, polling');
  console.log(
    MODERATION_ENABLED
      ? 'AI moderation ENABLED (Perspective API)'
      : 'AI moderation DISABLED (safe mode)'
  );
});
