/**
 * JOLT Chat Backend
 * © 2025 JOLT. All rights reserved.
 * Unauthorized copying, modification, or redistribution is prohibited.
 */

const axios = require('axios');
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http');
const bcrypt = require('bcrypt'); // ✅ CHANGE: moved to top for clarity
const crypto = require('crypto');
const MODERATION_ENABLED =
  process.env.MODERATION_ENABLED === 'true' &&
  Boolean(process.env.PERSPECTIVE_API_KEY);
const app = express();
// ✅ Serve frontend (public)
const server = http.createServer(app);
const port = process.env.PORT || 1234;
if (!process.env.PERSPECTIVE_API_KEY) {
  console.warn('⚠️ Perspective API not configured — moderation disabled');
}
// 🔐 SECURITY: Allowed origins (anti-clone, anti-scrape)
const ALLOWED_ORIGINS = [
  'https://joltchat.org',
  'https://www.joltchat.org',
  'capacitor://localhost',     // Android / iOS WebView
  'http://localhost:3000'      // local dev
];
app.get('/app', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'public/app/index.html')
  );
});

// --- Socket.IO with proper CORS and Transport Options ---
const { Server } = require('socket.io');
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      // Allow WebView, same-origin, server-to-server
      if (!origin || origin === 'null') {
        return callback(null, true);
      }

      if (ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }

      console.warn('Socket.IO CORS blocked origin:', origin);
      return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e8,
  perMessageDeflate: false
});

// ✅ Tiny request logger (helps debugging)
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// ✅ Enhanced CORS Middleware (Express)
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow WebView, same-origin, server-to-server
      if (!origin || origin === 'null') {
        return callback(null, true);
      }

      if (ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }

      console.warn('HTTP CORS blocked origin:', origin);
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS']
  })
);

// ✅ OPTIONS preflight handler (NO wildcard headers)
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.header(
      'Access-Control-Allow-Origin',
      req.headers.origin && ALLOWED_ORIGINS.includes(req.headers.origin)
        ? req.headers.origin
        : ''
    );
    res.header(
      'Access-Control-Allow-Methods',
      'GET, POST, OPTIONS'
    );
    res.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization'
    );
    return res.sendStatus(200);
  }
  next();
});

// JSON body parser
app.use(express.json({ limit: '2mb' }));
require('./payments/razorpay.webhook')(app);

// 🔐 HARDENED HTTP RATE LIMIT (IP-based, safe for Render)
const rateLimit = new Map();

app.set('trust proxy', true); // 🔐 required for Render / Netlify

app.use((req, res, next) => {
    // ✅ ALWAYS allow payment webhooks (Razorpay / PayPal)
  if (
    req.path.startsWith('/razorpay') ||
    req.path.startsWith('/paypal') ||
    req.path.includes('webhook')
  ) {
    return next();
  }
// Skip health & root
  if (req.path === '/' || req.path === '/health') {
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

  // 🔐 Burst protection
  if (entry.count > 120) {
    console.warn(`⛔ HTTP rate limit hit from IP: ${ip}`);
    return res.status(429).json({
      message: 'Too many requests. Please slow down.'
    });
  }
// ✅ Allow frontend assets & pages FIRST
if (
  req.method === 'GET' &&
  (
    req.path.startsWith('/app') ||
    req.path.startsWith('/styles') ||
    req.path.startsWith('/dist') ||
    req.path.endsWith('.html') ||
    req.path.endsWith('.css') ||
    req.path.endsWith('.js') ||
    req.path.endsWith('.ico') ||
    req.path.endsWith('.webmanifest')
  )
) {
  return next();
}
  /* 🤖 BOT / SCRAPER DETECTION (PASSIVE & SAFE) */
  const suspicious =
    !ua ||
    ua.length < 20 ||
    /curl|wget|python|node|axios|httpclient|scrapy|go-http|headless/i.test(ua) ||
    (!accept.includes('text/html') &&
      !accept.includes('application/json'));

if (suspicious) {
  console.warn(`🤖 Blocked suspicious client: ${ip} ${ua}`);
  return res.status(403).json({ message: 'Forbidden' });
}

  // 🧹 Memory cleanup
  if (rateLimit.size > 10_000) {
    for (const [k, v] of rateLimit) {
      if (now - v.ts > 120_000) rateLimit.delete(k);
    }
  }

  next();
});



// --- USERS db ---
const dbFile = path.join(__dirname, 'users.json');
function loadUsers() {
  let raw = '[]';
  try {
    if (fs.existsSync(dbFile)) raw = fs.readFileSync(dbFile, 'utf8') || '[]'; // ✅ CHANGE: fallback to '[]'
    let users = JSON.parse(raw);
    if (!Array.isArray(users)) {
      users = [];
      const tmpFile = `${dbFile}.tmp`;
fs.writeFileSync(tmpFile, JSON.stringify(users, null, 2), { mode: 0o600 });
fs.renameSync(tmpFile, dbFile);
    }
    return users;
  } catch (err) {
    console.error('Error loading users.json:', err); // ✅ CHANGE: log error
    fs.writeFileSync(dbFile, JSON.stringify([], null, 2));
    return [];
  }
}
function saveUsers(users) {
  const tmp = `${dbFile}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
  fs.renameSync(tmp, dbFile);
}
// ================= SESSION STORE =================
// sessionId -> { username, createdAt, execToken, ageVerified }

const sessions = new Map();

/* 🔐 Session TTL cleanup (30 minutes idle) */
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.createdAt > 30 * 60 * 1000) {
      sessions.delete(id);
    }
  }
}, 10 * 60 * 1000);

/*
  🔐 ACTIVE SOCKET TRACKING
  sessionId -> socket.id
*/
const activeSockets = new Map();

/*
  🔐 RECONNECT THROTTLE
  sessionId -> lastConnectTimestamp
*/
const reconnectThrottle = new Map();

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function createSession(username, ageVerified = false) {
  const sessionId = crypto.randomUUID();
  const execToken = crypto.randomBytes(32).toString('hex'); // 🔐 anti-replay token

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
  req.session = session; // 🔐 expose execToken & ageVerified
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
   // 🔐 SAFETY: Immediately disconnect reported user if online
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

  const gifts = loadGifts();
  const filtered = gifts
    .filter(g => g.from === username || g.to === username)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 20);

  res.json({ gifts: filtered });
});

// --- HEALTH & PROFILE ---
app.get('/', (req, res) => {
  res.send('Welcome to JOLT - Future of Random Chat! 🚀');
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
  execToken, // 🔐 client must send this on socket connect
  profile: {
  username: user.username,
  age: user.age || '',
  bio: user.bio || '',
  image: user.image || '',
  gender: user.gender || '',
  interests: user.interests || [],
  isPremium: user.isPremium,
  premiumUntil: user.premiumUntil
}
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
  const from = req.username; // 🔐 authoritative sender
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

// ✅ WebRTC Partners Map
const partners = new Map();
let waiting = null;

// ✅ In-memory moderation state + bans
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

  // 🔐 Invalidate all sessions for this user
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
    `⛔ User banned by AI moderation: ${username} ${reason ? `(${reason})` : ''}`
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

// 🔐 MODERATION EVIDENCE LEDGER (append-only, audit-grade)
const MOD_LOG_FILE = path.join(__dirname, 'moderation-log.jsonl');

/* 🔐 Ensure moderation log is append-only & private */
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

  // 🔐 EXEC TOKEN REPLAY PROTECTION
  if (session.execToken !== execToken) {
    return next(new Error('Invalid exec token'));
  }

  // 🔐 RECONNECT THROTTLE (1 reconnect / 3s)
  const now = Date.now();
  const last = reconnectThrottle.get(sessionId) || 0;

  if (now - last < 3000) {
    return next(new Error('Reconnect throttled'));
  }

  reconnectThrottle.set(sessionId, now);

  // 🔐 SINGLE ACTIVE SOCKET PER SESSION
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
    `🔌 New connection: ${socket.id} (user=${socket.username || 'unknown'}, session=${socket.sessionId || 'n/a'})`
  );

  /* 🔐 SAFETY: clear stale waiting socket (ghost cleanup) */
  if (waiting && waiting.socket && waiting.socket.disconnected) {
    waiting = null;
  }

  /* 🔐 SAFETY: prevent duplicate active socket binding */
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
        `⛔ Socket abuse: ${bucket} limit exceeded by ${socket.username || socket.id}`
      );
      return false;
    }

    return true;
  }

  /* ================= PARTNER CLEANUP ================= */
  function cleanupPartner(sock) {
    try {
      if (sock.partner) {
        sock.partner.emit('chatEnded');
        sock.partner.partner = null;
        partners.delete(sock.partner.id);
      }
    } catch (err) {
      console.error('Partner cleanup error:', err);
    }

    sock.partner = null;
    partners.delete(sock.id);
  }

  /* ================= MODERATION ================= */
  let lastModerationAt = 0;

  socket.on('moderate-frame', async payload => {
    try {
     if (!socketThrottle('moderation', 10, 10_000)) return;
 if (!MODERATION_ENABLED) {
  return; // 🔐 moderation hard-disabled (safe bypass)
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

    if (!waiting) {
      waiting = {
        socket,
        username,
        genderFilter,
        interestFilter,
        isPremium
      };
      socket.emit('waiting');
      return;
    }

    const partner = waiting;
    waiting = null;

    socket.partner = partner.socket;
    partner.socket.partner = socket;

    partners.set(socket.id, partner.socket.id);
    partners.set(partner.socket.id, socket.id);

    socket.emit('matched', partner.username);
    partner.socket.emit('matched', username);

    socket.emit('start-webrtc', { initiator: true });
    partner.socket.emit('start-webrtc', { initiator: false });
  });

  /* ================= CHAT ================= */
  socket.on('chatMsg', msg => {
  if (!socketThrottle('chat', 40, 10_000)) return;
  if (socket.partner) socket.partner.emit('chatMsg', msg);
});

  socket.on('endChat', () => {
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
  if (waiting && waiting.socket === socket) waiting = null;

  cleanupPartner(socket);

  // 🔐 Remove active socket binding
  if (socket.sessionId) {
    activeSockets.delete(socket.sessionId);
  }

  console.log(`🔌 Disconnected: ${socket.id}`);
});
});
module.exports.loadUsers = loadUsers;
module.exports.saveUsers = saveUsers;
require('./payments/razorpay')(app, requireSession);
require('./payments/paypal')(app, requireSession);
server.listen(port, () => {
  console.log(
    `✅ JOLT backend with WebRTC signaling running at http://localhost:${port}`
  );
  console.log('📡 Socket.IO transports: websocket, polling');
  console.log(
  MODERATION_ENABLED
    ? '🛡️ AI moderation ENABLED (Perspective API)'
    : '⚠️ AI moderation DISABLED (safe mode)'
);
});
