const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http');
const { execFile } = require('child_process');

const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 1234;

// --- Socket.IO with proper CORS and Transport Options ---
const { Server } = require('socket.io');
const io = new Server(server, {
  cors: {
    origin: '*',
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

// ✅ Enhanced CORS Middleware
app.use(
  cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS']
  })
);

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json({ limit: '2mb' }));

// --- USERS db ---
const dbFile = path.join(__dirname, 'users.json');
function loadUsers() {
  let raw = '[]';
  try {
    if (fs.existsSync(dbFile)) raw = fs.readFileSync(dbFile, 'utf8');
    let users = JSON.parse(raw);
    if (!Array.isArray(users)) {
      users = [];
      fs.writeFileSync(dbFile, JSON.stringify(users, null, 2));
    }
    return users;
  } catch {
    fs.writeFileSync(dbFile, JSON.stringify([], null, 2));
    return [];
  }
}
function saveUsers(users) {
  fs.writeFileSync(dbFile, JSON.stringify(users, null, 2));
}

// --- REPORTS FEATURE ---
const reportFile = path.join(__dirname, 'reports.json');
function loadReports() {
  let raw = '[]';
  try {
    if (fs.existsSync(reportFile)) raw = fs.readFileSync(reportFile, 'utf8');
    let reports = JSON.parse(raw);
    if (!Array.isArray(reports)) {
      reports = [];
      fs.writeFileSync(reportFile, JSON.stringify(reports, null, 2));
    }
    return reports;
  } catch {
    fs.writeFileSync(reportFile, JSON.stringify([], null, 2));
    return [];
  }
}
function saveReports(reports) {
  fs.writeFileSync(reportFile, JSON.stringify(reports, null, 2));
}

app.post('/report', (req, res) => {
  const { reporter, reported, reason } = req.body;
  const reports = loadReports();
  reports.push({
    reporter,
    reported,
    reason: reason || '',
    timestamp: new Date().toISOString()
  });
  saveReports(reports);
  res.json({ message: 'Report received.' });
});

// --- BLOCK FEATURE ---
const blockFile = path.join(__dirname, 'blocks.json');
function loadBlocks() {
  let raw = '[]';
  try {
    if (fs.existsSync(blockFile)) raw = fs.readFileSync(blockFile, 'utf8');
    let blocks = JSON.parse(raw);
    if (!Array.isArray(blocks)) {
      blocks = [];
      fs.writeFileSync(blockFile, JSON.stringify(blocks, null, 2));
    }
    return blocks;
  } catch {
    fs.writeFileSync(blockFile, JSON.stringify([], null, 2));
    return [];
  }
}
function saveBlocks(blocks) {
  fs.writeFileSync(blockFile, JSON.stringify(blocks, null, 2));
}
function isBlocked(userA, userB) {
  const blocks = loadBlocks();
  return blocks.some(
    b =>
      (b.blocker === userA && b.blocked === userB) ||
      (b.blocker === userB && b.blocked === userA)
  );
}
app.post('/block', (req, res) => {
  const { blocker, blocked } = req.body;
  const blocks = loadBlocks();
  if (!blocks.find(b => b.blocker === blocker && b.blocked === blocked)) {
    blocks.push({ blocker, blocked, timestamp: new Date().toISOString() });
    saveBlocks(blocks);
  }
  res.json({ message: 'User blocked.' });
});

// --- GIFTS FEATURE (LOGGING) ---
const giftsFile = path.join(__dirname, 'gifts.json');
function loadGifts() {
  let raw = '[]';
  try {
    if (fs.existsSync(giftsFile)) raw = fs.readFileSync(giftsFile, 'utf8');
    let gifts = JSON.parse(raw);
    if (!Array.isArray(gifts)) {
      gifts = [];
      fs.writeFileSync(giftsFile, JSON.stringify(gifts, null, 2));
    }
    return gifts;
  } catch {
    fs.writeFileSync(giftsFile, JSON.stringify([], null, 2));
    return [];
  }
}
function saveGifts(gifts) {
  fs.writeFileSync(giftsFile, JSON.stringify(gifts, null, 2));
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

const bcrypt = require('bcrypt');
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
    groups: []
  });
  saveUsers(users);
  res.json({ message: 'Signup successful! Login now.' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  let users = loadUsers();
  const user = users.find(u => u.username === username);
  if (user && (await bcrypt.compare(password, user.password))) {
    res.json({
      message: 'Login successful! Welcome to JOLT.',
      username: user.username,
      age: user.age || '',
      bio: user.bio || '',
      image: user.image || '',
      gender: user.gender || '',
      interests: user.interests || [],
      coins: user.coins || 0,
      paidFeatures: user.paidFeatures || { filtersUnlocked: false },
      isPremium: user.isPremium || false,
      groups: user.groups || []
    });
  } else {
    res.json({ message: 'Invalid credentials. Try again.' });
  }
});

app.post('/profile/update', (req, res) => {
  const {
    username,
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
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: 'User not found' });

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
    age: user.age,
    bio: user.bio,
    image: user.image,
    gender: user.gender,
    interests: user.interests,
    coins: user.coins,
    paidFeatures: user.paidFeatures,
    isPremium: user.isPremium,
    groups: user.groups
  });
});

// --- VIRTUAL COINS: BUY COINS (mock payment) ---
app.post('/buy-coins', (req, res) => {
  const { username, amount } = req.body;
  const coinsToAdd = Number(amount) || 0;
  if (!username || coinsToAdd <= 0) {
    return res
      .status(400)
      .json({ message: 'Invalid username or amount.' });
  }

  let users = loadUsers();
  const user = users.find(u => u.username === username);
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
app.post('/gift', (req, res) => {
  const { from, to, giftType, cost } = req.body;
  const giftCost = Number(cost) || 0;
  if (!from || !to || !giftType || giftCost <= 0) {
    return res.status(400).json({ message: 'Invalid gift request.' });
  }

  let users = loadUsers();
  const sender = users.find(u => u.username === from);
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
const bans = new Set();

function getModeration(username) {
  if (!moderationState.has(username)) {
    moderationState.set(username, { strikes: 0 });
  }
  return moderationState.get(username);
}

function isBanned(username) {
  return bans.has(username);
}

function banUser(username, reason = '') {
  bans.add(username);
  console.log(`⛔ User banned by AI moderation: ${username} ${reason ? `(${reason})` : ''}`);
}

// 🔍 Stub function for AI moderation decision
// Replace this with a real API call (e.g. OpenAI image moderation).
async function analyzeFrame(frameData) {
  // TODO: integrate real AI service here.
  // Return one of: 'ok' | 'warn' | 'strike' | 'ban'
  // For now, always treat as safe:
  return 'ok';
}

// ====== SOCKET.IO + PREMIUM FILTERED MATCHMAKING =====
io.on('connection', socket => {
  console.log(`🔌 New connection: ${socket.id}`);

  // Moderation: receive frames from frontend
  socket.on('moderate-frame', async payload => {
    try {
      const username = payload?.username || socket.username;
      const frame = payload?.frame;

      if (!username || !frame) {
        return;
      }

      if (isBanned(username)) {
        socket.emit('ai-banned', {
          message: 'Your account is banned due to unsafe content.'
        });
        socket.disconnect(true);
        return;
      }

      const decision = await analyzeFrame(frame);
      const state = getModeration(username);

      if (decision === 'ok') {
        // nothing to do
        return;
      }

      if (decision === 'warn') {
        socket.emit('content-warning', {
          message: 'Please follow the JOLT community rules while on camera.'
        });
        return;
      }

      if (decision === 'strike') {
        state.strikes += 1;
        socket.emit('imageRejected', {
          message: 'Inappropriate content detected. This counts as a strike.',
          strike: 1,
          level: 'warning'
        });

        // simple thresholds:
        if (state.strikes === 2) {
          // temporary kick from current chat
          socket.emit('kicked', {
            message: 'You have been kicked from this chat due to repeated unsafe content.'
          });
          if (socket.partner) {
            socket.partner.emit('chatEnded');
            socket.partner.partner = null;
            partners.delete(socket.partner.id);
          }
          socket.partner = null;
          partners.delete(socket.id);
          socket.disconnect(true);
        }

        if (state.strikes >= 3) {
          // permanent AI ban
          banUser(username, '3+ strikes');
          socket.emit('ai-banned', {
            message: 'You have been banned due to multiple violations of our safety policy.'
          });
          if (socket.partner) {
            socket.partner.emit('chatEnded');
            socket.partner.partner = null;
            partners.delete(socket.partner.id);
          }
          socket.partner = null;
          partners.delete(socket.id);
          socket.disconnect(true);
        }

        return;
      }

      if (decision === 'ban') {
        // immediate ban for very serious violation
        banUser(username, 'severe violation');
        socket.emit('ai-banned', {
          message: 'You have been banned due to severe unsafe content.'
        });
        if (socket.partner) {
          socket.partner.emit('chatEnded');
          socket.partner.partner = null;
          partners.delete(socket.partner.id);
        }
        socket.partner = null;
        partners.delete(socket.id);
        socket.disconnect(true);
        return;
      }
    } catch (err) {
      console.error('Moderation error:', err);
    }
  });

  socket.on('joinChat', data => {
    // Accept both old (string) and new (object) join requests:
    let username, genderFilter, interestFilter;
    if (typeof data === 'string') {
      username = data;
      genderFilter = '';
      interestFilter = [];
    } else {
      username = data.username;
      genderFilter = data.genderFilter || '';
      interestFilter = data.interestFilter || [];
    }

    console.log(
      `👤 joinChat from ${username} (genderFilter=${genderFilter}, interests=${interestFilter.join(
        ', '
      )})`
    );

    if (!username) {
      socket.emit('error', { message: 'Username missing.' });
      return;
    }

    // 🔐 Enforce AI ban list before anything else
    if (isBanned(username)) {
      socket.emit('ai-banned', {
        message: 'Your account is banned due to unsafe content.'
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

    socket.username = username; // ensure set for gifts/moderation

    const isPremium =
      user.isPremium ||
      (user.paidFeatures && user.paidFeatures.filtersUnlocked);

    // Enforce premium filter gating server-side
    if (
      (genderFilter || (interestFilter && interestFilter.length > 0)) &&
      !isPremium
    ) {
      socket.emit('filter-locked', {
        message: 'Upgrade to premium to use gender/interest filters.'
      });
      return;
    }

    if (!waiting) {
      waiting = { socket, username, genderFilter, interestFilter, isPremium };
      socket.emit('waiting');
      return;
    }

    const partner = waiting;
    const partnerUser = users.find(u => u.username === partner.username);

    // Enforce block and filter compatibility before matching
    if (
      isBlocked(username, partner.username) ||
      (isPremium &&
        genderFilter &&
        partnerUser.gender !== genderFilter) ||
      (isPremium &&
        interestFilter.length > 0 &&
        (!partnerUser.interests ||
          !interestFilter.some(i =>
            partnerUser.interests.includes(i)
          )))
    ) {
      console.log(
        `🚫 ${username} and ${partner.username} incompatible (blocked or filter)`
      );
      waiting = { socket, username, genderFilter, interestFilter, isPremium };
      partner.socket.emit('waiting');
      socket.emit('waiting');
      return;
    }

    // Match success: pair the users
    waiting = null;
    socket.partner = partner.socket;
    partner.socket.partner = socket;
    partners.set(socket.id, partner.socket.id);
    partners.set(partner.socket.id, socket.id);

    socket.username = username;
    partner.socket.username = partner.username;

    socket.emit('matched', partner.username);
    partner.socket.emit('matched', username);
    socket.emit('start-webrtc', { initiator: true });
    partner.socket.emit('start-webrtc', { initiator: false });

    socket.on('chatMsg', msg => {
      if (socket.partner) socket.partner.emit('chatMsg', msg);
    });
    partner.socket.on('chatMsg', msg => {
      if (partner.socket.partner)
        partner.socket.partner.emit('chatMsg', msg);
    });

    socket.on('endChat', () => {
      if (socket.partner) {
        socket.partner.emit('chatEnded');
        socket.partner.partner = null;
        partners.delete(socket.partner.id);
      }
      socket.partner = null;
      partners.delete(socket.id);
      console.log(`❌ ${username} ended chat`);
    });

    partner.socket.on('endChat', () => {
      if (partner.socket.partner) {
        partner.socket.partner.emit('chatEnded');
        partner.socket.partner.partner = null;
        partners.delete(partner.socket.partner.id);
      }
      partner.socket.partner = null;
      partners.delete(partner.socket.id);
      console.log(`❌ ${partner.username} ended chat`);
    });
  });

  // ====== WEBRTC SIGNALING BETWEEN PARTNERS ======

  socket.on('webrtc-offer', data => {
    const partnerId = partners.get(socket.id);
    if (!partnerId) {
      console.log(
        '❌ No partner found for offer from',
        socket.username
      );
      return;
    }
    const partnerSocket = io.sockets.sockets.get(partnerId);
    if (!partnerSocket) {
      console.log(
        '❌ Partner socket not available for offer from',
        socket.username
      );
      return;
    }
    partnerSocket.emit('webrtc-offer', {
      offer: data.offer,
      from: socket.username
    });
  });

  socket.on('webrtc-answer', data => {
    const partnerId = partners.get(socket.id);
    if (!partnerId) {
      console.log(
        '❌ No partner found for answer from',
        socket.username
      );
      return;
    }
    const partnerSocket = io.sockets.sockets.get(partnerId);
    if (!partnerSocket) {
      console.log(
        '❌ Partner socket not available for answer from',
        socket.username
      );
      return;
    }
    partnerSocket.emit('webrtc-answer', {
      answer: data.answer,
      from: socket.username
    });
  });

  socket.on('webrtc-ice-candidate', data => {
    const partnerId = partners.get(socket.id);
    if (!partnerId) {
      console.log('❌ No partner found for ICE candidate from', socket.username);
      return;
    }
    const partnerSocket = io.sockets.sockets.get(partnerId);
    if (!partnerSocket) {
      console.log('❌ Partner socket not available for ICE from', socket.username);
      return;
    }
    partnerSocket.emit('webrtc-ice-candidate', {
      candidate: data.candidate,
      from: socket.username
    });
  });

  socket.on('disconnect', () => {
    console.log(`🔌 Disconnected: ${socket.id}`);
    if (waiting && waiting.socket === socket) {
      console.log(
        `⏳ Removed ${waiting.username} from waiting queue`
      );
      waiting = null;
    }
    if (socket.partner) {
      socket.partner.emit('chatEnded');
      socket.partner.partner = null;
      partners.delete(socket.partner.id);
    }
    partners.delete(socket.id);
  });
});

server.listen(port, () => {
  console.log(
    `✅ JOLT backend with WebRTC signaling running at http://localhost:${port}`
  );
  console.log('📡 Socket.IO transports: websocket, polling');
  console.log('⚠️ AI moderation EVENTS enabled, but analyzeFrame() still uses a stub. Plug in a real model when ready.');
});
