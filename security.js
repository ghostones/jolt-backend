/**
 * Security Module
 * API Request Signing, Encryption, and Validation
 */

const crypto = require('crypto');

// API Client Secret (should match frontend api-config.js)
// Set via: API_CLIENT_SECRET=your-secret-key npm start
const API_CLIENT_SECRET = process.env.API_CLIENT_SECRET || 'joltclientsecret';

// Request signing using HMAC
function signRequest(payload, timestamp, nonce) {
  const data = JSON.stringify(payload) + timestamp + nonce;
  return crypto.createHmac('sha256', API_CLIENT_SECRET).update(data).digest('hex');
}

function verifyRequestSignature(payload, timestamp, nonce, signature, maxAge = 60000) {
  // Check timestamp (prevent replay attacks)
  const now = Date.now();
  if (Math.abs(now - timestamp) > maxAge) {
    return { valid: false, reason: 'Request expired' };
  }

  // Verify signature
  const expectedSignature = signRequest(payload, timestamp, nonce);
  if (signature.length !== expectedSignature.length) {
    return { valid: false, reason: 'Invalid signature length' };
  }
  
  const isValid = crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );

  return { valid: isValid, reason: isValid ? 'valid' : 'Invalid signature' };
}

// Simple payload encryption (for sensitive data)
function encryptPayload(data, secret = API_CLIENT_SECRET) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    data: encrypted,
    iv: iv.toString('hex')
  };
}

function decryptPayload(encryptedData, iv, secret = API_CLIENT_SECRET) {
  try {
    const key = crypto.createHash('sha256').update(secret).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  } catch (err) {
    return null;
  }
}

// Generate API key for requests
function generateApiKey() {
  return crypto.randomBytes(32).toString('base64');
}

// Validate API key format
function isValidApiKey(key) {
  return key && typeof key === 'string' && key.length >= 32;
}

module.exports = {
  signRequest,
  verifyRequestSignature,
  encryptPayload,
  decryptPayload,
  generateApiKey,
  isValidApiKey,
  API_CLIENT_SECRET
};
