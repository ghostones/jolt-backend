const { ImageAnnotatorClient } = require('@google-cloud/vision');
const path = require('path');
const fs = require('fs');

// Config file for moderation settings
const configFile = path.join(__dirname, 'config.json');

// Default thresholds/messages if config missing
const DEFAULT_CONFIG = {
  thresholds: {
    SAFE_MAX: 0.3,
    SUGGESTIVE_MAX: 0.5,
    PARTIAL_MAX: 0.7,
    EXPLICIT_MAX: 0.85,
    SEVERE_MAX: 0.95,
    ILLEGAL: 0.95
  },
  warnings: {
    SUGGESTIVE: "Please ensure appropriate attire. Continued violations may result in restrictions.",
    PARTIAL: "Partial nudity detected. Please cover up or your session will be ended.",
    EXPLICIT: "Explicit content detected. You have been removed from this chat.",
    SEVERE: "Severe NSFW content detected. You have been temporarily banned for 1 hour.",
    ILLEGAL: "Illegal content detected. Your account has been permanently banned and authorities notified."
  }
};

// Helper to load config
function loadConfig() {
  try {
    if (fs.existsSync(configFile)) {
      const raw = fs.readFileSync(configFile, 'utf8');
      const parsed = JSON.parse(raw);
      // Deep merge with DEFAULT_CONFIG for safety
      return {
        thresholds: { ...DEFAULT_CONFIG.thresholds, ...(parsed.thresholds || {}) },
        warnings: { ...DEFAULT_CONFIG.warnings, ...(parsed.warnings || {}) }
      };
    }
  } catch (e) {}
  return DEFAULT_CONFIG;
}

const vision = new ImageAnnotatorClient({
  keyFilename: path.join(__dirname, 'google-credentials.json')
});

// Severity levels mapped to integer for use as key
const SEVERITY = {
  SAFE: 0,
  SUGGESTIVE: 1,
  PARTIAL: 2,
  EXPLICIT: 3,
  SEVERE: 4,
  ILLEGAL: 5
};

class SmartModeration {
  constructor() {
    this.userStrikes = new Map();
    this.tempBans = new Map();
  }
  getCurrentConfig() {
    return loadConfig();
  }

  isTemporarilyBanned(username) {
    const banExpiry = this.tempBans.get(username);
    if (!banExpiry) return false;
    if (Date.now() > banExpiry) {
      this.tempBans.delete(username);
      return false;
    }
    return true;
  }
  applyTempBan(username, durationMs = 3600000) {
    const expiryTime = Date.now() + durationMs;
    this.tempBans.set(username, expiryTime);
    console.log(`⏰ ${username} temp banned until ${new Date(expiryTime).toLocaleString()}`);
  }
  addStrike(username, severity) {
    const strikes = this.userStrikes.get(username) || { count: 0, history: [] };
    strikes.count++;
    strikes.history.push({
      severity,
      timestamp: Date.now()
    });
    this.userStrikes.set(username, strikes);
    return strikes.count;
  }

  async analyzeImage(imagePath) {
    try {
      const [result] = await vision.safeSearchDetection(imagePath);
      const detections = result.safeSearchAnnotation;
      const scoreMap = {
        'VERY_UNLIKELY': 0.1,
        'UNLIKELY': 0.3,
        'POSSIBLE': 0.5,
        'LIKELY': 0.7,
        'VERY_LIKELY': 0.9
      };

      const adultScore = scoreMap[detections.adult] || 0;
      const racyScore = scoreMap[detections.racy] || 0;
      const violenceScore = scoreMap[detections.violence] || 0;
      const compositeScore = (adultScore * 0.6) + (racyScore * 0.3) + (violenceScore * 0.1);

      return {
        adult: detections.adult,
        racy: detections.racy,
        violence: detections.violence,
        medical: detections.medical,
        compositeScore,
        raw: detections
      };
    } catch (error) {
      console.error('Vision API error:', error);
      return null;
    }
  }

  // Load threshold values at evaluation time (live reconfigurable)
  getSeverity(score) {
    const { thresholds } = this.getCurrentConfig();
    if (score < thresholds.SAFE_MAX) return SEVERITY.SAFE;
    if (score < thresholds.SUGGESTIVE_MAX) return SEVERITY.SUGGESTIVE;
    if (score < thresholds.PARTIAL_MAX) return SEVERITY.PARTIAL;
    if (score < thresholds.EXPLICIT_MAX) return SEVERITY.EXPLICIT;
    if (score < thresholds.SEVERE_MAX) return SEVERITY.SEVERE;
    return SEVERITY.ILLEGAL;
  }

  getAction(severity, strikeCount) {
    const { warnings } = this.getCurrentConfig();
    switch(severity) {
      case SEVERITY.SAFE:
        return { action: 'allow', message: null };
      case SEVERITY.SUGGESTIVE:
        return { action: 'warn', message: warnings.SUGGESTIVE, disconnect: false };
      case SEVERITY.PARTIAL:
        if (strikeCount >= 2) {
          return { action: 'kick', message: "Multiple warnings ignored. Disconnected from chat.", disconnect: true };
        }
        return { action: 'warn', message: warnings.PARTIAL, disconnect: false };
      case SEVERITY.EXPLICIT:
        return { action: 'kick', message: warnings.EXPLICIT, disconnect: true };
      case SEVERITY.SEVERE:
        return { action: 'tempban', message: warnings.SEVERE, disconnect: true, banDuration: 3600000 };
      case SEVERITY.ILLEGAL:
        return { action: 'permban', message: warnings.ILLEGAL, disconnect: true, reportAuthorities: true };
      default:
        return { action: 'allow', message: null };
    }
  }

  async moderateFrame(username, imagePath) {
    if (this.isTemporarilyBanned(username)) {
      return { allowed: false, action: 'reject', message: 'You are temporarily banned. Please try again later.' };
    }
    const analysis = await this.analyzeImage(imagePath);
    if (!analysis) {
      console.error('Failed to analyze image');
      return { allowed: true };
    }
    const severity = this.getSeverity(analysis.compositeScore);
    const strikeCount = this.addStrike(username, severity);
    const action = this.getAction(severity, strikeCount);

    console.log(`🔍 ${username} - Score: ${analysis.compositeScore.toFixed(2)}, Severity: ${severity}, Strikes: ${strikeCount}`);

    if (action.action === 'tempban') {
      this.applyTempBan(username, action.banDuration);
    }
    return {
      allowed: action.action === 'allow' || action.action === 'warn',
      action: action.action,
      message: action.message,
      disconnect: action.disconnect || false,
      severity,
      score: analysis.compositeScore,
      details: analysis.raw,
      reportAuthorities: action.reportAuthorities || false
    };
  }
}

module.exports = new SmartModeration();
