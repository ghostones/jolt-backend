// moderation.js
const axios = require('axios');
const vision = require('@google-cloud/vision');
const path = require('path');

// --- CONFIGURATION ---
const PERSPECTIVE_KEY = process.env.PERSPECTIVE_API_KEY; // API key from your .env or shell
const client = new vision.ImageAnnotatorClient({
  keyFilename: path.join(__dirname, 'google-credentials.json') // Path to service account JSON
});

// --- TEXT MODERATION ---
async function moderateText(text) {
  try {
    const req = {
      comment: { text },
      languages: ['en'],
      requestedAttributes: {
        TOXICITY: {}, INSULT: {}, PROFANITY: {}, THREAT: {}, SEVERE_TOXICITY: {}
      }
    };
    const r = await axios.post(
      `https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=${PERSPECTIVE_KEY}`,
      req
    );
    const s = r.data.attributeScores;
    // Block if any score hits threshold
    return (
      (s.TOXICITY && s.TOXICITY.summaryScore.value > 0.8) ||
      (s.INSULT && s.INSULT.summaryScore.value > 0.8) ||
      (s.PROFANITY && s.PROFANITY.summaryScore.value > 0.8) ||
      (s.THREAT && s.THREAT.summaryScore.value > 0.7) ||
      (s.SEVERE_TOXICITY && s.SEVERE_TOXICITY.summaryScore.value > 0.65)
    );
  } catch (e) {
    console.log("Text moderation error:", e.message);
    return false;
  }
}

// --- IMAGE MODERATION ---
async function moderateImageBase64(base64Image) {
  try {
    const [result] = await client.safeSearchDetection({
      image: { content: Buffer.from(base64Image, 'base64') }
    });
    const annotation = result.safeSearchAnnotation;
    return (
      annotation.adult === 'LIKELY' || annotation.adult === 'VERY_LIKELY' ||
      annotation.violence === 'LIKELY' || annotation.violence === 'VERY_LIKELY' ||
      annotation.racy === 'LIKELY' || annotation.racy === 'VERY_LIKELY'
    );
  } catch (e) {
    console.log("Image moderation error:", e.message);
    return false;
  }
}

module.exports = { moderateText, moderateImageBase64 };
