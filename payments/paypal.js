// Load environment variables
require('dotenv').config();

const paypal = require('@paypal/checkout-server-sdk');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../users');

/* =========================
   PAYPAL CLIENT
========================= */

let paypalClient = null;
let paypalEnabled = false;

function getPayPalClient() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  const mode = process.env.PAYPAL_MODE || 'sandbox'; // default to sandbox

  if (!clientId || !clientSecret) {
    console.warn('⚠️ PayPal not initialized - Missing environment variables');
    console.warn('   Required: PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET');
    console.warn('   Optional: PAYPAL_MODE (default: sandbox)');
    console.warn('   Add these to your .env file in jolt-backend directory');
    return null;
  }

  try {
    const environment =
      mode === 'live'
        ? new paypal.core.LiveEnvironment(clientId, clientSecret)
        : new paypal.core.SandboxEnvironment(clientId, clientSecret);

    const client = new paypal.core.PayPalHttpClient(environment);
    console.log(`✅ PayPal initialized successfully (${mode} mode)`);
    return client;
  } catch (error) {
    console.error('❌ PayPal initialization error:', error.message);
    return null;
  }
}

paypalClient = getPayPalClient();
paypalEnabled = !!paypalClient;

/* =========================
   ROUTES
========================= */

module.exports = function paypalRoutes(app, requireSession) {

  /* =========================
     1️⃣ CREATE ORDER
  ========================= */
  app.post('/payments/paypal/create-order', requireSession, async (req, res) => {
    if (!paypalClient || !paypalEnabled) {
      return res.status(503).json({ 
        message: 'PayPal payments are not configured. Please check server configuration.',
        error: 'PAYPAL_NOT_CONFIGURED'
      });
    }

    const { plan } = req.body;
    if (!plan) {
      return res.status(400).json({ message: 'Plan is required' });
    }

    const planConfig = plans[plan];

    if (!planConfig || !planConfig.usd) {
      return res.status(400).json({ message: 'Invalid plan selected' });
    }

    try {
      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer('return=representation');
      request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [
          {
            description: `${planConfig.label} Premium Plan`,
            amount: {
              currency_code: 'USD',
              value: planConfig.usd
            }
          }
        ]
      });

      const order = await paypalClient.execute(request);
      
      if (order.statusCode !== 201 || !order.result || !order.result.id) {
        throw new Error('Invalid order response from PayPal');
      }

      console.log('✅ PayPal order created:', order.result.id);

      res.json({ 
        orderId: order.result.id,
        status: order.result.status
      });

    } catch (err) {
      console.error('❌ PayPal create-order error:', err);
      const errorMessage = err.message || (err.response?.body?.message) || 'Unknown error';
      res.status(500).json({ 
        message: 'PayPal order creation failed: ' + errorMessage,
        error: 'ORDER_CREATION_FAILED'
      });
    }
  });

  /* =========================
     2️⃣ CAPTURE PAYMENT
  ========================= */
  app.post('/payments/paypal/capture', requireSession, async (req, res) => {
    if (!paypalClient || !paypalEnabled) {
      return res.status(503).json({ 
        message: 'PayPal payments are not configured. Please check server configuration.',
        error: 'PAYPAL_NOT_CONFIGURED'
      });
    }

    const { orderId, plan } = req.body;

    if (!orderId) {
      return res.status(400).json({ message: 'Order ID is required' });
    }

    if (!plan) {
      return res.status(400).json({ message: 'Plan is required' });
    }

    const planConfig = plans[plan];

    if (!planConfig || !planConfig.durationDays) {
      return res.status(400).json({ message: 'Invalid plan selected' });
    }

    try {
      const request = new paypal.orders.OrdersCaptureRequest(orderId);
      request.requestBody({});
      const capture = await paypalClient.execute(request);

      if (!capture.result || capture.result.status !== 'COMPLETED') {
        return res.status(400).json({ 
          message: 'Payment not completed. Status: ' + (capture.result?.status || 'Unknown'),
          error: 'PAYMENT_NOT_COMPLETED'
        });
      }

      console.log('✅ PayPal payment captured:', orderId);

      // ✅ APPLY PREMIUM (SAME AS RAZORPAY)
      const users = loadUsers();
      const user = users.find(u => u.username === req.username);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const now = Date.now();
      const durationMs =
        planConfig.durationDays * 24 * 60 * 60 * 1000;

      if (user.premiumUntil && user.premiumUntil > now) {
        user.premiumUntil += durationMs; // renewal
      } else {
        user.premiumUntil = now + durationMs; // fresh purchase
      }

      user.isPremium = true;
      user.paidFeatures = { filtersUnlocked: true };

      saveUsers(users);

      res.json({
        message: 'Premium activated',
        premiumUntil: user.premiumUntil
      });

    } catch (err) {
      console.error('❌ PayPal capture error:', err);
      const errorMessage = err.message || (err.response?.body?.message) || 'Unknown error';
      res.status(500).json({ 
        message: 'PayPal capture failed: ' + errorMessage,
        error: 'CAPTURE_FAILED'
      });
    }
  });
};
