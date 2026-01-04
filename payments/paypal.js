const paypal = require('@paypal/checkout-server-sdk');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server');

/* =========================
   PAYPAL CLIENT
========================= */

function getPayPalClient() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.warn('⚠️ PayPal not initialized: missing env vars');
    return null;
  }

  const environment =
    process.env.PAYPAL_MODE === 'live'
      ? new paypal.core.LiveEnvironment(clientId, clientSecret)
      : new paypal.core.SandboxEnvironment(clientId, clientSecret);

  return new paypal.core.PayPalHttpClient(environment);
}

const paypalClient = getPayPalClient();

/* =========================
   ROUTES
========================= */

module.exports = function paypalRoutes(app, requireSession) {

  /* =========================
     1️⃣ CREATE ORDER
  ========================= */
  app.post('/payments/paypal/create-order', requireSession, async (req, res) => {
    if (!paypalClient) {
      return res.status(503).json({ message: 'PayPal not configured' });
    }

    const { plan } = req.body;
    const planConfig = plans[plan];

    if (!planConfig) {
      return res.status(400).json({ message: 'Invalid plan' });
    }

    try {
      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer('return=representation');
      request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [
          {
            amount: {
              currency_code: 'USD',
              value: planConfig.usd
            }
          }
        ]
      });

      const order = await paypalClient.execute(request);
      res.json({ orderId: order.result.id });

    } catch (err) {
      console.error('❌ PayPal create-order error:', err);
      res.status(500).json({ message: 'PayPal order creation failed' });
    }
  });

  /* =========================
     2️⃣ CAPTURE PAYMENT
  ========================= */
  app.post('/payments/paypal/capture', requireSession, async (req, res) => {
    if (!paypalClient) {
      return res.status(503).json({ message: 'PayPal not configured' });
    }

    const { orderId, plan } = req.body;
    const planConfig = plans[plan];

    if (!orderId || !planConfig || !planConfig.durationDays) {
      return res.status(400).json({ message: 'Invalid order or plan' });
    }

    try {
      const request = new paypal.orders.OrdersCaptureRequest(orderId);
      request.requestBody({});
      const capture = await paypalClient.execute(request);

      if (capture.result.status !== 'COMPLETED') {
        return res.status(400).json({ message: 'Payment not completed' });
      }

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
      res.status(500).json({ message: 'PayPal capture failed' });
    }
  });
};
