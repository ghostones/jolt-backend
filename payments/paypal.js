const paypal = require('@paypal/checkout-server-sdk');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server');

/* =========================
   PAYPAL ENVIRONMENT
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

  // 1️⃣ Create Order
  app.post('/payments/paypal/create-order', requireSession, async (req, res) => {
    try {
      if (!paypalClient) {
        return res.status(503).json({ message: 'PayPal not configured' });
      }

      const { plan } = req.body;
      if (!plans[plan]) {
        return res.status(400).json({ message: 'Invalid plan' });
      }

      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer('return=representation');
      request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: 'USD',
            value: plans[plan].usd
          }
        }]
      });

      const order = await paypalClient.execute(request);
      res.json({ orderId: order.result.id });

    } catch (err) {
      console.error('PayPal create-order error:', err);
      res.status(500).json({ message: 'PayPal order failed' });
    }
  });

  // 2️⃣ Capture Payment
  app.post('/payments/paypal/capture', requireSession, async (req, res) => {
    try {
      if (!paypalClient) {
        return res.status(503).json({ message: 'PayPal not configured' });
      }

      const { orderId } = req.body;
      const request = new paypal.orders.OrdersCaptureRequest(orderId);
      request.requestBody({});

      await paypalClient.execute(request);

      // ✅ Activate Premium
      const users = loadUsers();
      const user = users.find(u => u.username === req.username);

      user.isPremium = true;
      user.paidFeatures = { filtersUnlocked: true };
      user.premiumUntil = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days

      saveUsers(users);

      res.json({ message: 'Premium activated' });

    } catch (err) {
      console.error('PayPal capture error:', err);
      res.status(500).json({ message: 'PayPal capture failed' });
    }
  });
};
