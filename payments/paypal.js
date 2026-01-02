const paypal = require('@paypal/checkout-server-sdk');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server');

/* =========================
   PAYPAL CLIENT
========================= */

function environment() {
  if (process.env.PAYPAL_MODE === 'live') {
    return new paypal.core.LiveEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET
    );
  }
  return new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
  );
}

const client = new paypal.core.PayPalHttpClient(environment());

/* =========================
   ROUTES
========================= */

module.exports = function paypalRoutes(app, requireSession) {

  // 1️⃣ Create PayPal Order
  app.post('/payments/paypal/create-order', requireSession, async (req, res) => {
    try {
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

      const order = await client.execute(request);
      res.json({ orderId: order.result.id });

    } catch (err) {
      console.error('PayPal create-order error:', err);
      res.status(500).json({ message: 'PayPal order failed' });
    }
  });

  // 2️⃣ Capture PayPal Payment
  app.post('/payments/paypal/capture', requireSession, async (req, res) => {
    try {
      const { orderId } = req.body;
      const request = new paypal.orders.OrdersCaptureRequest(orderId);
      request.requestBody({});

      await client.execute(request);

      // ✅ Activate premium (example: monthly)
      const users = loadUsers();
      const user = users.find(u => u.username === req.username);

      user.isPremium = true;
      user.paidFeatures = { filtersUnlocked: true };
      user.premiumUntil = Date.now() + (30 * 24 * 60 * 60 * 1000);

      saveUsers(users);

      res.json({ message: 'Premium activated' });

    } catch (err) {
      console.error('PayPal capture error:', err);
      res.status(500).json({ message: 'PayPal capture failed' });
    }
  });
};
