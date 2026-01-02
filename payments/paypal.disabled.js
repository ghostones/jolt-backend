const paypal = require('@paypal/checkout-server-sdk');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server-helpers');

function paypalClient() {
  const env =
    process.env.PAYPAL_MODE === 'live'
      ? new paypal.core.LiveEnvironment(
          process.env.PAYPAL_CLIENT_ID,
          process.env.PAYPAL_CLIENT_SECRET
        )
      : new paypal.core.SandboxEnvironment(
          process.env.PAYPAL_CLIENT_ID,
          process.env.PAYPAL_CLIENT_SECRET
        );

  return new paypal.core.PayPalHttpClient(env);
}

module.exports = function paypalRoutes(app, requireSession) {

  // 1️⃣ Create Order
  app.post('/payments/paypal/create-order', requireSession, async (req, res) => {
    const { plan } = req.body;
    if (!plans[plan]) {
      return res.status(400).json({ message: 'Invalid plan' });
    }

    const request = new paypal.orders.OrdersCreateRequest();
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [{
        amount: {
          currency_code: 'USD',
          value: plans[plan].usd
        }
      }]
    });

    const order = await paypalClient().execute(request);
    res.json({ orderId: order.result.id });
  });

  // 2️⃣ Capture Payment
  app.post('/payments/paypal/capture', requireSession, async (req, res) => {
    const { orderId } = req.body;

    const request = new paypal.orders.OrdersCaptureRequest(orderId);
    const capture = await paypalClient().execute(request);

    if (capture.result.status === 'COMPLETED') {
      const users = loadUsers();
      const user = users.find(u => u.username === req.username);
      user.isPremium = true;
      user.paidFeatures = { filtersUnlocked: true };
      saveUsers(users);

      return res.json({ message: 'Premium activated' });
    }

    res.status(400).json({ message: 'Payment not completed' });
  });
};
