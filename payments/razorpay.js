const Razorpay = require('razorpay');
const crypto = require('crypto');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server');
// (we’ll explain this import below)

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

module.exports = function razorpayRoutes(app, requireSession) {

  // 1️⃣ Create Order
  app.post('/payments/razorpay/create-order', requireSession, async (req, res) => {
    const { plan } = req.body;
    if (!plans[plan]) {
      return res.status(400).json({ message: 'Invalid plan' });
    }

    const order = await razorpay.orders.create({
      amount: plans[plan].inr,
      currency: 'INR',
      receipt: `jolt_${req.username}_${Date.now()}`
    });

    res.json({
      orderId: order.id,
      keyId: process.env.RAZORPAY_KEY_ID,
      amount: order.amount
    });
  });

  // 2️⃣ Verify Payment
  app.post('/payments/razorpay/verify', requireSession, (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expected !== razorpay_signature) {
      return res.status(400).json({ message: 'Payment verification failed' });
    }

    // ✅ Unlock premium
    const users = loadUsers();
    const user = users.find(u => u.username === req.username);
    user.isPremium = true;
user.paidFeatures = { filtersUnlocked: true };
user.premiumUntil = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days
user.premiumUntil = Date.now() + (365 * 24 * 60 * 60 * 1000); // 1 year
    saveUsers(users);

    res.json({ message: 'Premium activated' });
  });
};
