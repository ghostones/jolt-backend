const crypto = require('crypto');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server');
const Razorpay = require("razorpay");

// ✅ Safe Razorpay initialization
let razorpay = null;

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.warn("⚠️ Razorpay not initialized: missing env vars");
} else {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
}

// ✅ Export ONLY routes
module.exports = function razorpayRoutes(app, requireSession) {

  // 1️⃣ Create Order
  app.post('/payments/razorpay/create-order', requireSession, async (req, res) => {
    if (!razorpay) {
      return res.status(503).json({ message: "Payments unavailable" });
    }

    const { plan } = req.body;
    if (!plans[plan]) {
      return res.status(400).json({ message: 'Invalid plan' });
    }

    try {
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
    } catch (err) {
      console.error("Razorpay order error:", err);
      res.status(500).json({ message: "Order creation failed" });
    }
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

    const users = loadUsers();
    const user = users.find(u => u.username === req.username);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // ✅ Unlock premium (FIXED logic)
    user.isPremium = true;
    user.paidFeatures = { filtersUnlocked: true };
    user.premiumUntil = Date.now() + (365 * 24 * 60 * 60 * 1000); // 1 year

    saveUsers(users);

    res.json({ message: 'Premium activated' });
  });
};
