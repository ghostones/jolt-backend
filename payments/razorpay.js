const crypto = require('crypto');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../server');
const Razorpay = require('razorpay');

// ================================
// 🔐 SAFE RAZORPAY INITIALIZATION
// ================================
let razorpay = null;

if (
  process.env.RAZORPAY_KEY_ID &&
  process.env.RAZORPAY_KEY_SECRET
) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });
} else {
  console.warn('⚠️ Razorpay disabled (missing env vars)');
}

// ================================
// 🚀 EXPORT ROUTES ONLY
// ================================
module.exports = function razorpayRoutes(app, requireSession) {

  // ================================
  // 1️⃣ CREATE ORDER
  // ================================
  app.post(
    '/payments/razorpay/create-order',
    requireSession,
    async (req, res) => {
      if (!razorpay) {
        return res.status(503).json({
          message: 'Payments temporarily unavailable'
        });
      }

      const { plan } = req.body;
      const planConfig = plans[plan];

      if (!planConfig || !planConfig.inr) {
        return res.status(400).json({
          message: 'Invalid plan'
        });
      }

      try {
        const order = await razorpay.orders.create({
  amount: plans[plan].inr,
  currency: 'INR',
  receipt: `jolt_${req.username}_${Date.now()}`,
  notes: {
    username: req.username,
    plan
  }
});

        res.json({
          orderId: order.id,
          keyId: process.env.RAZORPAY_KEY_ID,
          amount: order.amount
        });
      } catch (err) {
        console.error('❌ Razorpay order error:', err);
        res.status(500).json({
          message: 'Order creation failed'
        });
      }
    }
  );

  // ================================
  // 2️⃣ VERIFY PAYMENT
  // ================================
  app.post(
    '/payments/razorpay/verify',
    requireSession,
    (req, res) => {
      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
        plan
      } = req.body;

      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature ||
        !plan
      ) {
        return res.status(400).json({
          message: 'Missing payment data'
        });
      }

      // 🔐 SIGNATURE VERIFICATION
      const body =
        razorpay_order_id + '|' + razorpay_payment_id;

      const expectedSignature = crypto
        .createHmac(
          'sha256',
          process.env.RAZORPAY_KEY_SECRET
        )
        .update(body)
        .digest('hex');

      if (expectedSignature !== razorpay_signature) {
        return res.status(400).json({
          message: 'Payment verification failed'
        });
      }

      // 🔐 PLAN VALIDATION
      const planConfig = plans[plan];
      if (
        !planConfig ||
        !Number.isInteger(planConfig.durationDays)
      ) {
        return res.status(400).json({
          message: 'Invalid plan'
        });
      }

      const users = loadUsers();
      const user = users.find(
        u => u.username === req.username
      );

      if (!user) {
        return res.status(404).json({
          message: 'User not found'
        });
      }

      // ================================
      // ✅ PREMIUM DURATION LOGIC
      // ================================
      const now = Date.now();
      const durationMs =
        planConfig.durationDays *
        24 *
        60 *
        60 *
        1000;

      if (
        user.premiumUntil &&
        user.premiumUntil > now
      ) {
        // 🔁 Renewal
        user.premiumUntil += durationMs;
      } else {
        // 🆕 Fresh purchase
        user.premiumUntil = now + durationMs;
      }

      user.isPremium = true;
      user.paidFeatures = {
        filtersUnlocked: true
      };

      saveUsers(users);

      res.json({
        message: 'Premium activated',
        premiumUntil: user.premiumUntil
      });
    }
  );
};
