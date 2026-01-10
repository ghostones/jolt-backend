const crypto = require('crypto');
const plans = require('./plans');
const { loadUsers, saveUsers } = require('../users');

module.exports = function razorpayWebhook(app) {

  app.post(
    '/payments/razorpay/webhook',
    require('express').raw({ type: 'application/json' }),
    (req, res) => {

      const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
      if (!secret) {
        return res.status(500).send('Webhook secret missing');
      }

      const signature = req.headers['x-razorpay-signature'];
      const body = req.body.toString();

      const expected = crypto
        .createHmac('sha256', secret)
        .update(body)
        .digest('hex');

      if (expected !== signature) {
        console.warn('⚠️ Razorpay webhook signature mismatch');
        return res.status(400).send('Invalid signature');
      }

      const payload = JSON.parse(body);

      // ✅ PAYMENT CAPTURED EVENT
      if (payload.event === 'payment.captured') {
        const payment = payload.payload.payment.entity;

        const notes = payment.notes || {};
        const username = notes.username;
        const planKey = notes.plan;

        if (!username || !plans[planKey]) {
          return res.status(200).send('Ignored');
        }

        const users = loadUsers();
        const user = users.find(u => u.username === username);

        if (!user) {
          return res.status(200).send('User not found');
        }

        const now = Date.now();
        const durationMs =
          plans[planKey].durationDays * 24 * 60 * 60 * 1000;

        if (user.premiumUntil && user.premiumUntil > now) {
          user.premiumUntil += durationMs;
        } else {
          user.premiumUntil = now + durationMs;
        }

        user.isPremium = true;
        user.paidFeatures = { filtersUnlocked: true };

        saveUsers(users);
      }

      res.status(200).json({ status: 'ok' });
    }
  );
};
