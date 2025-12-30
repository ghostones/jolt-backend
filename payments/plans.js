// payments/plans.js
// Final market-tuned pricing (India-first) - values in paise for Razorpay

module.exports = {
  premium_weekly: {
    label: 'Weekly',
    inr: 10000,       // ₹100
    usd: '1.99',
    durationDays: 7
  },

  premium_monthly: {
    label: 'Monthly',
    inr: 24900,       // ₹249
    usd: '4.99',
    durationDays: 30
  },

  premium_quarterly: {
    label: 'Quarterly',
    inr: 64900,       // ₹649
    usd: '12.99',
    durationDays: 90
  },

  premium_half_yearly: {
    label: 'Half-Yearly',
    inr: 109900,      // ₹1099
    usd: '21.99',
    durationDays: 180
  },

  premium_yearly: {
    label: 'Yearly',
    inr: 179900,      // ₹1799
    usd: '34.99',
    durationDays: 365
  }
};
