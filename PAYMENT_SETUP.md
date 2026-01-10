# Payment Gateway Setup Guide

This guide will help you set up Razorpay and PayPal payment gateways for JOLT.

## Prerequisites

1. Node.js installed (v20.x)
2. npm installed
3. Razorpay account (for Indian payments)
4. PayPal Developer account (for international payments)

## Installation

1. Install dependencies:
```bash
npm install
```

The `dotenv` package is already included in package.json and will be installed.

## Environment Variables Setup

Create a `.env` file in the `jolt-backend` directory with the following variables:

### Required Variables

```env
# Razorpay Configuration (for Indian payments)
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret

# PayPal Configuration (for international payments)
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret
PAYPAL_MODE=sandbox
```

### Optional Variables

```env
# Server Configuration
PORT=1234
NODE_ENV=development

# Security
API_CLIENT_SECRET=joltclientsecret
REQUIRE_API_SIGNATURE=false

# AI Moderation (Optional)
MODERATION_ENABLED=false
PERSPECTIVE_API_KEY=your_perspective_api_key

# Debug Mode
DEBUG=false
```

## Getting Razorpay Keys

1. Go to https://razorpay.com/
2. Sign up or log in to your account
3. Navigate to **Settings** → **API Keys**
4. Generate **Test Keys** for development
5. Copy the **Key ID** and **Key Secret**
6. Add them to your `.env` file:
   ```
   RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxxxxx
   RAZORPAY_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxx
   ```
7. For production, generate **Live Keys** and update the values

## Getting PayPal Keys

1. Go to https://developer.paypal.com/
2. Sign up or log in to your account
3. Navigate to **Dashboard** → **My Apps & Credentials**
4. Click **Create App**
5. Choose **Sandbox** for testing or **Live** for production
6. Copy the **Client ID** and **Secret**
7. Add them to your `.env` file:
   ```
   PAYPAL_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   PAYPAL_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   PAYPAL_MODE=sandbox
   ```
8. For production, set `PAYPAL_MODE=live`

## Testing the Setup

1. Start the backend server:
   ```bash
   npm start
   ```

2. Check the console output:
   - ✅ Razorpay initialized successfully (if keys are set)
   - ✅ PayPal initialized successfully (sandbox mode) (if keys are set)
   - ⚠️ Razorpay disabled - Missing environment variables (if keys are missing)

3. Test payments:
   - Use Razorpay test cards: https://razorpay.com/docs/payments/test-cards/
   - Use PayPal sandbox: https://developer.paypal.com/docs/paypal-plus/test-with-paypal/

## Payment Flow

### Razorpay Flow:
1. User selects a plan and clicks "Pay with Razorpay"
2. Frontend calls `/payments/razorpay/create-order`
3. Razorpay checkout window opens
4. User completes payment
5. Frontend calls `/payments/razorpay/verify` with payment details
6. Backend verifies signature and activates premium

### PayPal Flow:
1. User selects a plan and clicks "Pay with PayPal"
2. Frontend calls `/payments/paypal/create-order`
3. PayPal payment window opens (or API flow)
4. User completes payment
5. Frontend calls `/payments/paypal/capture` with order ID
6. Backend captures payment and activates premium

## Troubleshooting

### Payment gateway not working

1. **Check environment variables:**
   - Make sure `.env` file exists in `jolt-backend` directory
   - Verify all required keys are present
   - Check for typos in variable names

2. **Check console logs:**
   - Look for initialization messages when server starts
   - Check for error messages in payment routes

3. **Test API keys:**
   - Razorpay: Use test mode with test keys
   - PayPal: Use sandbox mode with sandbox credentials

### Common Errors

- **"Payments temporarily unavailable"**: Check if environment variables are set correctly
- **"Order creation failed"**: Verify API keys are correct and have proper permissions
- **"Payment verification failed"**: Check if payment was actually completed

## Security Notes

1. **Never commit `.env` file** to version control
2. Use **test/sandbox** keys during development
3. Use **live** keys only in production
4. Keep your keys secure and rotate them periodically
5. Use HTTPS in production for secure payment processing

## Support

For payment gateway issues:
- Razorpay: https://razorpay.com/support/
- PayPal: https://developer.paypal.com/support/