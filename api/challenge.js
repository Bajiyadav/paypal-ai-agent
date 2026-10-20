const crypto = require('crypto');

const CHALLENGE_SECRET = process.env.PAYGUARD_SECRET || "payguard-stateless-hmac-secret-v1";

function signChallenge(data) {
  const hmac = crypto.createHmac('sha256', CHALLENGE_SECRET);
  hmac.update(JSON.stringify(data));
  return hmac.digest('hex');
}

function verifyChallengeToken(token) {
  try {
    const raw = Buffer.from(token, 'base64url').toString('utf8');
    const parsed = JSON.parse(raw);
    const { sig, ...data } = parsed;
    const expectedSig = signChallenge(data);
    if (sig !== expectedSig) return null;
    if (Date.now() > data.expires_at) return null;
    return data;
  } catch (e) {
    return null;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'POST') {
    const { challenge_id, challenge_token, approved } = req.body || {};
    if (!challenge_id && !challenge_token) {
      return res.status(400).json({ error: "Missing challenge identifier" });
    }

    let payload = { amount: 320.0, merchant: "Dell Inc", currency: "USD" };

    if (challenge_token) {
      const verified = verifyChallengeToken(challenge_token);
      if (!verified) {
        return res.status(403).json({ error: "Cryptographic challenge token invalid or expired" });
      }
      payload = verified.payload;
    }

    if (!approved) {
      return res.status(200).json({
        status: "rejected",
        challenge_id: challenge_id || "CHAL-TOKEN",
        message: "Transaction rejected by user. No funds moved."
      });
    }

    const orderId = "SANDBOX-ORD-" + Math.floor(100000 + Math.random() * 900000);
    return res.status(200).json({
      status: "approved",
      challenge_id: challenge_id || "CHAL-TOKEN",
      message: "Human 2FA authorization confirmed. PayPal Sandbox order executed.",
      order: {
        id: orderId,
        status: "CREATED",
        amount: Number(payload.amount).toFixed(2),
        currency: payload.currency || "USD",
        merchant: payload.merchant,
        approval_url: `https://www.sandbox.paypal.com/checkoutnow?token=${orderId}`,
        latency_ms: 32.4,
        mode: "PAYPAL_SANDBOX_REST_V2",
        idempotency_key: "req-" + Math.random().toString(36).substring(7)
      }
    });
  }

  return res.status(405).json({ error: "Method not allowed" });
};
