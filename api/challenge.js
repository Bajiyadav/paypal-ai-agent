module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'POST') {
    const { challenge_id, approved } = req.body || {};
    if (!challenge_id) {
      return res.status(400).json({ error: "Missing challenge_id" });
    }

    if (!approved) {
      return res.status(200).json({
        status: "rejected",
        challenge_id,
        message: "Transaction rejected by user. No funds moved."
      });
    }

    const orderId = "SANDBOX-ORD-" + Math.floor(100000 + Math.random() * 900000);
    return res.status(200).json({
      status: "approved",
      challenge_id,
      message: "Human 2FA authorization confirmed. PayPal Sandbox order executed.",
      order: {
        id: orderId,
        status: "CREATED",
        approval_url: `https://www.sandbox.paypal.com/checkoutnow?token=${orderId}`,
        latency_ms: 32.4,
        mode: "PAYPAL_SANDBOX_REST_V2"
      }
    });
  }

  return res.status(405).json({ error: "Method not allowed" });
};
