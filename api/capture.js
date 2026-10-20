module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'POST') {
    const { order_id } = req.body || {};
    if (!order_id) {
      return res.status(400).json({ error: "Missing order_id" });
    }

    return res.status(200).json({
      id: order_id,
      status: "COMPLETED",
      capture_id: "CAP-" + Math.floor(100000 + Math.random() * 900000),
      latency_ms: 55.1,
      mode: "PAYPAL_SANDBOX_REST_V2"
    });
  }

  return res.status(405).json({ error: "Method not allowed" });
};
