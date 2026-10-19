module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  res.status(200).json({
    status: "healthy",
    service: "PayGuard AI Agentic Commerce Core",
    version: "1.0.0",
    spending_limit_usd: 250.0,
    paypal_environment: "Sandbox",
    mode: "Vercel Edge Serverless"
  });
};
