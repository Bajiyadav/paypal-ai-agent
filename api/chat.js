module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { message } = req.body || {};
  const msg = (message || "").toLowerCase();

  let reply = "PayGuard AI is monitoring all autonomous transactions. How can I assist you with your payments?";

  if (msg.includes("limit") || msg.includes("cap")) {
    reply = "Your autonomous spending limit is currently set to **$250.00 USD**. Any transaction exceeding this limit requires human 2FA confirmation.";
  } else if (msg.includes("fraud") || msg.includes("risk") || msg.includes("protect")) {
    reply = "PayGuard AI evaluates risk using merchant domain reputation, SSL validation, duplicate charge analysis, and flagged phishing patterns before creating any PayPal order.";
  } else if (msg.includes("paypal") || msg.includes("api") || msg.includes("sandbox")) {
    reply = "PayGuard connects directly to the **PayPal Developer Sandbox REST API** (`/v2/checkout/orders` and `/v1/payments/payouts`), supporting instant OAuth2 bearer authentication, order creation, and capture.";
  }

  res.status(200).json({
    reply: reply,
    source: "PayGuard AI Copilot"
  });
};
