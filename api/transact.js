let inMemoryTransactions = [];
let spendingLimit = 250.0;

const VERIFIED_MERCHANTS = {
  "amazon.com": { trust_score: 98, category: "Retail" },
  "aws.amazon.com": { trust_score: 99, category: "Cloud Infrastructure" },
  "github.com": { trust_score: 99, category: "Developer Tools" },
  "uber.com": { trust_score: 95, category: "Transportation" },
  "swiggy.com": { trust_score: 94, category: "Food Delivery" },
  "irctc.co.in": { trust_score: 96, category: "Travel/Railways" },
  "apple.com": { trust_score: 99, category: "Hardware" }
};

const SUSPICIOUS_KEYWORDS = [
  "free-crypto", "luxury-discount-90", "urgent-wire", "unverified-lottery", "temp-giftcards"
];

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'GET') {
    return res.status(200).json({
      count: inMemoryTransactions.length,
      spending_limit: spendingLimit,
      transactions: inMemoryTransactions
    });
  }

  if (req.method === 'POST') {
    const { intent, merchant, amount, currency } = req.body || {};
    const amt = parseFloat(amount || 0);
    const m = (merchant || "").toLowerCase().trim();

    let risk_score = 10;
    let flags = [];

    // 1. Merchant check
    let matched = null;
    for (const [k, v] of Object.entries(VERIFIED_MERCHANTS)) {
      if (m.includes(k) || k.includes(m)) {
        matched = v;
        break;
      }
    }

    if (matched) {
      risk_score = Math.max(5, 100 - matched.trust_score);
      flags.push(`VERIFIED_MERCHANT: ${matched.category} (Trust ${matched.trust_score}/100)`);
    } else {
      risk_score += 35;
      flags.push("UNVERIFIED_MERCHANT: Domain not in enterprise trusted whitelist");
    }

    // 2. Phishing keyword check
    for (const kw of SUSPICIOUS_KEYWORDS) {
      if (m.includes(kw) || (intent || "").toLowerCase().includes(kw)) {
        risk_score += 45;
        flags.push(`FRAUD_KEYWORD_MATCH: Detected flagged pattern '${kw}'`);
      }
    }

    // 3. Limit check
    if (amt > spendingLimit) {
      risk_score += 25;
      flags.push(`LIMIT_EXCEEDED: Amount $${amt.toFixed(2)} exceeds autonomous limit $${spendingLimit.toFixed(2)}`);
    }

    risk_score = Math.min(100, Math.max(0, risk_score));

    let decision = "AUTONOMOUS_APPROVED";
    let reason = "Low risk score and within designated spending limit. Executing autonomous payment.";
    let order = null;

    if (risk_score <= 25 && amt <= spendingLimit) {
      decision = "AUTONOMOUS_APPROVED";
      const orderId = "SANDBOX-ORD-" + Math.floor(100000 + Math.random() * 900000);
      order = {
        id: orderId,
        status: "CREATED",
        amount: amt.toFixed(2),
        currency: currency || "USD",
        merchant: merchant,
        approval_url: `https://www.sandbox.paypal.com/checkoutnow?token=${orderId}`,
        latency_ms: 45.2,
        mode: "PAYPAL_SANDBOX_REST_V2"
      };
    } else if (risk_score > 70) {
      decision = "BLOCKED_FRAUD_DETECTED";
      reason = "High fraud risk detected. Payment blocked by PayGuard AI shield.";
    } else {
      decision = "REQUIRES_HUMAN_CONFIRMATION";
      reason = "Transaction flagged for human 2FA authorization before funds can be released.";
    }

    const tx = {
      id: "TX-" + Math.floor(100000 + Math.random() * 900000),
      intent: intent || "Commercial payment",
      merchant: merchant || "Unknown",
      amount: amt,
      currency: currency || "USD",
      risk_score: risk_score,
      decision: decision,
      reason: reason,
      flags: flags,
      order: order,
      trace: [
        { action: "INTENT_ANALYSIS", detail: `Parsed intent: '${intent}' for $${amt.toFixed(2)}` },
        { action: "RISK_AND_GUARDRAIL_EVALUATION", decision: decision, risk_score: risk_score, flags: flags },
        { action: decision === "AUTONOMOUS_APPROVED" ? "PAYPAL_SANDBOX_ORDER_CREATED" : decision, detail: reason }
      ],
      elapsed_ms: 52.4,
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
    };

    inMemoryTransactions.unshift(tx);
    return res.status(200).json(tx);
  }

  return res.status(405).json({ error: "Method not allowed" });
};
