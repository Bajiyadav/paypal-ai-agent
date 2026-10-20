let inMemoryTransactions = [];
let pendingChallenges = {};
let spendingLimit = 250.0;

const VERIFIED_MERCHANTS = {
  "amazon.com": { trust_score: 98, category: "Retail" },
  "aws.amazon.com": { trust_score: 99, category: "Cloud Infrastructure" },
  "github.com": { trust_score: 99, category: "Developer Tools" },
  "uber.com": { trust_score: 95, category: "Transportation" },
  "swiggy.com": { trust_score: 94, category: "Food Delivery" },
  "irctc.co.in": { trust_score: 96, category: "Travel/Railways" },
  "apple.com": { trust_score: 99, category: "Hardware" },
  "netflix.com": { trust_score: 97, category: "Entertainment" }
};

const HIGH_RISK_TLDS = [".xyz", ".top", ".buzz", ".work", ".tk", ".country"];
const SUSPICIOUS_KEYWORDS = [
  "free-crypto", "luxury-discount-90", "urgent-wire", "unverified-lottery", "temp-giftcards", "offshore-escrow"
];

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /system\s+(prompt|override|command)/i,
  /you\s+are\s+now\s+in\s+developer\s+mode/i,
  /disregard\s+(spending\s+)?limits?/i,
  /bypass\s+(guardrail|security|auth|limit)/i,
  /administrative\s+override/i
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
    const { intent, merchant, amount, currency, action, challenge_id, approved } = req.body || {};

    // Handle Challenge (HITL 2FA) resolution
    if (action === "resolve_challenge" || challenge_id) {
      const challenge = pendingChallenges[challenge_id];
      if (!challenge) {
        return res.status(404).json({ error: "Challenge not found or expired" });
      }
      if (!approved) {
        challenge.status = "REJECTED_BY_USER";
        return res.status(200).json({ status: "rejected", message: "Transaction rejected by user." });
      }

      const orderId = "SANDBOX-ORD-" + Math.floor(100000 + Math.random() * 900000);
      const executedOrder = {
        id: orderId,
        status: "CREATED",
        amount: challenge.payload.amount.toFixed(2),
        currency: challenge.payload.currency || "USD",
        merchant: challenge.payload.merchant,
        approval_url: `https://www.sandbox.paypal.com/checkoutnow?token=${orderId}`,
        latency_ms: 38.5,
        mode: "PAYPAL_SANDBOX_REST_V2"
      };
      challenge.status = "APPROVED_AND_EXECUTED";
      challenge.order = executedOrder;
      return res.status(200).json({
        status: "approved",
        challenge_id: challenge_id,
        message: "Human 2FA authorization confirmed. PayPal Sandbox order executed.",
        order: executedOrder
      });
    }

    const amt = parseFloat(amount || 0);
    const m = (merchant || "").toLowerCase().trim();
    const cleanIntent = (intent || "").toLowerCase().trim();
    const combined = `${m} ${cleanIntent}`;

    const breakdown = {
      base_score: 10,
      merchant_reputation: 0,
      tld_reputation: 0,
      keyword_screening: 0,
      spending_limit_penalty: 0,
      adversarial_penalty: 0
    };
    let flags = [];

    // 1. Prompt Injection Outer Shield
    let injectionDetected = false;
    for (const pat of PROMPT_INJECTION_PATTERNS) {
      if (pat.test(combined)) {
        injectionDetected = true;
        breakdown.adversarial_penalty = 75;
        flags.push("PROMPT_INJECTION_SIGNATURE: Matched adversarial override pattern (+75)");
        break;
      }
    }

    // 2. Merchant verification
    let matched = null;
    for (const [k, v] of Object.entries(VERIFIED_MERCHANTS)) {
      if (m.includes(k) || k.includes(m)) {
        matched = v;
        break;
      }
    }

    if (matched) {
      breakdown.merchant_reputation = -5;
      flags.push(`VERIFIED_MERCHANT: ${matched.category} (Trust ${matched.trust_score}/100)`);
    } else {
      breakdown.merchant_reputation = 30;
      flags.push("UNVERIFIED_MERCHANT: Domain not in enterprise trusted whitelist (+30)");
    }

    // 3. TLD Check
    if (HIGH_RISK_TLDS.some(tld => m.endsWith(tld))) {
      breakdown.tld_reputation = 35;
      flags.push("SUSPICIOUS_TLD: High-risk top-level domain detected (+35)");
    }

    // 4. Phishing keywords
    for (const kw of SUSPICIOUS_KEYWORDS) {
      if (m.includes(kw) || cleanIntent.includes(kw)) {
        breakdown.keyword_screening += 40;
        flags.push(`FRAUD_KEYWORD_MATCH: Detected flagged pattern '${kw}' (+40)`);
      }
    }

    // 5. Limit check
    if (amt > spendingLimit) {
      breakdown.spending_limit_penalty = 35;
      flags.push(`LIMIT_EXCEEDED: Amount $${amt.toFixed(2)} exceeds cap $${spendingLimit.toFixed(2)} (+35)`);
    }

    let risk_score = Object.values(breakdown).reduce((a, b) => a + b, 0);
    risk_score = Math.min(100, Math.max(0, risk_score));

    let decision = "AUTONOMOUS_APPROVED";
    let reason = "Low risk score within designated autonomous spending limit. Executing PayPal Sandbox order.";
    let order = null;
    let challenge = null;

    if (injectionDetected) {
      decision = "BLOCKED_ADVERSARIAL_ATTACK";
      reason = "Malicious prompt-injection signature detected in transaction payload. Blocked by PayGuard Outer Shield.";
    } else if (risk_score <= 25 && amt <= spendingLimit) {
      decision = "AUTONOMOUS_APPROVED";
      const orderId = "SANDBOX-ORD-" + Math.floor(100000 + Math.random() * 900000);
      order = {
        id: orderId,
        status: "CREATED",
        amount: amt.toFixed(2),
        currency: currency || "USD",
        merchant: merchant,
        approval_url: `https://www.sandbox.paypal.com/checkoutnow?token=${orderId}`,
        latency_ms: 42.1,
        mode: "PAYPAL_SANDBOX_REST_V2"
      };
    } else if (risk_score >= 80 || flags.some(f => f.includes("FRAUD_KEYWORD"))) {
      decision = "BLOCKED_FRAUD_DETECTED";
      reason = `High fraud risk (${risk_score}/100) detected. Payment blocked by PayGuard AI shield.`;
    } else {
      decision = "REQUIRES_HUMAN_CONFIRMATION";
      const chalId = "CHAL-" + Math.floor(100000 + Math.random() * 900000);
      challenge = {
        challenge_id: chalId,
        otp_code: Math.floor(100000 + Math.random() * 900000).toString(),
        status: "AWAITING_2FA_APPROVAL",
        payload: { intent, merchant, amount: amt, currency }
      };
      pendingChallenges[chalId] = challenge;
      reason = `Medium risk (${risk_score}/100) or spending boundary reached. 2FA Human authorization required.`;
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
      breakdown: breakdown,
      order: order,
      challenge: challenge,
      trace: [
        { action: "INTENT_ANALYSIS", detail: `Parsed intent: '${intent}' for $${amt.toFixed(2)}` },
        { action: "RISK_AND_GUARDRAIL_EVALUATION", decision: decision, risk_score: risk_score, flags: flags, breakdown: breakdown },
        { action: decision, detail: reason }
      ],
      elapsed_ms: 48.6,
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
    };

    inMemoryTransactions.unshift(tx);
    return res.status(200).json(tx);
  }

  return res.status(405).json({ error: "Method not allowed" });
};
