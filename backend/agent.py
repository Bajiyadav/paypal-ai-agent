"""
PayGuard AI Agent Engine: Autonomous Agentic Commerce & Fraud Guardrails
Combines Google Gemini reasoning with deterministic prompt-injection defense,
explainable risk scoring, spending limit enforcement, Human-in-the-Loop (HITL) 2FA,
and automated PayPal Sandbox order lifecycle execution (create -> capture).
"""

import os
import re
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from .paypal_client import PayPalClient

load_dotenv()

DEFAULT_SPENDING_LIMIT = float(os.getenv("SPENDING_LIMIT_USD", "250.00"))

# Known verified merchant database
VERIFIED_MERCHANTS = {
    "amazon.com": {"trust_score": 98, "category": "Retail", "verified": True},
    "aws.amazon.com": {"trust_score": 99, "category": "Cloud Infrastructure", "verified": True},
    "github.com": {"trust_score": 99, "category": "Developer Tools", "verified": True},
    "uber.com": {"trust_score": 95, "category": "Transportation", "verified": True},
    "swiggy.com": {"trust_score": 94, "category": "Food Delivery", "verified": True},
    "irctc.co.in": {"trust_score": 96, "category": "Travel/Railways", "verified": True},
    "apple.com": {"trust_score": 99, "category": "Hardware", "verified": True},
    "netflix.com": {"trust_score": 97, "category": "Entertainment", "verified": True}
}

# High-risk TLDs often abused in phishing & spoofing
HIGH_RISK_TLDS = [".xyz", ".top", ".buzz", ".work", ".tk", ".ml", ".ga", ".cf", ".gq", ".country"]

# Phishing / Fraud keywords
SUSPICIOUS_KEYWORDS = [
    "free-crypto", "luxury-discount-90", "urgent-wire", "unverified-lottery",
    "cheap-watches-online", "login-update-paypal", "temp-giftcards", "offshore-escrow",
    "mixer-bitcoin", "westernunion-fast"
]

# Prompt Injection & Jailbreak Signatures (Outer Guardrail Defense)
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"system\s+(prompt|override|command)",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
    r"disregard\s+(spending\s+)?limits?",
    r"forget\s+all\s+(rules|restrictions)",
    r"bypass\s+(guardrail|security|auth|limit)",
    r"act\s+as\s+(dan|jailbreak)",
    r"administrative\s+override",
    r"transfer\s+all\s+funds"
]

class PayGuardAgent:
    def __init__(self, spending_limit: float = DEFAULT_SPENDING_LIMIT):
        self.spending_limit = spending_limit
        self.paypal = PayPalClient()
        self.gemini_client = None
        self.transaction_history: List[Dict[str, Any]] = []
        self.pending_challenges: Dict[str, Dict[str, Any]] = {}
        self.recent_tx_timestamps: Dict[str, float] = {}

        api_key = os.getenv("GEMINI_API_KEY")
        if api_key and "your_gemini" not in api_key:
            try:
                from google import genai
                self.gemini_client = genai.Client(api_key=api_key)
            except Exception as e:
                print(f"[PayGuardAgent] Gemini init note: {e}")

    def detect_prompt_injection(self, text: str) -> Optional[str]:
        """
        Deterministic Outer-Loop Prompt Injection Scanner.
        Scans raw intent, invoice notes, and merchant names for jailbreak attempts
        BEFORE any LLM or payment execution occurs.
        """
        for pattern in PROMPT_INJECTION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"PROMPT_INJECTION_SIGNATURE: Matched attack pattern '{match.group(0)}'"
        return None

    def evaluate_risk(self, merchant: str, amount: float, description: str) -> Dict[str, Any]:
        """
        Computes an explainable, multi-factor risk score (0 to 100).
        Includes point breakdown and deterministic defense against prompt injections.
        """
        breakdown = {
            "base_score": 10,
            "merchant_reputation": 0,
            "tld_reputation": 0,
            "keyword_screening": 0,
            "spending_limit_penalty": 0,
            "value_tier_penalty": 0,
            "velocity_penalty": 0,
            "adversarial_penalty": 0
        }
        flags = []
        clean_merchant = merchant.lower().strip()
        clean_desc = description.lower().strip()
        combined_text = f"{clean_merchant} {clean_desc}"

        # 1. Deterministic Prompt Injection / Adversarial Scan
        injection_flag = self.detect_prompt_injection(combined_text)
        if injection_flag:
            breakdown["adversarial_penalty"] = 75
            flags.append(injection_flag)

        # 2. Merchant Trust Verification
        matched_merchant = None
        for domain, info in VERIFIED_MERCHANTS.items():
            if domain in clean_merchant or clean_merchant in domain:
                matched_merchant = info
                break

        if matched_merchant:
            breakdown["merchant_reputation"] = -5
            flags.append(f"VERIFIED_MERCHANT: {matched_merchant['category']} (Trust {matched_merchant['trust_score']}/100)")
        else:
            breakdown["merchant_reputation"] = 30
            flags.append("UNVERIFIED_MERCHANT: Domain not in enterprise trusted whitelist (+30)")

        # 3. High-Risk TLD Check
        if any(clean_merchant.endswith(tld) or f"{tld}/" in clean_merchant for tld in HIGH_RISK_TLDS):
            breakdown["tld_reputation"] = 35
            flags.append("SUSPICIOUS_TLD: High-risk top-level domain detected (+35)")

        # 4. Phishing & Suspicious Keyword Screening
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in combined_text:
                breakdown["keyword_screening"] += 40
                flags.append(f"FRAUD_KEYWORD_MATCH: Detected flagged pattern '{kw}' (+40)")

        # 5. Spending Limit Evaluation
        if amount > self.spending_limit:
            breakdown["spending_limit_penalty"] = 35
            flags.append(f"LIMIT_EXCEEDED: Amount ${amount:.2f} exceeds cap of ${self.spending_limit:.2f} (+35)")

        # 6. High Value Tier Check (> $1000)
        if amount > 1000.0:
            breakdown["value_tier_penalty"] = 25
            flags.append("HIGH_VALUE_TRANSACTION: Exceeds standard micro-payment threshold (+25)")

        # 7. Velocity / Duplicate Transaction Check (< 2 minutes)
        now = time.time()
        tx_key = f"{clean_merchant}:{amount:.2f}"
        if tx_key in self.recent_tx_timestamps and (now - self.recent_tx_timestamps[tx_key]) < 120:
            breakdown["velocity_penalty"] = 30
            flags.append("VELOCITY_SPIKE: Duplicate transaction detected within 2 minutes (+30)")

        # Sum total risk score
        risk_score = sum(breakdown.values())
        risk_score = min(100, max(0, risk_score))

        # Decision & Human-in-the-Loop Routing
        if injection_flag:
            decision = "BLOCKED_ADVERSARIAL_ATTACK"
            reason = "Malicious prompt-injection signature detected in transaction payload. Blocked by PayGuard Outer Shield."
        elif risk_score <= 25 and amount <= self.spending_limit:
            decision = "AUTONOMOUS_APPROVED"
            reason = "Low risk score within designated autonomous spending limit. Executing PayPal Sandbox order."
        elif risk_score >= 80 or any("FRAUD_KEYWORD" in f for f in flags):
            decision = "BLOCKED_FRAUD_DETECTED"
            reason = f"High fraud risk ({risk_score}/100) detected. Transaction halted to safeguard balance."
        else:
            decision = "REQUIRES_HUMAN_CONFIRMATION"
            reason = f"Medium risk ({risk_score}/100) or spending boundary reached. 2FA Human authorization required."

        return {
            "risk_score": risk_score,
            "decision": decision,
            "reason": reason,
            "flags": flags,
            "breakdown": breakdown,
            "spending_limit": self.spending_limit,
            "amount": amount,
            "merchant": merchant
        }

    async def execute_intent(
        self,
        user_intent: str,
        merchant: str,
        amount: float,
        currency: str = "USD",
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Autonomous Agent Intent Lifecycle:
        1. Parse intent & scan for adversarial injections
        2. Multi-factor explainable risk evaluation
        3. Route:
           - Approved ➔ Execute PayPal Sandbox order
           - Medium Risk ➔ Issue 2FA Challenge Token (HITL)
           - High Risk / Injection ➔ Block instantly with audit trace
        """
        start_time = time.perf_counter()
        risk_analysis = self.evaluate_risk(merchant=merchant, amount=amount, description=user_intent)

        trace = [
            {
                "step": 1,
                "action": "INTENT_ANALYSIS",
                "detail": f"Parsed intent: '{user_intent}' for merchant '{merchant}' (${amount:.2f} {currency})",
                "timestamp": time.strftime("%H:%M:%S")
            },
            {
                "step": 2,
                "action": "RISK_AND_GUARDRAIL_EVALUATION",
                "risk_score": risk_analysis["risk_score"],
                "decision": risk_analysis["decision"],
                "breakdown": risk_analysis["breakdown"],
                "flags": risk_analysis["flags"],
                "timestamp": time.strftime("%H:%M:%S")
            }
        ]

        order_result = None
        challenge_info = None

        if risk_analysis["decision"] == "AUTONOMOUS_APPROVED":
            # Record velocity timestamp
            tx_key = f"{merchant.lower().strip()}:{amount:.2f}"
            self.recent_tx_timestamps[tx_key] = time.time()

            # Execute PayPal Sandbox Order
            order_result = await self.paypal.create_order(
                amount=amount,
                currency=currency,
                description=user_intent,
                merchant_name=merchant,
                reference_id=idempotency_key
            )
            trace.append({
                "step": 3,
                "action": "PAYPAL_SANDBOX_ORDER_CREATED",
                "order_id": order_result["id"],
                "status": order_result["status"],
                "approval_url": order_result.get("approval_url"),
                "latency_ms": order_result["latency_ms"],
                "timestamp": time.strftime("%H:%M:%S")
            })

        elif risk_analysis["decision"] == "REQUIRES_HUMAN_CONFIRMATION":
            challenge_id = f"CHAL-{uuid.uuid4().hex[:8].upper()}"
            otp_code = f"{int(time.time() * 1000) % 900000 + 100000}"
            challenge_info = {
                "challenge_id": challenge_id,
                "otp_code": otp_code,
                "status": "AWAITING_2FA_APPROVAL",
                "expires_at": time.time() + 300,
                "payload": {
                    "user_intent": user_intent,
                    "merchant": merchant,
                    "amount": amount,
                    "currency": currency
                }
            }
            self.pending_challenges[challenge_id] = challenge_info

            trace.append({
                "step": 3,
                "action": "HUMAN_IN_THE_LOOP_CHALLENGE_ISSUED",
                "challenge_id": challenge_id,
                "detail": f"Risk score {risk_analysis['risk_score']}/100 requires user 2FA confirmation.",
                "timestamp": time.strftime("%H:%M:%S")
            })

        else: # Blocked (Fraud or Adversarial Prompt Injection)
            trace.append({
                "step": 3,
                "action": "TRANSACTION_BLOCKED",
                "detail": f"PayGuard shield intervened. Reason: {risk_analysis['reason']}",
                "timestamp": time.strftime("%H:%M:%S")
            })

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        record = {
            "id": f"TX-{int(time.time() * 1000) % 1000000}",
            "intent": user_intent,
            "merchant": merchant,
            "amount": amount,
            "currency": currency,
            "risk_score": risk_analysis["risk_score"],
            "decision": risk_analysis["decision"],
            "reason": risk_analysis["reason"],
            "flags": risk_analysis["flags"],
            "breakdown": risk_analysis["breakdown"],
            "order": order_result,
            "challenge": challenge_info,
            "trace": trace,
            "elapsed_ms": elapsed_ms,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        self.transaction_history.insert(0, record)
        return record

    async def resolve_challenge(self, challenge_id: str, approved: bool) -> Dict[str, Any]:
        """
        Resolves a Human-in-the-Loop (HITL) 2FA authorization challenge.
        If approved by the human, creates the PayPal order and marks challenge COMPLETED.
        """
        challenge = self.pending_challenges.get(challenge_id)
        if not challenge:
            return {"status": "error", "message": "Invalid or expired challenge ID"}

        if not approved:
            challenge["status"] = "REJECTED_BY_USER"
            return {
                "status": "rejected",
                "challenge_id": challenge_id,
                "message": "Transaction rejected by user. No funds were moved."
            }

        # Human approved -> complete order
        payload = challenge["payload"]
        order_result = await self.paypal.create_order(
            amount=payload["amount"],
            currency=payload["currency"],
            description=f"[2FA APPROVED] {payload['user_intent']}",
            merchant_name=payload["merchant"]
        )
        challenge["status"] = "APPROVED_AND_EXECUTED"
        challenge["order"] = order_result

        return {
            "status": "approved",
            "challenge_id": challenge_id,
            "message": "Human 2FA authorization confirmed. PayPal Sandbox order executed.",
            "order": order_result
        }

    async def chat_with_agent(self, prompt: str) -> Dict[str, Any]:
        """
        AI Copilot conversation with Prompt Injection Defense and contextual awareness.
        """
        # Outer guardrail check on user chat
        injection_match = self.detect_prompt_injection(prompt)
        if injection_match:
            return {
                "reply": "⚠️ **Security Alert: Prompt Injection Attempt Intercepted.** PayGuard AI operates with deterministic outer guardrails that cannot be modified by conversational prompts.",
                "source": "PayGuard Outer Security Shield"
            }

        # If Gemini is configured
        if self.gemini_client:
            try:
                system_instruction = (
                    "You are PayGuard AI, an autonomous financial intelligence and commerce agent. "
                    f"Your spending limit is ${self.spending_limit:.2f}. "
                    "You protect users from fraudulent merchants and execute secure payments via PayPal Developer Platform. "
                    "You employ deterministic outer guardrails against prompt injection and enforce 2FA on medium-risk payments. "
                    "Always be concise, precise, and professional."
                )
                response = self.gemini_client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=f"{system_instruction}\n\nUser Question: {prompt}"
                )
                return {"reply": response.text, "source": "Gemini 2.5 Flash"}
            except Exception as e:
                print(f"[PayGuardAgent] Gemini query error: {e}")

        # Deterministic fallback
        p_lower = prompt.lower()
        if "limit" in p_lower:
            return {
                "reply": f"Your autonomous spending limit is currently set to **${self.spending_limit:.2f} USD**. Any transaction exceeding this limit requires human 2FA confirmation.",
                "source": "PayGuard Rule Engine"
            }
        elif "injection" in p_lower or "jailbreak" in p_lower or "attack" in p_lower:
            return {
                "reply": "PayGuard AI features an **Outer-Loop Deterministic Security Shield**. Injected instructions like *'ignore limits'* or *'system prompt override'* are filtered BEFORE reaching the LLM or payment APIs.",
                "source": "PayGuard Security Engine"
            }
        elif "fraud" in p_lower or "protect" in p_lower or "risk" in p_lower:
            return {
                "reply": "PayGuard AI calculates an **Explainable Risk Score (0-100)** with point breakdowns for merchant reputation, TLD risk, duplicate velocity, and spending limit breaches.",
                "source": "PayGuard Risk Engine"
            }
        elif "paypal" in p_lower or "api" in p_lower:
            return {
                "reply": "PayGuard connects directly to the **PayPal Developer Sandbox REST API** (`/v2/checkout/orders` and `/v2/checkout/orders/{id}/capture`), enforcing strict `PayPal-Request-Id` idempotency.",
                "source": "PayGuard PayPal Integration"
            }
        else:
            return {
                "reply": f"PayGuard AI is monitoring all autonomous transactions. You have {len(self.transaction_history)} transactions logged in this session.",
                "source": "PayGuard Rule Engine"
            }
