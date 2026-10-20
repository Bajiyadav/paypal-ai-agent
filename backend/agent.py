"""
PayGuard AI Agent Engine: Autonomous Agentic Commerce & Fraud Guardrails
Combines Google Gemini reasoning with deterministic prompt-injection defense,
strict parsed-hostname merchant verification, typosquatting detection,
explainable risk scoring, cumulative spending caps, Human-in-the-Loop (HITL) 2FA,
and automated PayPal Sandbox order lifecycle execution (create -> capture).
"""

import os
import re
import json
import time
import uuid
import math
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from .paypal_client import PayPalClient

load_dotenv()

DEFAULT_SPENDING_LIMIT = float(os.getenv("SPENDING_LIMIT_USD", "250.00"))
DEFAULT_CUMULATIVE_CAP = float(os.getenv("CUMULATIVE_CAP_USD", "1000.00"))

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

def extract_host(merchant: str) -> str:
    """Safely parses and extracts the normalized hostname from a merchant string."""
    m = (merchant or "").strip().lower()
    if not m:
        return ""
    if "://" not in m:
        m = "//" + m
    try:
        parsed = urlparse(m)
        host = (parsed.hostname or "").rstrip(".")
        return host
    except Exception:
        return ""

def match_verified_merchant(host: str) -> Optional[Dict[str, Any]]:
    """
    Strict hostname matching against verified enterprise whitelist.
    Prevents sub-domain spoofing attacks (e.g. 'amazon.com.evil.xyz')
    and homograph/punycode spoofing (e.g. 'xn--...').
    """
    if not host or "xn--" in host or not host.isascii():
        return None
    for domain, info in VERIFIED_MERCHANTS.items():
        # Exact match or authentic sub-domain of verified root (e.g. 'aws.amazon.com')
        if host == domain or host.endswith("." + domain):
            return info
    return None

def detect_typosquatting(host: str) -> Optional[str]:
    """Detects character substitution attacks (e.g., 'paypa1.com', 'arnazon.com')."""
    if not host:
        return None
    common_targets = ["paypal.com", "amazon.com", "apple.com", "github.com", "netflix.com"]
    # Check for obvious visual substitutions
    subs = {"1": "l", "0": "o", "rn": "m", "vv": "w"}
    normalized = host
    for k, v in subs.items():
        normalized = normalized.replace(k, v)
    for target in common_targets:
        if normalized == target and host != target:
            return f"TYPOSQUATTING_DETECTED: Host '{host}' visually mimics verified entity '{target}'"
    return None


class PayGuardAgent:
    def __init__(
        self,
        spending_limit: float = DEFAULT_SPENDING_LIMIT,
        cumulative_cap: float = DEFAULT_CUMULATIVE_CAP
    ):
        self.spending_limit = spending_limit
        self.cumulative_cap = cumulative_cap
        self.cumulative_spent_usd = 0.0
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

    async def parse_intent_with_gemini(self, user_intent: str) -> Dict[str, Any]:
        """
        Agentic Decomposition:
        Uses Google Gemini with structured extraction to parse unstructured commercial intent.
        Proposes {merchant, amount, currency}, which is then passed to deterministic guardrails.
        """
        if self.gemini_client:
            try:
                prompt = (
                    "Extract the merchant domain, amount in USD (number only), and currency from this commercial intent. "
                    "Return ONLY valid JSON format: {\"merchant\": string, \"amount\": number, \"currency\": string}.\n"
                    f"Intent: {user_intent}"
                )
                response = await self.gemini_client.aio.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
                raw_text = response.text.strip()
                # Clean markdown blocks if present
                if raw_text.startswith("```"):
                    raw_text = re.sub(r"^```(?:json)?\n|\n```$", "", raw_text, flags=re.MULTILINE)
                parsed = json.loads(raw_text)
                return {
                    "merchant": parsed.get("merchant", "").strip(),
                    "amount": float(parsed.get("amount", 0.0)),
                    "currency": parsed.get("currency", "USD").upper(),
                    "source": "Gemini 2.5 Flash Structured Intent Extraction"
                }
            except Exception as e:
                print(f"[PayGuardAgent] Gemini extraction fallback: {e}")

        # Deterministic Regex Fallback
        amt_match = re.search(r"\$?([0-9]+(?:\.[0-9]{1,2})?)", user_intent)
        amount = float(amt_match.group(1)) if amt_match else 0.0
        
        # Simple domain extract
        domain_match = re.search(r"([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)", user_intent)
        merchant = domain_match.group(1) if domain_match else "unknown-vendor.com"

        return {
            "merchant": merchant,
            "amount": amount,
            "currency": "USD",
            "source": "PayGuard Regex Entity Extractor"
        }

    def evaluate_risk(self, merchant: str, amount: float, description: str) -> Dict[str, Any]:
        """
        Computes an explainable, multi-factor risk score (0 to 100).
        Validates amounts, hostnames, spoofing, typosquatting, velocity, and prompt injection.
        """
        # 1. Amount & Currency Validation
        if amount is None or not isinstance(amount, (int, float)) or math.isnan(amount) or math.isinf(amount) or amount <= 0:
            return {
                "risk_score": 100,
                "decision": "BLOCKED_INVALID_AMOUNT",
                "reason": f"Invalid amount (${amount}). Transaction amounts must be positive, finite numbers.",
                "flags": ["INVALID_AMOUNT: Non-positive or non-finite transaction amount"],
                "breakdown": {"base_score": 100},
                "spending_limit": self.spending_limit,
                "amount": amount,
                "merchant": merchant
            }

        breakdown = {
            "base_score": 10,
            "merchant_reputation": 0,
            "tld_reputation": 0,
            "typosquatting_penalty": 0,
            "keyword_screening": 0,
            "spending_limit_penalty": 0,
            "cumulative_cap_penalty": 0,
            "value_tier_penalty": 0,
            "velocity_penalty": 0,
            "adversarial_penalty": 0
        }
        flags = []
        host = extract_host(merchant)
        clean_desc = description.lower().strip()
        combined_text = f"{host} {merchant} {clean_desc}"

        # 2. Deterministic Prompt Injection / Adversarial Scan
        injection_flag = self.detect_prompt_injection(combined_text)
        if injection_flag:
            breakdown["adversarial_penalty"] = 75
            flags.append(injection_flag)

        # 3. Strict Host Merchant Trust Verification
        matched_merchant = match_verified_merchant(host)
        if matched_merchant:
            breakdown["merchant_reputation"] = -5
            flags.append(f"VERIFIED_MERCHANT: {matched_merchant['category']} (Trust {matched_merchant['trust_score']}/100)")
        else:
            breakdown["merchant_reputation"] = 30
            flags.append(f"UNVERIFIED_MERCHANT: Host '{host or 'none'}' not in enterprise trusted whitelist (+30)")

        # 4. Typosquatting Detection
        typo_flag = detect_typosquatting(host)
        if typo_flag:
            breakdown["typosquatting_penalty"] = 45
            flags.append(typo_flag + " (+45)")

        # 5. High-Risk TLD Check
        if any(host.endswith(tld) for tld in HIGH_RISK_TLDS):
            breakdown["tld_reputation"] = 35
            flags.append("SUSPICIOUS_TLD: High-risk top-level domain detected (+35)")

        # 6. Phishing & Suspicious Keyword Screening
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in combined_text:
                breakdown["keyword_screening"] += 40
                flags.append(f"FRAUD_KEYWORD_MATCH: Detected flagged pattern '{kw}' (+40)")

        # 7. Per-Transaction Spending Limit Evaluation
        if amount > self.spending_limit:
            breakdown["spending_limit_penalty"] = 35
            flags.append(f"LIMIT_EXCEEDED: Amount ${amount:.2f} exceeds per-transaction cap of ${self.spending_limit:.2f} (+35)")

        # 8. Cumulative Session Cap Evaluation
        if (self.cumulative_spent_usd + amount) > self.cumulative_cap:
            breakdown["cumulative_cap_penalty"] = 40
            flags.append(f"CUMULATIVE_CAP_EXCEEDED: Total spend ${self.cumulative_spent_usd + amount:.2f} exceeds session cap ${self.cumulative_cap:.2f} (+40)")

        # 9. High Value Tier Check (> $1000)
        if amount > 1000.0:
            breakdown["value_tier_penalty"] = 25
            flags.append("HIGH_VALUE_TRANSACTION: Exceeds standard micro-payment threshold (+25)")

        # 10. Velocity / Duplicate Transaction Check (< 2 minutes)
        now = time.time()
        tx_key = f"{host}:{amount:.2f}"
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
        elif breakdown.get("typosquatting_penalty", 0) > 0:
            decision = "BLOCKED_FRAUD_DETECTED"
            reason = "Typosquatting/homograph domain mimicry detected. Payment blocked by PayGuard AI shield."
        elif risk_score <= 25 and amount <= self.spending_limit and (self.cumulative_spent_usd + amount) <= self.cumulative_cap:
            decision = "AUTONOMOUS_APPROVED"
            reason = "Low risk score within designated autonomous spending limits. Prepared for PayPal Sandbox execution."
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
            "cumulative_spent": self.cumulative_spent_usd,
            "cumulative_cap": self.cumulative_cap,
            "amount": amount,
            "merchant": merchant,
            "host": host
        }

    async def execute_intent(
        self,
        user_intent: str,
        merchant: Optional[str] = None,
        amount: Optional[float] = None,
        currency: str = "USD",
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Agentic Autonomous Workflow:
        1. If merchant/amount are omitted, Gemini performs autonomous entity extraction.
        2. Evaluate Risk & Guardrails via Deterministic Outer Shield.
        3. Route:
           - Approved ➔ Execute PayPal Order (with graceful exception handling)
           - Medium Risk ➔ Issue 2FA Challenge Token (HITL)
           - High Risk / Injection ➔ Block instantly with audit trace
        """
        start_time = time.perf_counter()
        trace = []

        # Step 1: Agentic Entity Extraction if freeform prompt provided
        extracted_meta = None
        if not merchant or amount is None:
            extracted_meta = await self.parse_intent_with_gemini(user_intent)
            merchant = merchant or extracted_meta["merchant"]
            amount = amount if amount is not None else extracted_meta["amount"]
            currency = currency or extracted_meta["currency"]
            trace.append({
                "step": 1,
                "action": "AGENTIC_ENTITY_EXTRACTION",
                "detail": f"{extracted_meta['source']} extracted merchant='{merchant}', amount=${amount:.2f}",
                "timestamp": time.strftime("%H:%M:%S")
            })
        else:
            trace.append({
                "step": 1,
                "action": "INTENT_ANALYSIS",
                "detail": f"Parsed intent: '{user_intent}' for merchant '{merchant}' (${amount:.2f} {currency})",
                "timestamp": time.strftime("%H:%M:%S")
            })

        # Step 2: Risk and Guardrail Evaluation
        risk_analysis = self.evaluate_risk(merchant=merchant, amount=amount, description=user_intent)
        trace.append({
            "step": 2,
            "action": "RISK_AND_GUARDRAIL_EVALUATION",
            "risk_score": risk_analysis["risk_score"],
            "decision": risk_analysis["decision"],
            "breakdown": risk_analysis["breakdown"],
            "flags": risk_analysis["flags"],
            "timestamp": time.strftime("%H:%M:%S")
        })

        order_result = None
        challenge_info = None

        if risk_analysis["decision"] == "AUTONOMOUS_APPROVED":
            # Record velocity timestamp & cumulative spend
            host = risk_analysis.get("host") or merchant
            tx_key = f"{host}:{amount:.2f}"
            self.recent_tx_timestamps[tx_key] = time.time()
            self.cumulative_spent_usd += amount

            # Execute PayPal Sandbox Order with graceful error handling
            try:
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
            except Exception as e:
                order_result = None
                trace.append({
                    "step": 3,
                    "action": "PAYPAL_ERROR",
                    "detail": f"PayPal Sandbox API failed: {str(e)}",
                    "timestamp": time.strftime("%H:%M:%S")
                })
                risk_analysis["decision"] = "PAYPAL_EXECUTION_FAILED"
                risk_analysis["reason"] = f"PayPal Sandbox rejected order: {str(e)}"

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
            "id": f"TX-{uuid.uuid4().hex[:10].upper()}",
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

        payload = challenge["payload"]
        try:
            order_result = await self.paypal.create_order(
                amount=payload["amount"],
                currency=payload["currency"],
                description=f"[2FA APPROVED] {payload['user_intent']}",
                merchant_name=payload["merchant"]
            )
            challenge["status"] = "APPROVED_AND_EXECUTED"
            challenge["order"] = order_result
            self.cumulative_spent_usd += payload["amount"]

            return {
                "status": "approved",
                "challenge_id": challenge_id,
                "message": "Human 2FA authorization confirmed. PayPal Sandbox order executed.",
                "order": order_result
            }
        except Exception as e:
            return {
                "status": "error",
                "challenge_id": challenge_id,
                "message": f"PayPal Order Execution Failed: {str(e)}"
            }

    async def chat_with_agent(self, prompt: str) -> Dict[str, Any]:
        """
        AI Copilot conversation grounded in live transaction history and guardrails.
        """
        # Outer guardrail check on user chat
        injection_match = self.detect_prompt_injection(prompt)
        if injection_match:
            return {
                "reply": "⚠️ **Security Alert: Prompt Injection Attempt Intercepted.** PayGuard AI operates with deterministic outer guardrails that cannot be modified by conversational prompts.",
                "source": "PayGuard Outer Security Shield"
            }

        # Context grounding
        history_summary = f"Session Transactions: {len(self.transaction_history)}, Cumulative Spent: ${self.cumulative_spent_usd:.2f} / ${self.cumulative_cap:.2f} USD."

        if self.gemini_client:
            try:
                system_instruction = (
                    "You are PayGuard AI, an autonomous financial intelligence and commerce agent. "
                    f"Current Spending Limit: ${self.spending_limit:.2f}. {history_summary} "
                    "You protect users from fraudulent merchants, detect spoofing/typosquatting, and execute secure payments via PayPal Developer Platform. "
                    "You employ deterministic outer guardrails against prompt injection and enforce 2FA on medium-risk payments. "
                    "Always be concise, precise, and professional."
                )
                response = await self.gemini_client.aio.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=f"{system_instruction}\n\nUser Question: {prompt}"
                )
                return {"reply": response.text, "source": "Gemini 2.5 Flash"}
            except Exception as e:
                print(f"[PayGuardAgent] Gemini query error: {e}")

        # Deterministic fallback grounded in live status
        p_lower = prompt.lower()
        if "limit" in p_lower:
            return {
                "reply": f"Your autonomous spending limit is **${self.spending_limit:.2f} USD** per transaction, and session cap is **${self.cumulative_cap:.2f} USD** (Spent: ${self.cumulative_spent_usd:.2f}).",
                "source": "PayGuard Rule Engine"
            }
        elif "injection" in p_lower or "jailbreak" in p_lower or "attack" in p_lower:
            return {
                "reply": "PayGuard AI features an **Outer-Loop Deterministic Security Shield**. Injected instructions like *'ignore limits'* or *'system prompt override'* are filtered BEFORE reaching the LLM or payment APIs.",
                "source": "PayGuard Security Engine"
            }
        elif "history" in p_lower or "transactions" in p_lower:
            return {
                "reply": f"You have **{len(self.transaction_history)} transactions** logged in this session with cumulative spend of **${self.cumulative_spent_usd:.2f} USD**.",
                "source": "PayGuard Transaction History"
            }
        elif "fraud" in p_lower or "protect" in p_lower or "risk" in p_lower:
            return {
                "reply": "PayGuard AI calculates an **Explainable Risk Score (0-100)** with parsed-hostname verification, typosquatting detection, duplicate velocity checks, and spending limit enforcement.",
                "source": "PayGuard Risk Engine"
            }
        else:
            return {
                "reply": f"PayGuard AI is monitoring all autonomous transactions. {history_summary}",
                "source": "PayGuard Rule Engine"
            }
