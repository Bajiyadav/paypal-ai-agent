# 💳 PayGuard AI: Autonomous Agentic Commerce & Fraud Shield

> **Hackathon Submission:** [PayPal AI Hackathon](https://paypalaihackathon.devpost.com/) (Devpost & PayPal)  
> **Track:** Best Use of Agentic Commerce ($5,000) & Best Use of PayPal + AI ($5,000)  
> **Prize Pool:** $67,500+  
> **Team Lead:** Baji Baddela  
> **Core Tech:** PayPal Developer Platform (Sandbox APIs), Google Gemini AI, FastAPI, Postman CLI  

---

## ⚡ The Vision: Agentic Commerce Behind the Wheel

Traditional e-commerce requires human users to manually click through 10 checkout steps, type credit card details, and calculate currency conversions.

**PayGuard AI** turns AI agents into **autonomous commercial actors**:
1. **Natural-Language Voice & Text Intent:** The user says: *"Book a train to Bangalore under $50 and pay my electric utility bill."*
2. **Autonomous Vendor & Fraud Verification:** The agent analyzes merchant reputation, checks duplicate billing, and calculates a risk score before a single dollar moves.
3. **Autonomous PayPal Execution:** The agent interacts directly with **PayPal Sandbox REST APIs** (`/v2/checkout/orders`, `/v1/payments/payouts`) to authorize, create, and capture secure transactions.
4. **Agentic Guardrails:** Strict spending limits, two-factor confirmation for transactions above custom thresholds, and real-time Postman API audit logging.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│             PayGuard Cyber HUD / React Client               │
│         (Real-time Transaction Canvas & AI Terminal)        │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST / JSON
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                PayGuard Agent Core (FastAPI)                │
│    - Google Gemini Autonomous Reasoning Engine              │
│    - Transaction Risk & Fraud Evaluation Engine             │
│    - Postman Automated Contract Test Runner                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
 ┌─────────────────────────────┐ ┌───────────────────────────┐
 │   PayPal Sandbox API        │ │    Fraud & Guardrail DB   │
 │ - /v2/checkout/orders       │ │ - Spending Limit Vault    │
 │ - /v2/payments/captures     │ │ - Vendor Whitelist Graph  │
 │ - /v1/payments/payouts      │ │ - Multi-Hop Anomaly Trace │
 └─────────────────────────────┘ └───────────────────────────┘
```

---

## 🚀 Quickstart

### Prerequisites
* Python 3.10+
* Node.js & npm (optional for frontend)
* PayPal Developer Account (Sandbox Client ID & Secret)

### Setup
```bash
# 1. Clone & Enter Directory
cd /Users/bajiyadav/paypal-ai-agent

# 2. Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# 3. Configure Credentials
cp .env.example .env
# Edit .env with your PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, and GEMINI_API_KEY
```
