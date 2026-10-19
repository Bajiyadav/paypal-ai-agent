"""
Unit Testing Suite for PayGuard AI
Tests the risk scoring engine, spending guardrails, PayPal client, and FastAPI endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.agent import PayGuardAgent
from backend.paypal_client import PayPalClient

client = TestClient(app)

class TestRiskEngine:
    def setup_method(self):
        self.agent = PayGuardAgent(spending_limit=250.00)

    def test_verified_merchant_is_low_risk(self):
        """Verified merchants should have low risk and get autonomous approval if under limit."""
        eval_res = self.agent.evaluate_risk(
            merchant="aws.amazon.com",
            amount=45.00,
            description="Monthly AWS cloud hosting"
        )
        assert eval_res["risk_score"] <= 25
        assert eval_res["decision"] == "AUTONOMOUS_APPROVED"

    def test_phishing_keyword_is_blocked(self):
        """Suspicious phishing keywords should be flagged as fraud and blocked."""
        eval_res = self.agent.evaluate_risk(
            merchant="free-crypto-store.xyz",
            amount=50.00,
            description="Buy cheap luxury giftcards"
        )
        assert eval_res["risk_score"] > 70
        assert eval_res["decision"] == "BLOCKED_FRAUD_DETECTED"

    def test_amount_exceeding_limit_requires_confirmation(self):
        """Transactions exceeding user spending limit must require human 2FA confirmation."""
        eval_res = self.agent.evaluate_risk(
            merchant="amazon.com",
            amount=500.00, # Exceeds limit of 250
            description="Buy new monitor"
        )
        assert eval_res["decision"] == "REQUIRES_HUMAN_CONFIRMATION"

class TestFastAPIEndpoints:
    def test_health_endpoint(self):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "spending_limit_usd" in data

    def test_evaluate_endpoint(self):
        payload = {
            "merchant": "github.com",
            "amount": 20.00,
            "description": "GitHub Team Subscription"
        }
        res = client.post("/api/evaluate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["decision"] == "AUTONOMOUS_APPROVED"

    def test_transact_endpoint_autonomous_execution(self):
        payload = {
            "intent": "Pay train ticket",
            "merchant": "irctc.co.in",
            "amount": 35.00,
            "currency": "USD"
        }
        res = client.post("/api/transact", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["decision"] == "AUTONOMOUS_APPROVED"
        assert "order" in data
        assert data["order"]["status"] == "CREATED"
        assert "approval_url" in data["order"]

    def test_transactions_feed(self):
        res = client.get("/api/transactions")
        assert res.status_code == 200
        data = res.json()
        assert "transactions" in data
        assert data["count"] >= 1

    def test_guardrails_update(self):
        res = client.post("/api/guardrails", json={"spending_limit": 300.0})
        assert res.status_code == 200
        data = res.json()
        assert data["new_spending_limit_usd"] == 300.0

    def test_copilot_chat(self):
        res = client.post("/api/chat", json={"message": "What is my spending limit?"})
        assert res.status_code == 200
        data = res.json()
        assert "reply" in data
        assert "spending limit" in data["reply"].lower()
