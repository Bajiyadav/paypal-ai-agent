"""
PayGuard AI: PayPal Sandbox API Client
Handles OAuth2 token acquisition, order creation, capture, and verification using PayPal Developer Sandbox REST APIs.
"""

import os
import time
import httpx
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")

class PayPalClient:
    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        self.client_id = client_id or PAYPAL_CLIENT_ID
        self.client_secret = client_secret or PAYPAL_CLIENT_SECRET
        self.base_url = PAYPAL_API_BASE.rstrip("/")
        self._cached_token: Optional[str] = None
        self._token_expiry: float = 0

    async def get_access_token(self) -> str:
        """Fetch or refresh OAuth2 Bearer token from PayPal Sandbox."""
        # Return cached token if still valid
        if self._cached_token and time.time() < self._token_expiry - 60:
            return self._cached_token

        # Fallback simulation if running in demo/offline mode without live keys
        if not self.client_id or not self.client_secret or "your_paypal" in self.client_id:
            self._cached_token = "A21AAK_simulated_sandbox_token_payguard_demo"
            self._token_expiry = time.time() + 3600
            return self._cached_token

        url = f"{self.base_url}/v1/oauth2/token"
        headers = {
            "Accept": "application/json",
            "Accept-Language": "en_US"
        }
        data = {"grant_type": "client_credentials"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                headers=headers,
                data=data,
                auth=(self.client_id, self.client_secret)
            )
            if resp.status_code != 200:
                raise Exception(f"PayPal OAuth Failed [{resp.status_code}]: {resp.text}")
            
            payload = resp.json()
            self._cached_token = payload["access_token"]
            self._token_expiry = time.time() + payload.get("expires_in", 3600)
            return self._cached_token

    async def create_order(
        self,
        amount: float,
        currency: str = "USD",
        description: str = "PayGuard AI Autonomous Agent Transaction",
        merchant_name: str = "Verified Merchant",
        reference_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates an order in PayPal Sandbox (/v2/checkout/orders).
        Returns order ID and approval link.
        """
        start_time = time.perf_counter()
        token = await self.get_access_token()

        order_payload = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": reference_id or f"payguard-ref-{int(time.time())}",
                    "description": description,
                    "amount": {
                        "currency_code": currency,
                        "value": f"{amount:.2f}"
                    },
                    "payee": {
                        "email_address": "merchant-sandbox@payguard.ai"
                    }
                }
            ],
            "application_context": {
                "brand_name": "PayGuard AI Agentic Shield",
                "landing_page": "NO_PREFERENCE",
                "user_action": "PAY_NOW",
                "return_url": "https://paypal-ai-agent.vercel.app/success",
                "cancel_url": "https://paypal-ai-agent.vercel.app/cancel"
            }
        }

        # If in simulated sandbox mode
        if token.startswith("A21AAK_simulated"):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            mock_id = f"SANDBOX-ORD-{int(time.time() * 1000) % 1000000}"
            return {
                "id": mock_id,
                "status": "CREATED",
                "intent": "CAPTURE",
                "amount": f"{amount:.2f}",
                "currency": currency,
                "merchant": merchant_name,
                "description": description,
                "approval_url": f"https://www.sandbox.paypal.com/checkoutnow?token={mock_id}",
                "latency_ms": elapsed_ms,
                "mode": "SANDBOX_SIMULATED"
            }

        url = f"{self.base_url}/v2/checkout/orders"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "PayPal-Request-Id": f"payguard-req-{time.time()}"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, headers=headers, json=order_payload)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            
            if resp.status_code not in (200, 201):
                raise Exception(f"PayPal Order Creation Failed [{resp.status_code}]: {resp.text}")

            res_json = resp.json()
            approval_link = next((l["href"] for l in res_json.get("links", []) if l["rel"] == "approve"), None)
            
            return {
                "id": res_json["id"],
                "status": res_json.get("status", "CREATED"),
                "amount": f"{amount:.2f}",
                "currency": currency,
                "merchant": merchant_name,
                "description": description,
                "approval_url": approval_link,
                "latency_ms": elapsed_ms,
                "mode": "LIVE_SANDBOX"
            }

    async def capture_order(self, order_id: str) -> Dict[str, Any]:
        """
        Captures payment for an approved order (/v2/checkout/orders/{id}/capture).
        """
        start_time = time.perf_counter()
        token = await self.get_access_token()

        if token.startswith("A21AAK_simulated"):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "id": order_id,
                "status": "COMPLETED",
                "capture_id": f"CAP-{int(time.time() * 1000) % 1000000}",
                "latency_ms": elapsed_ms,
                "mode": "SANDBOX_SIMULATED"
            }

        url = f"{self.base_url}/v2/checkout/orders/{order_id}/capture"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, headers=headers)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            
            if resp.status_code not in (200, 201):
                raise Exception(f"PayPal Capture Failed [{resp.status_code}]: {resp.text}")

            res_json = resp.json()
            return {
                "id": res_json["id"],
                "status": res_json.get("status", "COMPLETED"),
                "capture_id": res_json.get("purchase_units", [{}])[0].get("payments", {}).get("captures", [{}])[0].get("id"),
                "latency_ms": elapsed_ms,
                "mode": "LIVE_SANDBOX"
            }
