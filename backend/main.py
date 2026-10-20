"""
PayGuard AI: FastAPI Backend Server
Serves REST API endpoints for agentic commerce, prompt injection defense,
explainable risk scoring, Human-in-the-Loop 2FA challenge resolution,
and PayPal Sandbox order creation & capture.
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from .agent import PayGuardAgent

app = FastAPI(
    title="PayGuard AI: Autonomous Agentic Commerce & Security Shield",
    description="Intelligent financial guardrails, prompt-injection defense, and PayPal Developer Sandbox order lifecycle.",
    version="2.0.0"
)

# Enable CORS for all local and hosted frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Agent
agent = PayGuardAgent()

# Request/Response Schemas
class TransactRequest(BaseModel):
    intent: str = Field(..., description="User instruction, e.g., 'Pay monthly AWS server bill'")
    merchant: Optional[str] = Field(None, description="Target vendor, e.g., 'aws.amazon.com'")
    amount: Optional[float] = Field(None, description="Amount in USD")
    currency: Optional[str] = Field("USD", description="Currency code (USD, EUR, etc.)")
    idempotency_key: Optional[str] = Field(None, description="Optional unique request key for replay defense")

class RiskEvaluateRequest(BaseModel):
    merchant: str
    amount: float
    description: Optional[str] = ""

class ChallengeActionRequest(BaseModel):
    challenge_id: str
    approved: bool

class CaptureRequest(BaseModel):
    order_id: str

class ChatRequest(BaseModel):
    message: str

class GuardrailUpdateRequest(BaseModel):
    spending_limit: float = Field(..., gt=0, description="New autonomous spending limit in USD")

# ====================
# REST API ENDPOINTS
# ====================

@app.get("/api/health")
def healthcheck():
    """System health check, engine status, and security shield status."""
    return {
        "status": "healthy",
        "service": "PayGuard AI Agentic Commerce Core",
        "version": "2.0.0",
        "spending_limit_usd": agent.spending_limit,
        "paypal_environment": "Sandbox",
        "security_shield": "Active (Deterministic Outer Guardrails)",
        "pending_challenges": len(agent.pending_challenges),
        "transactions_tracked": len(agent.transaction_history)
    }

@app.get("/api/transactions")
def get_transactions():
    """Retrieve full history of autonomous transactions, risk breakdowns, and audit trace."""
    return {
        "count": len(agent.transaction_history),
        "spending_limit": agent.spending_limit,
        "transactions": agent.transaction_history
    }

@app.post("/api/evaluate")
def evaluate_transaction_risk(req: RiskEvaluateRequest):
    """Calculates explainable risk score, point breakdown, and guardrail decision without moving funds."""
    return agent.evaluate_risk(
        merchant=req.merchant,
        amount=req.amount,
        description=req.description or ""
    )

@app.post("/api/transact")
async def execute_agentic_transaction(req: TransactRequest):
    """
    Main Autonomous Agent Trigger:
    Scans for prompt injections, calculates explainable risk, enforces spending caps,
    and executes PayPal order or issues Human-in-the-Loop 2FA challenge.
    """
    result = await agent.execute_intent(
        user_intent=req.intent,
        merchant=req.merchant,
        amount=req.amount,
        currency=req.currency or "USD",
        idempotency_key=req.idempotency_key
    )
    return result

@app.post("/api/challenge/action")
async def handle_challenge_action(req: ChallengeActionRequest):
    """
    Human-in-the-Loop (HITL) 2FA Resolution:
    Approves or rejects a transaction held for human review.
    """
    return await agent.resolve_challenge(
        challenge_id=req.challenge_id,
        approved=req.approved
    )

@app.post("/api/capture")
async def capture_order(req: CaptureRequest):
    """
    PayPal Order Capture Lifecycle:
    Captures authorized funds for a given PayPal Sandbox order ID.
    """
    return await agent.paypal.capture_order(order_id=req.order_id)

@app.post("/api/chat")
async def chat_with_copilot(req: ChatRequest):
    """Conversational AI Copilot with outer-loop prompt injection defense."""
    return await agent.chat_with_agent(req.message)

@app.post("/api/guardrails")
def update_spending_limit(req: GuardrailUpdateRequest):
    """Updates the user-defined autonomous spending limit."""
    agent.spending_limit = req.spending_limit
    return {
        "status": "updated",
        "new_spending_limit_usd": agent.spending_limit,
        "message": f"Autonomous spending cap updated to ${agent.spending_limit:.2f} USD."
    }

# ====================
# STATIC FILE SERVING
# ====================
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_frontend():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "PayGuard AI API Running. Frontend index.html not found."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
