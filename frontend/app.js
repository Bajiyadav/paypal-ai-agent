/**
 * PayGuard AI: Frontend Controller
 * Handles scenario presets, autonomous API execution, spending guardrails, and Copilot chat.
 */

const API_BASE = "";

// Scenarios
const SCENARIOS = {
  aws: {
    intent: "Pay monthly AWS cloud infrastructure bill",
    merchant: "aws.amazon.com",
    amount: "45.00"
  },
  train: {
    intent: "Book express train ticket to Bangalore",
    merchant: "irctc.co.in",
    amount: "32.50"
  },
  laptop: {
    intent: "Purchase developer MacBook Air for intern",
    merchant: "apple.com",
    amount: "899.00"
  },
  phishing: {
    intent: "Claim 90% discount on luxury giftcards",
    merchant: "free-crypto-store.xyz",
    amount: "500.00"
  }
};

function loadScenario(type) {
  const s = SCENARIOS[type];
  if (!s) return;
  document.getElementById("intent-input").value = s.intent;
  document.getElementById("merchant-input").value = s.merchant;
  document.getElementById("amount-input").value = s.amount;
  
  // Highlight execute button
  const btn = document.getElementById("execute-btn");
  btn.style.transform = "scale(1.02)";
  setTimeout(() => { btn.style.transform = "none"; }, 300);
}

// Handle Autonomous Transaction
async function handleTransact(e) {
  e.preventDefault();
  const btn = document.getElementById("execute-btn");
  const intent = document.getElementById("intent-input").value;
  const merchant = document.getElementById("merchant-input").value;
  const amount = parseFloat(document.getElementById("amount-input").value);

  btn.disabled = true;
  btn.innerHTML = "<span>⏳ Agent Reasoning & Vetting...</span>";

  try {
    const res = await fetch(`${API_BASE}/api/transact`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ intent, merchant, amount, currency: "USD" })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    // Render Trace
    renderTrace(data.trace, data.decision);

    // Refresh Feed & Metrics
    await fetchTransactions();

  } catch (err) {
    alert("Error executing transaction: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = "<span>⚡ Execute Autonomous Agent</span>";
  }
}

// Render Trace in HUD
function renderTrace(trace, decision) {
  const box = document.getElementById("trace-box");
  box.innerHTML = "";

  (trace || []).forEach(step => {
    const el = document.createElement("div");
    el.className = "trace-step";
    
    let tagColor = "var(--paypal-light)";
    if (step.action.includes("APPROVED")) tagColor = "var(--success)";
    if (step.action.includes("BLOCKED")) tagColor = "var(--danger)";
    if (step.action.includes("PAUSE")) tagColor = "var(--warning)";

    el.innerHTML = `
      <span class="trace-tag" style="color: ${tagColor}">[${step.action}]</span>
      <span>${step.detail || step.decision || 'Step executed'}</span>
    `;
    box.appendChild(el);
  });
  box.scrollTop = box.scrollHeight;
}

// Fetch and Render Transactions Feed
async function fetchTransactions() {
  try {
    const res = await fetch(`${API_BASE}/api/transactions`);
    const data = await res.json();
    
    const list = document.getElementById("transaction-list");
    if (!data.transactions || data.transactions.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">💳</div>
          <h3>No Transactions Yet</h3>
          <p>Click one of the Quick Scenarios on the left to watch PayGuard AI evaluate risk and execute a PayPal order.</p>
        </div>
      `;
      return;
    }

    list.innerHTML = "";
    let approvedCount = 0;
    let blockedCount = 0;
    let totalLatency = 0;

    data.transactions.forEach(tx => {
      if (tx.decision === "AUTONOMOUS_APPROVED") approvedCount++;
      if (tx.decision === "BLOCKED_FRAUD_DETECTED") blockedCount++;
      totalLatency += (tx.elapsed_ms || 10);

      const card = document.createElement("div");
      let statusClass = "approved";
      let statusLabel = "AUTONOMOUS APPROVED";

      if (tx.decision === "BLOCKED_FRAUD_DETECTED") {
        statusClass = "blocked";
        statusLabel = "BLOCKED (FRAUD)";
      } else if (tx.decision === "REQUIRES_HUMAN_CONFIRMATION") {
        statusClass = "paused";
        statusLabel = "2FA CONFIRMATION NEEDED";
      }

      card.className = `tx-card ${statusClass}`;
      
      let orderLinkHtml = "";
      if (tx.order && tx.order.approval_url) {
        orderLinkHtml = `<a href="${tx.order.approval_url}" target="_blank" class="paypal-link">🅿️ PayPal Order ${tx.order.id} ↗</a>`;
      }

      card.innerHTML = `
        <div class="tx-left">
          <h4>${escapeHtml(tx.intent)}</h4>
          <div class="tx-meta">
            <span>🏢 ${escapeHtml(tx.merchant)}</span> • 
            <span>Risk Score: <strong style="color: ${getRiskColor(tx.risk_score)}">${tx.risk_score}/100</strong></span> • 
            <span>${tx.created_at || 'Just now'}</span>
          </div>
          ${orderLinkHtml}
        </div>
        <div class="tx-right">
          <div class="tx-amount">$${parseFloat(tx.amount).toFixed(2)}</div>
          <span class="tx-badge ${statusClass}">${statusLabel}</span>
        </div>
      `;
      list.appendChild(card);
    });

    // Update Metrics
    document.getElementById("metric-total").innerText = data.transactions.length;
    document.getElementById("metric-approved").innerText = approvedCount;
    document.getElementById("metric-blocked").innerText = blockedCount;
    document.getElementById("metric-latency").innerText = `${Math.round(totalLatency / (data.transactions.length || 1))} ms`;

  } catch (err) {
    console.error("Error fetching transactions:", err);
  }
}

function getRiskColor(score) {
  if (score <= 30) return "var(--success)";
  if (score <= 70) return "var(--warning)";
  return "var(--danger)";
}

// Update Guardrails
async function updateLimit(val) {
  document.getElementById("slider-val").innerText = `$${val}`;
  document.getElementById("header-limit").innerText = `$${val}.00`;
  
  try {
    await fetch(`${API_BASE}/api/guardrails`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ spending_limit: parseFloat(val) })
    });
  } catch (e) {
    console.error("Failed to update guardrails", e);
  }
}

// Copilot Chat
async function handleChat(e) {
  e.preventDefault();
  const input = document.getElementById("chat-input");
  const msg = input.value.trim();
  if (!msg) return;

  input.value = "";
  appendChat(msg, "user");

  try {
    const res = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg })
    });
    const data = await res.json();
    appendChat(data.reply || "I am analyzing your request.", "agent");
  } catch (err) {
    appendChat("Error reaching PayGuard Copilot: " + err.message, "agent");
  }
}

function askCopilot(question) {
  document.getElementById("chat-input").value = question;
  handleChat(new Event("submit"));
}

function appendChat(text, sender) {
  const container = document.getElementById("chat-messages");
  const bubble = document.createElement("div");
  bubble.className = `chat-bubble ${sender}`;
  bubble.innerHTML = formatMarkdown(text);
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
}

function formatMarkdown(text) {
  return text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code style="background: rgba(0,0,0,0.4); padding: 2px 4px; border-radius: 4px;">$1</code>')
    .replace(/\n/g, '<br>');
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Initial Load
document.addEventListener("DOMContentLoaded", () => {
  fetchTransactions();
});
