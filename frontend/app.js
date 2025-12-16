// =======================================
// CyberSentinel AI - Frontend Logic
// =======================================

// -------------------------------
// URL format validation (frontend)
// -------------------------------
function isValidUrlFormat(url) {
  // Reject spaces
  if (url.includes(" ")) return false;

  // Basic URL / domain pattern
  const pattern = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  return pattern.test(url);
}

// -------------------------------
// Main scan function
// -------------------------------
async function scanUrl() {
  const urlInput = document.getElementById("urlInput");
  const resultBox = document.getElementById("result");

  const url = urlInput.value.trim();

  // -------------------------------
  // Empty input check
  // -------------------------------
  if (!url) {
    resultBox.innerText = "❌ Please enter a URL.";
    return;
  }

  // -------------------------------
  // Frontend validation
  // -------------------------------
  if (!isValidUrlFormat(url)) {
    resultBox.innerText =
      "❌ Invalid URL format. Please enter a valid URL (no spaces).";
    return;
  }

  // -------------------------------
  // Show loading message
  // -------------------------------
  resultBox.innerText = "🔍 Scanning URL, please wait...";

  // -------------------------------
  // Backend API base
  // -------------------------------
  const API_BASE = "https://cybersentinel-production-ed46.up.railway.app";

  try {
    const response = await fetch(
      `${API_BASE}/scan?url=${encodeURIComponent(url)}`
    );

    const data = await response.json();

    // -------------------------------
    // Backend validation error
    // -------------------------------
    if (data.error) {
      resultBox.innerText = `❌ ${data.error}`;
      return;
    }

    // -------------------------------
    // Reachability text
    // -------------------------------
    const reachableText = data.reachable
      ? "✅ Reachable"
      : "⚠️ Not reachable";

    // -------------------------------
    // Final output
    // -------------------------------
    resultBox.innerText = `
🔐 CyberSentinel AI – Scan Result
--------------------------------

Domain        : ${data.domain}
Trust Status  : ${data.trust_status}
URL Type      : ${data.url_type}
Risk Level    : ${data.risk_level}
Risk Score    : ${data.risk_score}
Reachability  : ${reachableText}

Verdict:
${data.verdict}

WHOIS Information:
${data.whois_summary}

DNS Information:
${data.dns_summary}
`;
  } catch (err) {
    console.error(err);
    resultBox.innerText =
      "❌ Unable to connect to the backend. Please try again later.";
  }
}
