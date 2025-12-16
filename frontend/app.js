async function scanUrl() {
  const url = document.getElementById("urlInput").value;
  const resultBox = document.getElementById("result");

  if (!url) {
    resultBox.innerText = "Please enter a URL.";
    return;
  }

  resultBox.innerText = "Scanning...";

  
  const API_BASE = "https://cybersentinel-production-ed46.up.railway.app";

  try {
    const response = await fetch(
      `${API_BASE}/scan?url=${encodeURIComponent(url)}`
    );

    if (!response.ok) {
      throw new Error("Backend error");
    }

    const data = await response.json();

    resultBox.innerText = `
Domain: ${data.domain}
Trust Status: ${data.trust_status}
URL Type: ${data.url_type}
Risk Level: ${data.risk_level}
Risk Score: ${data.risk_score}

Verdict:
${data.verdict}

WHOIS Information:
${data.whois_summary}

DNS Information:
${data.dns_summary}
`;
  } catch (err) {
    console.error(err);
    resultBox.innerText = "Error connecting to backend.";
  }
}
