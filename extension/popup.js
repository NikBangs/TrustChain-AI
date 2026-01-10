document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.tabs.sendMessage(tab.id, { type: "EVALUATE_PAGE" }, async (response) => {
    console.log("Received from backend:", response);
    if (!response) {
      document.getElementById("score").textContent = "⚠ No response from content script";
      return;
    }

    const { trust_score, risk, flagged, criteria } = response;

    document.getElementById("score").textContent = trust_score;
    document.getElementById("risk").textContent = risk;
    if (flagged) {
      document.getElementById("risk").textContent += " 🚩 Already Reported";
    }

    const criteriaDiv = document.getElementById("criteria");
    for (const [category, result] of Object.entries(criteria)) {
      const status = typeof result === "string" && result === "passed" ? "✅ Passed" : "❌ Failed";
      const reasonList = Array.isArray(result)
        ? `<ul style='margin: 0; padding-left: 16px;'>${result.map(r => `<li>${r}</li>`).join("")}</ul>`
        : "";

      criteriaDiv.innerHTML += `
        <div style="margin-bottom: 8px;">
          <strong>${category.replace(/_/g, " ")}:</strong> ${status}
          ${reasonList}
        </div>
      `;
    }

    document.getElementById("report").addEventListener("click", async () => {
      await fetch("http://localhost:5000/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: new URL(tab.url).hostname })
      });
      alert("Fraud reported to blockchain!");
    });
  });
});
