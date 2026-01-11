document.addEventListener("DOMContentLoaded", async () => {
  const loadingEl = document.getElementById("loading");
  const statusEl = document.getElementById("status");
  const errorEl = document.getElementById("error");
  const successEl = document.getElementById("success");
  const scoreEl = document.getElementById("score");
  const riskEl = document.getElementById("risk");
  const criteriaEl = document.getElementById("criteria");
  const reportBtn = document.getElementById("report");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.tabs.sendMessage(tab.id, { type: "EVALUATE_PAGE" }, async (response) => {
      console.log("Received from backend:", response);
      
      if (!response) {
        showError("No response from content script. Please refresh the page and try again.");
        return;
      }

      const { trust_score, risk, flagged, criteria } = response;

      // Update score with color coding
      scoreEl.textContent = trust_score || "N/A";
      const scoreNum = parseInt(trust_score);
      if (!isNaN(scoreNum)) {
        scoreEl.className = "score-value";
        if (scoreNum >= 70) {
          scoreEl.classList.add("high");
        } else if (scoreNum >= 40) {
          scoreEl.classList.add("medium");
        } else {
          scoreEl.classList.add("low");
        }
      }

      // Update risk badge
      const riskLower = (risk || "").toLowerCase();
      riskEl.className = "risk-badge";
      riskEl.textContent = risk || "Unknown";
      
      if (flagged) {
        riskEl.classList.add("flagged");
        riskEl.textContent = "⚠️ Flagged - Already Reported";
      } else if (riskLower.includes("low") || riskLower.includes("safe")) {
        riskEl.classList.add("safe");
      } else if (riskLower.includes("medium") || riskLower.includes("moderate")) {
        riskEl.classList.add("moderate");
      } else {
        riskEl.classList.add("danger");
      }

      // Render criteria
      criteriaEl.innerHTML = "";
      if (criteria && Object.keys(criteria).length > 0) {
        for (const [category, result] of Object.entries(criteria)) {
          const isPassed = typeof result === "string" && result === "passed";
          const hasReasons = Array.isArray(result) && result.length > 0;
          
          const categoryName = category.replace(/_/g, " ");
          
          const criteriaItem = document.createElement("div");
          criteriaItem.className = "criteria-item";
          
          const header = document.createElement("div");
          header.className = "criteria-header";
          
          const name = document.createElement("div");
          name.className = "criteria-name";
          name.textContent = categoryName;
          
          const status = document.createElement("div");
          status.className = `criteria-status ${isPassed ? "passed" : "failed"}`;
          status.textContent = isPassed ? "✓ Passed" : "✗ Failed";
          
          header.appendChild(name);
          header.appendChild(status);
          
          criteriaItem.appendChild(header);
          
          if (hasReasons) {
            const reasonsDiv = document.createElement("div");
            reasonsDiv.className = "criteria-reasons";
            const ul = document.createElement("ul");
            result.forEach(reason => {
              const li = document.createElement("li");
              li.textContent = reason;
              ul.appendChild(li);
            });
            reasonsDiv.appendChild(ul);
            criteriaItem.appendChild(reasonsDiv);
          }
          
          criteriaEl.appendChild(criteriaItem);
        }
      }

      // Show status, hide loading
      loadingEl.style.display = "none";
      statusEl.style.display = "block";

      // Report button handler
      reportBtn.addEventListener("click", async () => {
        reportBtn.disabled = true;
        reportBtn.innerHTML = '<span>⏳</span><span>Reporting...</span>';
        
        try {
          const res = await fetch("http://localhost:5000/report", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: new URL(tab.url).hostname })
          });

          if (res.ok) {
            const data = await res.json();
            showSuccess(`Fraud reported to blockchain! Transaction: ${data.tx?.substring(0, 20)}...`);
            
            // Update UI to show flagged status
            riskEl.className = "risk-badge flagged";
            riskEl.textContent = "⚠️ Flagged - Already Reported";
          } else {
            showError("Failed to report fraud. Please try again.");
            reportBtn.disabled = false;
            reportBtn.innerHTML = '<span>🚨</span><span>Report Fraud</span>';
          }
        } catch (err) {
          console.error("Report error:", err);
          showError("Error reporting fraud. Please check your connection.");
          reportBtn.disabled = false;
          reportBtn.innerHTML = '<span>🚨</span><span>Report Fraud</span>';
        }
      });
    });
  } catch (err) {
    console.error("Error:", err);
    showError("An error occurred. Please try again.");
  }

  function showError(message) {
    loadingEl.style.display = "none";
    statusEl.style.display = "none";
    errorEl.textContent = message;
    errorEl.style.display = "block";
  }

  function showSuccess(message) {
    successEl.textContent = message;
    successEl.style.display = "block";
    setTimeout(() => {
      successEl.style.display = "none";
    }, 5000);
  }
});
