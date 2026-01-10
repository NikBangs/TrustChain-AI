chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "EVALUATE_PAGE") {
    const domain = window.location.hostname;
    const content = document.body.innerText.toLowerCase();

    fetch("http://localhost:5000/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, content })
    })
      .then(res => res.json())
      .then(data => sendResponse(data))
      .catch(err => {
        console.error("Fetch failed:", err);
        sendResponse(null);
      });

    return true;  // keep the message channel open
  }
});
