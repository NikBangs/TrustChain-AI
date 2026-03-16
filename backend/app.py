# app.py – Flask app with scoring + logs endpoint

from flask import Flask, request, jsonify
from flask_cors import CORS
from scorer import evaluate
from logger import get_recent_logs, log_debug

app = Flask(__name__)
CORS(app)

@app.route("/evaluate", methods=["POST"])
def evaluate_site():
    data = request.get_json()
    domain = data.get("domain")
    content = data.get("content")

    trust_score, risk, criteria = evaluate(domain, content)

    return jsonify({
        "trust_score": trust_score,
        "risk": risk,
        "criteria": criteria
    })


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    domain = data.get("domain")
    log_debug(f"[Report] Domain manually reported as suspicious: {domain}")
    return jsonify({"status": "logged"})


@app.route("/logs", methods=["GET"])
def recent_logs():
    logs = get_recent_logs(n=10)
    return jsonify(logs)


if __name__ == "__main__":
    app.run(debug=True)
