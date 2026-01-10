# app.py – Flask app with scoring + logs endpoint

from flask import Flask, request, jsonify
from flask_cors import CORS
from scorer import evaluate
from blockchain import is_reported, report_site
from logger import get_recent_logs

app = Flask(__name__)
CORS(app)

@app.route("/evaluate", methods=["POST"])
def evaluate_site():
    data = request.get_json()
    domain = data.get("domain")
    content = data.get("content")

    flagged = is_reported(domain)
    trust_score, risk, criteria = evaluate(domain, content)

    return jsonify({
        "trust_score": trust_score,
        "risk": risk,
        "flagged": flagged,
        "criteria": criteria
    })


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    domain = data.get("domain")
    tx = report_site(domain)
    return jsonify({"status": "logged", "tx": tx})


@app.route("/logs", methods=["GET"])
def recent_logs():
    logs = get_recent_logs(n=10)
    return jsonify(logs)


if __name__ == "__main__":
    app.run(debug=True)
