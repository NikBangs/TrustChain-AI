import argparse
import csv
import json
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import requests


@dataclass
class Counts:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0


def _normalize_label(raw: str) -> Optional[str]:
    if raw is None:
        return None
    v = str(raw).strip().lower()
    if v in {"fraud", "scam", "malicious", "bad", "1", "true", "yes", "y", "pos", "positive"}:
        return "fraud"
    if v in {"legit", "legitimate", "good", "0", "false", "no", "n", "neg", "negative"}:
        return "legit"
    if v == "":
        return None
    return v


def predict_label(trust_score: Optional[float], risk: Optional[str], threshold: float) -> str:
    if trust_score is not None and trust_score < threshold:
        return "fraud"
    if (risk or "").strip().lower() == "high risk":
        return "fraud"
    return "legit"


def call_evaluate(api_base: str, domain: str, content: str, timeout_s: float) -> Tuple[dict, float]:
    url = api_base.rstrip("/") + "/evaluate"
    payload = {"domain": domain, "content": content}

    t0 = time.perf_counter()
    res = requests.post(url, json=payload, timeout=timeout_s)
    dt_ms = (time.perf_counter() - t0) * 1000.0

    res.raise_for_status()
    return res.json(), dt_ms


def update_counts(counts: Counts, y_true: str, y_pred: str) -> None:
    if y_true == "fraud" and y_pred == "fraud":
        counts.tp += 1
    elif y_true == "legit" and y_pred == "legit":
        counts.tn += 1
    elif y_true == "legit" and y_pred == "fraud":
        counts.fp += 1
    elif y_true == "fraud" and y_pred == "legit":
        counts.fn += 1


def safe_float(v) -> Optional[float]:
    try:
        if v is None:
            return None
        return float(v)
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate dataset.csv against running TrustChain AI backend.")
    parser.add_argument("--input", default="dataset.csv", help="Input CSV path (default: dataset.csv)")
    parser.add_argument("--output", default="dataset_results.csv", help="Output CSV path (default: dataset_results.csv)")
    parser.add_argument("--api", default="http://localhost:5000", help="Backend base URL (default: http://localhost:5000)")
    parser.add_argument("--threshold", type=float, default=50.0, help="Fraud threshold: trust_score < threshold (default: 50)")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-request timeout seconds (default: 60)")
    args = parser.parse_args()

    counts = Counts()
    latencies_ms = []
    processed = 0
    skipped = 0

    with open(args.input, "r", newline="", encoding="utf-8") as f_in, open(
        args.output, "w", newline="", encoding="utf-8"
    ) as f_out:
        reader = csv.DictReader(f_in)
        if reader.fieldnames is None:
            raise SystemExit("Input CSV has no header row.")

        fieldnames = [
            "domain",
            "label_true",
            "label_pred",
            "trust_score",
            "risk",
            "latency_ms",
            "sentiment_label",
            "criteria_json",
            "error",
        ]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            domain = (row.get("domain") or "").strip()
            if not domain:
                skipped += 1
                continue

            label_true = _normalize_label(row.get("label"))
            sentiment_label = row.get("sentiment_label", "")
            content = row.get("content", "") or ""

            try:
                data, dt_ms = call_evaluate(args.api, domain=domain, content=content, timeout_s=args.timeout)
                trust_score = safe_float(data.get("trust_score"))
                risk = data.get("risk")
                criteria = data.get("criteria")

                label_pred = predict_label(trust_score, risk, threshold=args.threshold)

                if label_true in {"fraud", "legit"}:
                    update_counts(counts, y_true=label_true, y_pred=label_pred)

                latencies_ms.append(dt_ms)
                processed += 1

                writer.writerow(
                    {
                        "domain": domain,
                        "label_true": label_true or "",
                        "label_pred": label_pred,
                        "trust_score": "" if trust_score is None else trust_score,
                        "risk": risk or "",
                        "latency_ms": round(dt_ms, 2),
                        "sentiment_label": sentiment_label or "",
                        "criteria_json": json.dumps(criteria, ensure_ascii=False),
                        "error": "",
                    }
                )
            except Exception as e:
                processed += 1
                writer.writerow(
                    {
                        "domain": domain,
                        "label_true": label_true or "",
                        "label_pred": "",
                        "trust_score": "",
                        "risk": "",
                        "latency_ms": "",
                        "sentiment_label": sentiment_label or "",
                        "criteria_json": "",
                        "error": f"{type(e).__name__}: {e}",
                    }
                )

    # ---- Print summary to terminal (optional, but useful) ----
    denom = counts.tp + counts.tn + counts.fp + counts.fn
    accuracy = (counts.tp + counts.tn) / denom if denom else None
    fpr = counts.fp / (counts.fp + counts.tn) if (counts.fp + counts.tn) else None
    fnr = counts.fn / (counts.fn + counts.tp) if (counts.fn + counts.tp) else None
    precision = counts.tp / (counts.tp + counts.fp) if (counts.tp + counts.fp) else None

    lat_mean = (sum(latencies_ms) / len(latencies_ms)) if latencies_ms else None

    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    print(f"Processed rows: {processed} (skipped without domain: {skipped})")
    print(f"Fraud threshold: trust_score < {args.threshold} OR risk == 'high risk'")
    if denom:
        print(f"Confusion matrix: TP={counts.tp} TN={counts.tn} FP={counts.fp} FN={counts.fn}")
        print(f"Accuracy: {accuracy:.4f}" if accuracy is not None else "Accuracy: n/a")
        print(f"False positive rate: {fpr:.4f}" if fpr is not None else "False positive rate: n/a")
        print(f"False negative rate: {fnr:.4f}" if fnr is not None else "False negative rate: n/a")
        print(f"Precision (PPV): {precision:.4f}" if precision is not None else "Precision (PPV): n/a")
    else:
        print("No labeled rows found (label column must be fraud/legit).")
    print(f"Average latency (ms): {lat_mean:.2f}" if lat_mean is not None else "Average latency (ms): n/a")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

