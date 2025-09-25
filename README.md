# src/dns_detector_logs.py

"""
DNS Tunneling Detection from Logs
--------------------------------
Analyzes DNS query logs (CSV/Zeek format) to detect potential DNS
tunneling using heuristics and scoring.
"""

import pandas as pd
import math


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for c in freq:
        p_x = freq[c] / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


def score_query(qname: str) -> float:
    """Compute a simple heuristic score for suspicious DNS queries."""
    labels = qname.split(".")
    max_label_len = max([len(l) for l in labels]) if labels else 0
    entropy = shannon_entropy(qname)
    numeric_ratio = sum(c.isdigit() for c in qname) / len(qname) if qname else 0

    # simple scoring: higher is more suspicious
    score = 0
    if max_label_len > 40:
        score += 1
    if entropy > 3.5:
        score += 1
    if numeric_ratio > 0.5:
        score += 1
    return score


def detect_tunneling(log_file: str, threshold: int = 2) -> pd.DataFrame:
    """
    Detect suspicious DNS queries from a CSV/Zeek log file.

    Parameters
    ----------
    log_file : str
        Path to CSV/Zeek dns log (must contain column 'query').
    threshold : int
        Minimum heuristic score to flag a query as suspicious.

    Returns
    -------
    pd.DataFrame
        DataFrame of suspicious queries with their scores.
    """
    df = pd.read_csv(log_file)
    if "query" not in df.columns:
        raise ValueError("Log file must contain 'query' column")

    df["score"] = df["query"].apply(score_query)
    alerts = df[df["score"] >= threshold].copy()
    return alerts.sort_values(by="score", ascending=False)


if __name__ == "__main__":
    log_file = "examples/sample_dns_log.csv"
    alerts = detect_tunneling(log_file)

    print(f"⚠️ Detected {len(alerts)} suspicious DNS queries:")
    print(alerts.head(20))
# paython-file
