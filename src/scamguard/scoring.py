"""Combine ML probability + rule findings into one 0-100 risk score.

ML probability is *calibrated to the decision thresholds* so that
  p = 0.5            -> risk 30  (start of "suspicious")
  p = thr_danger     -> risk 60  (start of "dangerous"; thr_danger = probability at ~1 % false-positive rate)
"""
from __future__ import annotations

from typing import Dict, List, Optional

VERDICTS = ((60, "dangerous"), (30, "suspicious"), (0, "low_risk"))


def calibrate(p: float, thr_danger: float = 0.9) -> float:
    p = max(0.0, min(1.0, p))
    thr_danger = max(0.55, min(0.995, thr_danger))
    if p < 0.5:
        return 0.6 * p
    if p < thr_danger:
        return 0.30 + 0.30 * (p - 0.5) / (thr_danger - 0.5)
    return 0.60 + 0.40 * (p - thr_danger) / (1.0 - thr_danger)


def combine(ml_prob: Optional[float], findings: List, thr_danger: float = 0.9, ml_cap: Optional[float] = None) -> Dict:
    ml_risk = 0.0 if ml_prob is None else calibrate(ml_prob, thr_danger)
    if ml_cap is not None:
        ml_risk = min(ml_risk, ml_cap)
    keep = 1.0 - ml_risk
    seen = set()
    for f in findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        keep *= 1.0 - max(0.0, min(0.95, f.weight))
    risk = round(100 * (1 - keep))
    return {"risk": risk, "verdict": next(v for t, v in VERDICTS if risk >= t), "ml_risk": round(100 * ml_risk)}
