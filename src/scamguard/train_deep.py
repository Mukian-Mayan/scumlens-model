"""Train the backend *deep* model (URL + page-content features).

Two data routes (use either / both):
  A) PhiUSIIL (UCI #967): put the CSV at data/raw/external/phiusiil.csv. Its label 1 = LEGITIMATE (we flip it).
  B) Your own scraped pages: data/content/collected.csv produced by scripts/collect_content.py
     columns: url,label,<CONTENT_FEATURES...>

  python -m scamguard.train_deep [--limit N]
Output: models/deep_ensemble.joblib, models/metrics_deep.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from . import features_url as fu
from .features_content import CONTENT_FEATURES
from .train_url import metrics

ROOT = Path(__file__).resolve().parents[2]
PHIUSIIL = ROOT / "data" / "raw" / "external" / "phiusiil.csv"
COLLECTED = ROOT / "data" / "content" / "collected.csv"


def load_frames(phiusiil=PHIUSIIL, collected=COLLECTED, limit=None):
    frames = []
    if Path(phiusiil).exists():
        d = pd.read_csv(phiusiil)
        d["label"] = 1 - d["label"]  # PhiUSIIL: 1 = legitimate -> flip so 1 = phishing
        have = [c for c in CONTENT_FEATURES if c in d.columns]
        frames.append(d[["URL", "label"] + have].rename(columns={"URL": "url"}))
    if Path(collected).exists():
        c = pd.read_csv(collected)
        frames.append(c[["url", "label"] + [x for x in CONTENT_FEATURES if x in c.columns]])
    if not frames:
        raise SystemExit("No content data found. Provide PhiUSIIL CSV or run scripts/collect_content.py (see README).")
    df = pd.concat(frames, ignore_index=True)
    for c in CONTENT_FEATURES:
        if c not in df.columns:
            df[c] = 0.0
    df[CONTENT_FEATURES] = df[CONTENT_FEATURES].fillna(0.0)
    if limit:
        df = df.sample(min(limit, len(df)), random_state=0)
    return df.reset_index(drop=True)


def build_X(df):
    U = fu.matrix(df["url"].tolist())
    C = df[CONTENT_FEATURES].to_numpy(dtype="float32")
    return np.hstack([U, C]), fu.FEATURE_NAMES + CONTENT_FEATURES


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--phiusiil", default=str(PHIUSIIL))
    ap.add_argument("--collected", default=str(COLLECTED))
    ap.add_argument("--out", default=str(ROOT / "models"))
    a = ap.parse_args(argv)
    df = load_frames(a.phiusiil, a.collected, a.limit)
    X, names = build_X(df)
    y = df["label"].values
    groups = df["url"].map(lambda u: fu.registered_domain(fu.split_url(u)[2]))
    tr, te = next(GroupShuffleSplit(1, test_size=0.2, random_state=3).split(X, y, groups=groups))
    model = VotingClassifier([
        ("rf", RandomForestClassifier(200, min_samples_leaf=2, n_jobs=-1, random_state=1)),
        ("hgb", HistGradientBoostingClassifier(max_iter=250, max_depth=8, random_state=2)),
    ], voting="soft").fit(X[tr], y[tr])
    p = model.predict_proba(X[te])[:, 1]
    rep = {"rows": int(len(df)), "n_features": len(names), "test": metrics(y[te], p, 0.5)}
    # content-only ablation: how much do page features add over URL-only?
    n_url = len(fu.FEATURE_NAMES)
    base = HistGradientBoostingClassifier(max_iter=250, max_depth=8, random_state=2).fit(X[tr][:, :n_url], y[tr])
    rep["url_only_baseline_auc"] = round(float(roc_auc_score(y[te], base.predict_proba(X[te][:, :n_url])[:, 1])), 4)
    out = Path(a.out)
    out.mkdir(exist_ok=True)
    import joblib
    joblib.dump({"model": model, "feature_names": names}, out / "deep_ensemble.joblib", compress=3)
    (out / "metrics_deep.json").write_text(json.dumps(rep, indent=2))
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
