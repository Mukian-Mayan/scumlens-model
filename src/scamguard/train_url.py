"""Train the URL models.

  python -m scamguard.train_url            # full training
  python -m scamguard.train_url --fast     # small/quick run for smoke tests

Outputs (models/):
  url_device.onnx          small gradient-boosted model for on-device use
  url_ensemble.joblib      soft-voting RF + HGB + LR (backend)
  url_ensemble.onnx        (best effort) ONNX of the ensemble
  metrics_url.json         honest evaluation incl. bias checks
  model_card_url.md        human-readable summary
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import features_url as fu

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "unified" / "unified_urls.csv.gz"
MODELS = ROOT / "models"


def load(path=DATA, limit=None):
    df = pd.read_csv(path, compression="gzip")
    if limit:
        df = df.sample(n=min(limit, len(df)), random_state=0)
    return df.reset_index(drop=True)


def featurize(df):
    return fu.matrix(df["url"].tolist())


def strip_path(url: str) -> str:
    sch, _, host, _, _, port = fu.split_url(url)
    return f"{sch or 'http'}://{host}" + (f":{port}" if port not in (-1, 80, 443) else "")


def metrics(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y)), "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, p), 4) if len(set(y)) > 1 else None,
        "pr_auc": round(average_precision_score(y, p), 4) if len(set(y)) > 1 else None,
        "fpr": round(fp / max(fp + tn, 1), 4), "fnr": round(fn / max(fn + tp, 1), 4),
    }


def threshold_for_fpr(y, p, target=0.01):
    fpr, tpr, thr = roc_curve(y, p)
    ok = np.where(fpr <= target)[0]
    return float(thr[ok[-1]]) if len(ok) else 0.99


def make_device_model(fast=False):
    # Classic GradientBoosting (not Hist...) because it converts cleanly to ONNX (~300 KB).
    return GradientBoostingClassifier(
        n_estimators=60 if fast else 150, max_depth=5, subsample=0.8, learning_rate=0.1, random_state=7)


def make_ensemble(fast=False):
    rf = RandomForestClassifier(n_estimators=60 if fast else 150, min_samples_leaf=3, n_jobs=-1,
                                random_state=7, max_features="sqrt")
    hgb = HistGradientBoostingClassifier(max_iter=80 if fast else 300, max_depth=8, learning_rate=0.1,
                                         l2_regularization=1.0, random_state=11)
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=500, C=1.0))
    return VotingClassifier([("rf", rf), ("hgb", hgb), ("lr", lr)], voting="soft", weights=[2, 3, 1])


def to_onnx(model, n_features, path):
    from skl2onnx import to_onnx as _to_onnx
    from skl2onnx.common.data_types import FloatTensorType  # noqa: F401
    onx = _to_onnx(model, np.zeros((1, n_features), dtype=np.float32), options={id(model): {"zipmap": False}},
                   target_opset={"": 15, "ai.onnx.ml": 3})
    Path(path).write_bytes(onx.SerializeToString())


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--data", default=str(DATA))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--target-fpr", type=float, default=0.01)
    a = ap.parse_args(argv)

    t0 = time.time()
    df = load(a.data, a.limit or (30000 if a.fast else None))
    print(f"rows={len(df):,}  phishing={int(df.label.sum()):,}")
    X = featurize(df)
    y = df["label"].values
    w = df["weight"].values
    print(f"features: {X.shape}  ({time.time() - t0:.0f}s)")

    # group-aware split: all URLs of a registered domain stay on one side -> no leakage
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    tr, te = next(gss.split(X, y, groups=df["reg_domain"]))
    synth = (df["kind"] == "synthetic_scam").values
    te_real = te[~synth[te]]  # never grade on the synthetic rows

    dev = make_device_model(a.fast).fit(X[tr], y[tr], sample_weight=w[tr])
    ens = make_ensemble(a.fast)
    ens.fit(X[tr], y[tr], sample_weight=w[tr]) if _supports_sw() else ens.fit(X[tr], y[tr])

    MODELS.mkdir(exist_ok=True)
    report = {"rows": int(len(df)), "train": int(len(tr)), "test_real": int(len(te_real)),
              "split": "GroupShuffleSplit by registered domain, 80/20", "models": {}}
    for name, m in (("device_gb", dev), ("ensemble_vote", ens)):
        p = m.predict_proba(X[te_real])[:, 1]
        thr_fpr = threshold_for_fpr(y[te_real], p, a.target_fpr)
        r = {"overall@0.5": metrics(y[te_real], p, 0.5),
             f"overall@fpr{a.target_fpr}": metrics(y[te_real], p, thr_fpr),
             "threshold_for_target_fpr": round(thr_fpr, 4)}
        # ---- bias checks ----------------------------------------------------
        sub = df.iloc[te_real]
        for kind in ("host_only", "augmented_benign", "full_url"):
            mask = (sub["kind"] == kind).values
            if mask.sum() > 20 and len(set(y[te_real][mask])) >= 1:
                pp, yy = p[mask], y[te_real][mask]
                r[f"kind={kind}"] = {"n": int(mask.sum()), "positive_rate_flagged": round(float((pp >= 0.5).mean()), 4),
                                     "label_mean": round(float(yy.mean()), 4)}
        # phishing with the path removed -> does the model still catch bare phishing hosts?
        ph_idx = te_real[y[te_real] == 1]
        if len(ph_idx):
            bare = fu.matrix([strip_path(u) for u in df.iloc[ph_idx]["url"]])
            r["phishing_path_stripped_recall@0.5"] = round(float((m.predict_proba(bare)[:, 1] >= 0.5).mean()), 4)
        report["models"][name] = r
        print(f"\n== {name}")
        print(json.dumps(r["overall@0.5"]))
        print("FPR-targeted:", json.dumps(r[f"overall@fpr{a.target_fpr}"]))

    # per-source recall on phishing test rows (ensemble)
    pe = ens.predict_proba(X[te_real])[:, 1]
    srcs = df.iloc[te_real]["source"].values
    report["recall_by_source@0.5"] = {s: round(float((pe[(srcs == s) & (y[te_real] == 1)] >= 0.5).mean()), 4)
                                      for s in sorted(set(srcs)) if ((srcs == s) & (y[te_real] == 1)).sum() > 10}
    # synthetic regional rows held in test: informational only (templates are ours)
    syn_te = te[synth[te]]
    if len(syn_te):
        report["synthetic_regional_recall@0.5_(informational)"] = round(
            float((ens.predict_proba(X[syn_te])[:, 1] >= 0.5).mean()), 4)

    # sanity set: well-known legitimate URLs with real paths (never used for fitting)
    sp = ROOT / "data" / "seed" / "sanity_benign_urls.txt"
    if sp.exists():
        urls = [l.strip() for l in sp.read_text().splitlines() if l.strip() and not l.startswith("#")]
        Xs = fu.matrix(urls)
        rep = {}
        for nm, m in (("device_gb", dev), ("ensemble_vote", ens)):
            ps = m.predict_proba(Xs)[:, 1]
            rep[nm] = {"n": len(urls), "flagged@0.5": int((ps >= 0.5).sum()),
                       "worst": [(urls[i], round(float(ps[i]), 3)) for i in np.argsort(-ps)[:5]]}
        report["sanity_benign_set"] = rep
        print("sanity benign set:", json.dumps({k: (v["flagged@0.5"], v["n"]) for k, v in rep.items()}))

    # feature importance (RF inside the ensemble)
    rf = ens.named_estimators_["rf"]
    imp = sorted(zip(fu.FEATURE_NAMES, rf.feature_importances_), key=lambda t: -t[1])[:15]
    report["top_features_rf"] = [(n, round(float(v), 4)) for n, v in imp]

    # ---- persist --------------------------------------------------------------
    import joblib
    joblib.dump({"model": ens, "feature_names": fu.FEATURE_NAMES}, MODELS / "url_ensemble.joblib", compress=3)
    to_onnx(dev, len(fu.FEATURE_NAMES), MODELS / "url_device.onnx")
    try:
        to_onnx(ens, len(fu.FEATURE_NAMES), MODELS / "url_ensemble.onnx")
    except Exception as e:  # pragma: no cover
        print("ensemble ONNX export skipped:", e, file=sys.stderr)

    thr = {"device": report["models"]["device_gb"]["threshold_for_target_fpr"],
           "ensemble": report["models"]["ensemble_vote"]["threshold_for_target_fpr"],
           "suspicious": 0.5, "dangerous": 0.85, "target_fpr": a.target_fpr}
    (MODELS / "thresholds.json").write_text(json.dumps(thr, indent=2))
    (MODELS / "metrics_url.json").write_text(json.dumps(report, indent=2))
    write_card(report, df)
    print(f"\nDone in {time.time() - t0:.0f}s. Artifacts in {MODELS}")


def _supports_sw():
    # VotingClassifier forwards sample_weight when every sub-estimator supports it; the LR pipeline does not
    # accept it unless routed, so we do not pass weights to the ensemble (weights only used for device model).
    return False


def write_card(report, df):
    d = report["models"]["device_gb"]["overall@0.5"]
    e = report["models"]["ensemble_vote"]["overall@0.5"]
    txt = f"""# URL model card (auto-generated)

Rows: {report['rows']:,} (train {report['train']:,}, held-out real test {report['test_real']:,}).
Split: {report['split']}.

| model | accuracy | precision | recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| device (GB, ONNX ~300KB) | {d['accuracy']} | {d['precision']} | {d['recall']} | {d['f1']} | {d['roc_auc']} | {d['fpr']} |
| ensemble (RF+HGB+LR) | {e['accuracy']} | {e['precision']} | {e['recall']} | {e['f1']} | {e['roc_auc']} | {e['fpr']} |

**Read the numbers with care.** The benign class is mostly *bare popular domains* (some given
synthetic realistic paths) while the phishing class is mostly *real phishing URLs*. High scores here
partly measure "popular domain vs. throw-away URL". Add PhiUSIIL / LegitPhish / your own benign
URLs-with-paths (see data/DATASETS.md) and retrain before trusting the figures. See `metrics_url.json`
for the bias checks (`kind=*`, `phishing_path_stripped_recall`).
"""
    (MODELS / "model_card_url.md").write_text(txt)


if __name__ == "__main__":
    main()
