#!/usr/bin/env python3
"""Scrape page-content features for a sample of URLs from the unified dataset.

SAFETY: phishing pages can serve malware. Run this ONLY inside a disposable container/VM with no
credentials mounted. The scraper never executes JavaScript and never saves page bodies, but stay careful.
Many phishing URLs are already dead - expect a low yield; benign yield is much higher.

  python scripts/collect_content.py --n-phish 3000 --n-benign 3000 --workers 16
Output: data/content/collected.csv   (url,label,<CONTENT_FEATURES>)
"""
import argparse, csv, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from scamguard.features_content import CONTENT_FEATURES  # noqa: E402
from scamguard.scraper import content_features, fetch  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--n-phish", type=int, default=2000); ap.add_argument("--n-benign", type=int, default=2000)
ap.add_argument("--workers", type=int, default=12); ap.add_argument("--timeout", type=float, default=6.0)
a = ap.parse_args()
df = pd.read_csv(ROOT / "data" / "unified" / "unified_urls.csv.gz")
df = df[df.source.isin(["phishing_database", "openphish", "top_domains", "phiusiil", "legitphish", "phishtank", "tranco"])]
full = df[df.kind.isin(["full_url", "host_only", "augmented_benign", "phish_host_only"])]
# benign augmented URLs have invented paths -> fetch the bare host instead
def target(r):
    if r.kind == "augmented_benign":
        from urllib.parse import urlsplit
        s = urlsplit(r.url); return f"{s.scheme}://{s.netloc}/"
    return r.url
pick = pd.concat([full[full.label == 1].sample(a.n_phish, random_state=1), full[full.label == 0].sample(a.n_benign, random_state=1)])
jobs = [(target(r), int(r.label)) for r in pick.itertuples()]
out = ROOT / "data" / "content" / "collected.csv"; out.parent.mkdir(parents=True, exist_ok=True)
def work(j):
    u, lab = j
    res = fetch(u, timeout=a.timeout, with_whois=False)
    if not res.ok or not res.html: return None
    return {"url": u, "label": lab, **content_features(res)}
ok = 0
with open(out, "w", newline="") as fh, ThreadPoolExecutor(a.workers) as ex:
    w = csv.DictWriter(fh, fieldnames=["url", "label"] + CONTENT_FEATURES); w.writeheader()
    for i, fut in enumerate(as_completed([ex.submit(work, j) for j in jobs]), 1):
        r = fut.result()
        if r: w.writerow(r); ok += 1
        if i % 200 == 0: print(f"{i}/{len(jobs)} fetched, {ok} usable", flush=True)
print(f"done: {ok} usable pages -> {out}")
