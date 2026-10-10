#!/usr/bin/env python3
"""Build reputation lists used next to the ML model.

  data/lists/allowlist_domains.txt   registered domains of the top-N popular sites + regional seed
                                     (ML score is dampened for these; free-hosts/shorteners are excluded)
  data/lists/denylist_hosts.txt.gz   unique hosts seen in known phishing feeds (exact-host match)

Run after downloading raw data:  python scripts/build_lists.py [--top 50000]
"""
import argparse, gzip, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from scamguard.features_url import registered_domain, split_url  # noqa: E402
from scamguard.lexicons import FREE_HOSTS, URL_SHORTENERS  # noqa: E402

ap = argparse.ArgumentParser(); ap.add_argument("--top", type=int, default=50000); a = ap.parse_args()
RAW, OUT = ROOT / "data" / "raw", ROOT / "data" / "lists"; OUT.mkdir(parents=True, exist_ok=True)
shared = set(FREE_HOSTS) | set(URL_SHORTENERS)

allow = []
for src in (RAW / "top_domains.txt", ROOT / "data" / "seed" / "regional_benign.txt"):
    if not src.exists(): continue
    n = 0
    for l in open(src, errors="ignore"):
        d = l.strip().split(",")[-1].lower()
        if not d or d.startswith("#"): continue
        reg = registered_domain(d)
        if reg in shared or any(reg.endswith("." + s) for s in shared): continue
        allow.append(reg); n += 1
        if src.name == "top_domains.txt" and n >= a.top: break
allow = sorted(set(allow))
allow_set = set(allow)
(OUT / "allowlist_domains.txt").write_text("\n".join(allow) + "\n")

hosts = set()
for f in ("phishdb_links.txt", "openphish_feed.txt"):
    p = RAW / f
    if p.exists():
        for l in open(p, errors="ignore"):
            h = split_url(l.strip())[2]
            if h and "." in h and h not in allow_set and registered_domain(h) not in allow_set: hosts.add(h)
with gzip.open(OUT / "denylist_hosts.txt.gz", "wt") as fh:
    fh.write("\n".join(sorted(hosts)) + "\n")
print(f"allowlist {len(allow):,} domains, denylist {len(hosts):,} hosts")
