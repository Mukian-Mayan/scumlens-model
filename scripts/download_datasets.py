#!/usr/bin/env python3
"""Download every public source we know. Never crashes; prints a status table.

Run from a machine with open internet (some hosts are blocked in restricted sandboxes).
Files land in data/raw/ (+ data/raw/external/ for the big academic sets); then run
    python scripts/build_unified_dataset.py && python scripts/build_lists.py
"""
import io, sys, zipfile
from pathlib import Path
import requests
ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"; EXT = RAW / "external"; EXT.mkdir(parents=True, exist_ok=True)

SOURCES = [  # (name, url, dest, kind)
    ("Phishing.Database ACTIVE links (MIT)", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt", RAW / "phishdb_links.txt", "raw"),
    ("OpenPhish community feed", "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt", RAW / "openphish_feed.txt", "raw"),
    ("Top-1M domains (zer0h)", "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains", RAW / "top_domains.txt", "raw"),
    ("PhiUSIIL (UCI #967)", "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip", EXT / "phiusiil.csv", "zip-csv"),
    ("Tranco top-1M", "https://tranco-list.eu/top-1m.csv.zip", EXT / "tranco.csv", "zip-csv"),
    ("PhishTank online-valid", "https://data.phishtank.com/data/online-valid.csv", EXT / "phishtank.csv", "raw"),
]
MANUAL = [
    "LegitPhish (PMC12552964): follow the data-availability link in the paper, save as data/raw/external/legitphish.csv (needs columns url + label).",
    "Your own East-Africa scam reports: append URLs to data/raw/external/phish_ea_reports.txt (one per line) - they are merged automatically.",
    "Your own verified-legit local sites: data/raw/external/benign_ea_verified.txt (one domain per line).",
]
for name, url, dest, kind in SOURCES:
    try:
        r = requests.get(url, timeout=120, headers={"User-Agent": "scamguard-dataset-fetch/0.1"})
        r.raise_for_status()
        if kind == "zip-csv":
            z = zipfile.ZipFile(io.BytesIO(r.content)); n = next(x for x in z.namelist() if x.lower().endswith(".csv"))
            dest.write_bytes(z.read(n))
        else:
            dest.write_bytes(r.content)
        print(f"OK    {name:42s} -> {dest.relative_to(ROOT)} ({dest.stat().st_size/1e6:.1f} MB)")
    except Exception as e:
        print(f"FAIL  {name:42s} {type(e).__name__}: {str(e)[:80]}")
print("\nManual steps:"); [print(" -", m) for m in MANUAL]
