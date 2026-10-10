#!/usr/bin/env python3
"""Merge every available source into ONE labelled file: data/unified/unified_urls.csv.gz

Columns
-------
url        the URL (scheme included where the source had one)
label      1 = phishing / scam / malicious, 0 = benign
source     where the row came from (see data/DATASETS.md)
kind       full_url | host_only | augmented_benign | phish_host_only | synthetic_scam
reg_domain registered domain (used for group-aware train/test splits)
weight     training weight (synthetic rows are down-weighted)

Sources are picked up automatically if the file exists:
  data/raw/phishdb_links.txt            Phishing.Database ACTIVE links (MIT)
  data/raw/openphish_feed.txt           OpenPhish community feed
  data/raw/top_domains.txt              top-1M domains list (benign, bare domains)
  data/raw/external/phiusiil.csv        PhiUSIIL (UCI #967)  [label 1 = LEGIT there]
  data/raw/external/legitphish.csv      LegitPhish (PMC12552964)
  data/raw/external/phishtank.csv       PhishTank online-valid.csv
  data/raw/external/tranco.csv          Tranco top-1M (rank,domain)
  data/raw/external/*.txt|*.csv         any extra file named  phish_*.{txt,csv} or benign_*.{txt,csv}
  data/seed/regional_benign.txt         East-Africa legitimate domains (curated)
  (regional synthetic scam URLs are generated here, deterministic seed)

Usage:  python scripts/build_unified_dataset.py [--max-phish 150000] [--max-benign 150000]
"""
from __future__ import annotations

import argparse
import csv
import gzip
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from scamguard.features_url import registered_domain, split_url  # noqa: E402

RAW = ROOT / "data" / "raw"
EXT = RAW / "external"
SEED = ROOT / "data" / "seed"
OUT = ROOT / "data" / "unified" / "unified_urls.csv.gz"

rng = random.Random(1337)


def read_lines(p: Path):
    with open(p, errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def clean_url(u: str):
    u = u.strip().strip('"').strip("'")
    if not u or len(u) > 2000 or " " in u:
        return None
    if re.match(r"^(ftp|file|data|javascript):", u, re.I):
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", u):
        u = "http://" + u
    _, _, host, _, _, _ = split_url(u)
    if not host or "." not in host:
        return None
    return u


# ----------------------------------------------------------------- loaders
def load_phish_txt(path: Path, source: str):
    for l in read_lines(path):
        u = clean_url(l)
        if u:
            yield u, 1, source, "full_url"


def load_domains(path: Path, source: str, limit: int):
    n = 0
    for l in read_lines(path):
        d = l.split(",")[-1].strip().lower()  # supports "rank,domain" too
        if not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", d):
            continue
        yield "https://" + d, 0, source, "host_only"
        n += 1
        if n >= limit:
            break


def _find_cols(header):
    low = {h.lower(): h for h in header}
    url_col = next((low[k] for k in ("url", "urls", "link", "website") if k in low), None)
    lab_col = next((low[k] for k in ("label", "class", "status", "result", "type", "phishing") if k in low), None)
    return url_col, lab_col


def load_labelled_csv(path: Path, source: str, legit_is_one: bool = False):
    with open(path, newline="", errors="ignore") as fh:
        rd = csv.DictReader(fh)
        url_col, lab_col = _find_cols(rd.fieldnames or [])
        if not url_col or not lab_col:
            print(f"  ! {path.name}: could not find url/label columns in {rd.fieldnames}; skipped", file=sys.stderr)
            return
        for row in rd:
            u = clean_url(row[url_col])
            if not u:
                continue
            v = str(row[lab_col]).strip().lower()
            if v in ("1", "phishing", "phish", "malicious", "bad", "true", "yes"):
                lab = 1
            elif v in ("0", "legitimate", "legit", "benign", "good", "false", "no", "-1"):
                lab = 0
            else:
                continue
            if legit_is_one:  # PhiUSIIL uses 1 = legitimate
                lab = 1 - lab
            kind = "full_url" if "/" in u.split("://", 1)[1] else "host_only"
            yield u, lab, source, kind


def load_phishtank(path: Path):
    with open(path, newline="", errors="ignore") as fh:
        for row in csv.DictReader(fh):
            u = clean_url(row.get("url", ""))
            if u:
                yield u, 1, "phishtank", "full_url"


# ----------------------------------------------------------- benign augment
_PATHS = [
    "/", "/about", "/contact", "/products", "/products/{n}", "/blog",
    "/blog/{y}/{m}/{slug}", "/news/{slug}", "/news/{y}/{m}/{d}/{slug}",
    "/search?q={slug}", "/category/{slug}", "/help/{slug}", "/pricing",
    "/en/{slug}", "/careers", "/careers/{n}", "/store/{slug}-{n}",
    "/support/articles/{n}", "/docs/{slug}", "/watch?v={tok}", "/wiki/{slug}",
    "/article/{n}/{slug}", "/user/{slug}", "/cart", "/shop?page={n}",
    "/sitemap.xml", "/privacy", "/terms", "/faq", "/en-us/{slug}",
    "/login", "/signin", "/account", "/my-account", "/checkout", "/verify-email?token={tok}",
    "/secure/{slug}", "/update/{slug}", "/index.html", "/index.php", "/home.html", "/wp-login.php",
    "/download", "/payment/{n}", "/support", "/contact-us.html", "/services/{slug}.html",
    "/mpesa", "/mobile-money", "/loans", "/personal/{slug}", "/en/careers/{slug}",
]
_WORDS = ("home update review guide tips news sports weather recipe travel music "
          "health school market price list video photo story report events team "
          "service customer support policy download app pricing plans jobs").split()


def augment_benign(u: str, path_prob: float = 0.75) -> tuple:
    """Randomise formatting of a bare benign domain so that scheme / www / path / trailing slash
    carry NO label information. Returns (url, kind)."""
    scheme, host = u.split("://", 1)
    host = host.rstrip("/")
    if rng.random() < 0.5 and not host.startswith("www."):
        host = "www." + host
    if rng.random() < 0.12:
        scheme = "http"
    if rng.random() < path_prob:
        tpl = rng.choice(_PATHS)
        slug = "-".join(rng.sample(_WORDS, rng.randint(1, 3)))
        path = tpl.format(
            n=rng.randint(1, 99999), y=rng.randint(2018, 2025), m=f"{rng.randint(1, 12):02d}",
            d=f"{rng.randint(1, 28):02d}", slug=slug,
            tok="".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") for _ in range(11)),
        )
        return f"{scheme}://{host}{path}", "augmented_benign"
    return f"{scheme}://{host}" + ("/" if rng.random() < 0.4 else ""), "host_only"


def vary_phish_host(u: str):
    """Real phishing URL reduced to its host (+ optional '/'), so bare phishing hosts exist in training."""
    sch, _, host, _, _, port = split_url(u)
    base = f"{sch or 'http'}://{host}" + (f":{port}" if port not in (-1, 80, 443) else "")
    return base + ("/" if rng.random() < 0.4 else "")


# ------------------------------------------------------- synthetic regional
_BRANDS_EA = ["mpesa", "m-pesa", "safaricom", "mtn", "mtn-momo", "momo", "airtel", "airtel-money",
              "ura", "kra", "nssf", "nhif", "ecitizen", "equity", "stanbic", "dfcu", "absa", "kcb",
              "centenary", "jumia", "sacco", "pesapal", "flutterwave"]
_LURES = ["loan", "fast-loan", "instant-loan", "refund", "tax-refund", "promo", "bonus", "reward",
          "claim", "winner", "verify", "update", "kyc", "reversal", "unlock", "jobs", "vacancy",
          "invest", "double", "profit", "airdrop", "recharge", "free-data", "grant", "scholarship",
          "bet-bonus", "payout", "account-verify", "login", "secure"]
_TLDS = ["xyz", "top", "online", "site", "click", "icu", "cc", "tk", "ml", "ga", "co", "info", "live",
         "vip", "link", "shop", "buzz", "life", "com", "net", "support"]
_CC = ["ug", "ke", "tz", "rw", "ng", "gh"]
_SCAM_PATHS = ["/login.php", "/verify/index.html", "/apply", "/claim?id={n}", "/kyc/update", "/pay/confirm.php",
               "/loan/apply.html", "/secure/login?user={n}", "/promo", "/", "/index.php?acc={n}",
               "/wp-content/uploads/{n}/verify.html", "/app/download.apk", "/jobs/apply?ref={n}",
               "/reversal/request", "/winner/{n}"]
_FREE = ["web.app", "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "pages.dev",
         "netlify.app", "github.io", "firebaseapp.com", "godaddysites.com", "vercel.app"]


def synth_scam(n: int):
    seen = set()
    while len(seen) < n:
        b, l = rng.choice(_BRANDS_EA), rng.choice(_LURES)
        style = rng.random()
        sep = rng.choice(["-", "-", "", "."])
        if style < 0.45:
            host = f"{b}{sep}{l}{rng.choice(['', '-' + rng.choice(_CC), str(rng.randint(1, 99))])}.{rng.choice(_TLDS)}"
        elif style < 0.7:
            host = f"{b}-{l}-{rng.choice(_CC)}.{rng.choice(_FREE)}"
        elif style < 0.85:
            host = f"{b}.{l}.{rng.choice(['com', 'net', 'info'])}.{rng.choice(_TLDS)}"
        else:
            host = f"{rng.choice(['secure', 'www', 'my', 'portal'])}.{b}{rng.choice(['', '-'])}{l}.{rng.choice(_TLDS)}"
        path = rng.choice(_SCAM_PATHS).format(n=rng.randint(10, 999999))
        scheme = rng.choice(["http", "https", "https"])
        seen.add(f"{scheme}://{host}{path}")
    for u in seen:
        yield u, 1, "synthetic_regional", "synthetic_scam"


# -------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-phish", type=int, default=150_000)
    ap.add_argument("--max-benign", type=int, default=150_000)
    ap.add_argument("--n-synthetic", type=int, default=3_000)
    ap.add_argument("--augment-benign-frac", type=float, default=0.75,
                    help="share of bare-domain benign rows that get a synthetic realistic path")
    args = ap.parse_args()

    rows = []  # (url,label,source,kind)

    def add(gen, name):
        c = 0
        for r in gen:
            rows.append(r)
            c += 1
        print(f"  + {name}: {c:,}")

    print("Reading sources ...")
    if (RAW / "phishdb_links.txt").exists():
        add(load_phish_txt(RAW / "phishdb_links.txt", "phishing_database"), "phishing_database")
    if (RAW / "openphish_feed.txt").exists():
        add(load_phish_txt(RAW / "openphish_feed.txt", "openphish"), "openphish")
    if (RAW / "top_domains.txt").exists():
        add(load_domains(RAW / "top_domains.txt", "top_domains", 1_000_000), "top_domains")
    if (SEED / "regional_benign.txt").exists():
        add(load_domains(SEED / "regional_benign.txt", "regional_seed_benign", 10_000), "regional_seed_benign")
    if EXT.exists():
        p = EXT / "phiusiil.csv"
        if p.exists():
            add(load_labelled_csv(p, "phiusiil", legit_is_one=True), "phiusiil")
        p = EXT / "legitphish.csv"
        if p.exists():
            add(load_labelled_csv(p, "legitphish"), "legitphish")
        p = EXT / "phishtank.csv"
        if p.exists():
            add(load_phishtank(p), "phishtank")
        p = EXT / "tranco.csv"
        if p.exists():
            add(load_domains(p, "tranco", 300_000), "tranco")
        for p in sorted(EXT.glob("phish_*")):
            add(load_phish_txt(p, p.stem), p.stem)
        for p in sorted(EXT.glob("benign_*")):
            add(load_domains(p, p.stem, 300_000), p.stem)
    add(synth_scam(args.n_synthetic), "synthetic_regional")

    # dedupe on normalised url
    seen, uniq = set(), []
    for r in rows:
        k = r[0].lower().rstrip("/")
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    print(f"After dedupe: {len(uniq):,}")

    # conflict: same registered domain host-only benign vs phishing host -> keep both (they differ by path)
    phish = [r for r in uniq if r[1] == 1 and r[2] != "synthetic_regional"]
    synth = [r for r in uniq if r[2] == "synthetic_regional"]
    benign = [r for r in uniq if r[1] == 0]

    # cap one phishing registered-domain to avoid mega-hosts (e.g. 20k urls on one free host) dominating
    by_dom = {}
    capped = []
    rng.shuffle(phish)
    for r in phish:
        d = registered_domain(split_url(r[0])[2])
        by_dom[d] = by_dom.get(d, 0) + 1
        if by_dom[d] <= 25:
            capped.append(r)
    print(f"Phishing after per-domain cap (25): {len(capped):,} (from {len(phish):,})")
    phish = capped[: args.max_phish]

    # benign: real-path rows first; bare domains stratified: 40% from the head (rank<=50k), 60% uniform over the long tail
    benign_real = [r for r in benign if r[3] == "full_url"]
    benign_host = [r for r in benign if r[3] == "host_only"]
    seed_b = [r for r in benign_host if r[2] == "regional_seed_benign"]
    other_b = [r for r in benign_host if r[2] != "regional_seed_benign"]
    keep_host = max(args.max_benign - len(benign_real) - len(seed_b), 0)
    head, tail = other_b[:50_000], other_b[50_000:]
    n_head = min(int(keep_host * 0.4), len(head))
    picked = rng.sample(head, n_head) + rng.sample(tail, min(keep_host - n_head, len(tail)))
    benign = benign_real + seed_b + picked

    final = []
    for u, lab, src, kind in phish:
        if rng.random() < 0.30 and kind == "full_url":
            final.append((vary_phish_host(u), 1, src, "phish_host_only", 1.0))
        else:
            final.append((u, 1, src, kind, 1.0))
    for u, lab, src, kind in synth:
        final.append((u, 1, src, kind, 0.4))
    for u, lab, src, kind in benign:
        if kind == "host_only":
            nu, nk = augment_benign(u, args.augment_benign_frac)
            final.append((nu, 0, src, nk, 1.0))
        else:
            final.append((u, 0, src, kind, 1.0))
    rng.shuffle(final)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label", "source", "kind", "reg_domain", "weight"])
        for u, lab, src, kind, wt in final:
            w.writerow([u, lab, src, kind, registered_domain(split_url(u)[2]), wt])

    n1 = sum(1 for r in final if r[1] == 1)
    print(f"\nWrote {OUT.relative_to(ROOT)}  rows={len(final):,}  phishing/scam={n1:,}  benign={len(final) - n1:,}")
    from collections import Counter
    print("By source/kind:")
    for (s, k), c in sorted(Counter((r[2], r[3]) for r in final).items()):
        print(f"  {s:24s} {k:18s} {c:>8,}")


if __name__ == "__main__":
    main()
