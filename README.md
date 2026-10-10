# ScamGuard model package — Checkpoint 1

Python ML + rules engine + API for the mobile scam-detection app (working name; see the UI/UX doc for 20 name options).
The Flutter app (checkpoint 2) consumes the **`export/`** folder (on-device) and the **FastAPI backend** (deep checks).

```
data/raw/            downloaded sources (Phishing.Database, OpenPhish, top-1M domains) - shipped as the separate scamguard_raw_data.zip; unzip it into this folder, or run scripts/download_datasets.py
data/seed/           curated East-Africa benign domains, sanity-check URLs
data/unified/        unified_urls.csv.gz   <- ALL datasets merged into ONE file
data/lists/          allowlist_domains.txt, denylist_hosts.txt.gz
scripts/             download_datasets.py, build_unified_dataset.py, build_lists.py, collect_content.py
src/scamguard/       features_url, features_content, scraper, rules, scoring, i18n/locales, train_url, train_deep, predict, serve, export
rules/rules.json     detection rules (text, WhatsApp, HTML/API sniffing, files, OAuth, apps, USB)
models/              baseline artifacts trained in this session: url_device.onnx, thresholds, metrics, model card.
                     (url_ensemble.joblib, 45 MB, is NOT shipped for size - `python -m scamguard.train_url` recreates it; the Scanner falls back to the device model without it)
export/              everything the Flutter app needs (ONNX model, spec, rules, locales, parity vectors, lists)
tests/               pytest suite (12 tests)
```

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src

python scripts/download_datasets.py          # optional: refresh + add PhiUSIIL, Tranco, PhishTank (needs open internet)
python scripts/build_unified_dataset.py      # -> data/unified/unified_urls.csv.gz  (ONE merged dataset)
python scripts/build_lists.py                # -> allowlist / denylist
python -m scamguard.train_url                # trains device (ONNX) + backend ensemble; ~4 min on 2 CPUs
python -m scamguard.export                   # -> export/ for Flutter
pytest -q tests
uvicorn scamguard.serve:app --app-dir src --port 8000
```

## Architecture (hybrid)
| Layer | Where | What |
|---|---|---|
| Allow/deny lists | device | popular-domain dampening, known-bad hosts (exact match) |
| URL model (48 lexical features, GB → ONNX ~340 KB) | **device** | instant, offline, private; port of `features_url.py` to Dart verified with `export/parity_vectors.json` |
| Rules engine | device + backend | text/SMS scams, WhatsApp lures, file names, OAuth, app permissions, USB class heuristics |
| URL ensemble (RF+HGB+LR) | backend | stronger second opinion |
| Deep model (URL + page content) | backend | needs content data: PhiUSIIL **or** `scripts/collect_content.py`; train with `python -m scamguard.train_deep` |
| Scraper | backend | SSRF-guarded fetch (no JS), TLS info, WHOIS age, redirect chain, HTML API-sniffing |

Final score = calibrated ML probability combined with rule findings (`scoring.py`): risk 0–100 → *low_risk / suspicious (≥30) / dangerous (≥60)*. Every finding carries `title / why / tip` in the user's language (en, sw, fr, es, pt, ar, hi, zh; non-English files currently translate titles for URL/text/WhatsApp findings and fall back to English elsewhere — **machine-drafted, have native speakers review**).

## What the baseline numbers mean (please read)
Held-out test (split by registered domain, 59,643 rows): ensemble **AUC 0.972, accuracy 0.909, FPR 8 % at p≥0.5**, recall 0.72 at 1 % FPR.
These are lower than the 96 %+ quoted in the literature **on purpose**: a first build scored higher but turned out to be exploiting formatting
shortcuts (`www.`, trailing `/`, https, path presence — `google.com/` scored 0.93). We removed them by randomising formatting across both classes,
adding bare-host phishing rows, and sampling benign domains from the long tail. Remaining honest limits:
1. Benign data is **only popular-site domains** (no real benign long-tail URLs with paths) → unknown small legitimate sites are the main false-positive risk. The allowlist handles popular sites; add PhiUSIIL/LegitPhish (real benign URLs) and your own verified local sites, then retrain.
2. Phishing data = Phishing.Database/OpenPhish (global). East-Africa coverage = 3,000 **synthetic** template scam URLs (down-weighted, never used for evaluation) — real local reports are the highest-value data you can add (`data/raw/external/phish_ea_reports.txt`).
3. Sanity set (`data/seed/sanity_benign_urls.txt`, 30 real legit URLs): 1/30 flagged after allowlist (Microsoft OAuth URL).
4. The deep (content) model could **not** be trained here (PhiUSIIL download blocked in the sandbox); the pipeline is tested on a synthetic fixture only. No accuracy claim is made for it.

## Scope honesty — what ML can and cannot do
Dataset-trained: URL / page scam classification. **Rule-based (heuristic, no training data)**: WhatsApp lure patterns, API/behaviour sniffing in page source,
risky files, OAuth consent phishing, app-permission combos, USB class anomalies, mobile-money / loan / job / investment scam text.
Needs **native Android code in the Flutter app** (outside this package): intercepting clicked links system-wide, reading installed-app permissions, USB attach events,
Wi-Fi / captive-portal checks, the floating widget. We cannot detect an *actual* WhatsApp takeover — only the lures that precede it.

## Using it from code
```python
from scamguard.predict import Scanner
s = Scanner()
s.scan_url("http://mpesa-loan.xyz/apply", lang="sw")
s.scan_text("Mistakenly sent you Ksh 5000, kindly reverse")
s.scan_file("Invoice.pdf.exe"); s.scan_app([...perms...], installer="com.unknown")
s.scan_usb({"interfaces": [3], "expected": "charge"})
s.scan_live("https://example.com")      # fetch + deep checks (backend only)
```
REST: `POST /v1/scan/{url|live|text|file|app|usb}`, `GET /v1/model/manifest` (OTA model updates), `GET /health`.

## Safety
`scraper.py` blocks private/loopback targets, caps size/time/redirects, never executes JavaScript or stores bodies. Still run `collect_content.py` only in a disposable VM.
Do not use this tool to take action against individuals; verdicts are probabilistic and should be presented as warnings, never as proof.
