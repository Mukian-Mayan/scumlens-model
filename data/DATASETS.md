# Data sources → one unified file

`data/unified/unified_urls.csv.gz` (303,000 rows; columns `url,label,source,kind,reg_domain,weight`; label 1 = phishing/scam).

| source | rows (this build) | label | notes / licence |
|---|---|---|---|
| Phishing.Database ACTIVE links | 149,951 (45,158 reduced to bare host) | 1 | MIT. Per-registered-domain cap of 25 so mega-hosts don't dominate |
| OpenPhish community feed | 49 | 1 | free community feed; check terms for commercial use |
| Top-1M domains list (zer0h) | 150k (112k given synthetic paths) | 0 | Alexa-era ranking; licence unclear — replace with Tranco for production |
| Regional seed benign | 49 | 0 | curated East-African domains (`data/seed/regional_benign.txt`) — extend it |
| Synthetic regional scams | 3,000 | 1 | **generated templates** (mobile money, loans, jobs, investment, tax). weight 0.4, excluded from evaluation |
| PhiUSIIL (UCI #967) | – | flipped (their 1 = legit) | CC BY 4.0. Drop CSV at `data/raw/external/phiusiil.csv` |
| LegitPhish | – | 0/1 | save as `data/raw/external/legitphish.csv` |
| PhishTank / Tranco | – | 1 / 0 | `scripts/download_datasets.py` |
| Your own reports | – | 1 / 0 | `data/raw/external/phish_*.txt`, `benign_*.txt` merged automatically |

`kind`: `full_url`, `host_only`, `augmented_benign` (bare benign domain + invented realistic path / www / scheme variation), `phish_host_only` (real phishing URL reduced to its host), `synthetic_scam`.
Why augmentation exists: without it the model learns "has a path / trailing slash / https = phishing" instead of real signals (see README).
Blocked in the build sandbox (re-run `download_datasets.py` locally): UCI/PhiUSIIL, PhishTank, Tranco, PMC.
