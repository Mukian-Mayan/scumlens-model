# Flutter integration notes (for checkpoint 2)
1. Copy `export/` into `assets/model/` and register in pubspec.
2. On-device inference: `onnxruntime` Flutter plugin; input `float32[1,48]` in `feature_spec.json -> feature_names` order; probability = `output[1][0][1]`.
3. Port `features_url.py` + `scoring.py` + rules to Dart; unit-test with `parity_vectors.json` (|Δ feature| < 1e-4).
4. Load `allowlist_domains.txt` into a Set / bloom filter; apply the same ML-cap logic as `Scanner._reputation`.
5. Deep checks: `POST /v1/scan/live`; model OTA: poll `/v1/model/manifest` (sha256) and swap the ONNX file.
6. Explanations: `locales/<lang>.json` → `findings[id].{title,why,tip}`; fall back to `en`.
