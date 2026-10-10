"""Export everything the Flutter app needs to reproduce the Python behaviour.

  python -m scamguard.export     ->  export/
      url_device.onnx          model
      feature_spec.json        feature names/order + all lexicons + thresholds
      rules.json               detection rules
      locales/*.json           explanations
      allowlist_domains.txt / denylist_hosts.txt.gz   reputation lists (bundle allowlist; denylist is a downloadable update)
      parity_vectors.json      [{url, features[], prob}]  -> unit-test the Dart port against these
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import numpy as np

from . import features_url as fu, lexicons as L
from .predict import MODELS, Scanner

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "export"

PARITY_URLS = [
    "https://www.google.com/", "https://safaricom.co.ke/mpesa", "http://mpesa-loan-approved.xyz/apply?id=123",
    "http://192.168.0.5:8080/login.php", "https://paypal.com.secure-verify.web.app/signin", "bit.ly/3xYz",
    "http://user@evil.example.com/a.apk", "https://xn--pple-43d.com/id", "https://mtn-momo-promo-ug.top/claim/88421",
    "https://docs.python.org/3/library/re.html", "http://invoice.pdf.exe.example.org/Invoice.pdf.exe",
    "https://news.example.co.ug/2024/05/story-title-123", "https://a.b.c.d.e.example.com/x?u=http://x.y/z",
]


def main():
    OUT.mkdir(exist_ok=True)
    (OUT / "locales").mkdir(exist_ok=True)
    shutil.copy(MODELS / "url_device.onnx", OUT / "url_device.onnx")
    shutil.copy(ROOT / "rules" / "rules.json", OUT / "rules.json")
    for p in (ROOT / "src" / "scamguard" / "locales").glob("*.json"):
        shutil.copy(p, OUT / "locales" / p.name)
    for f in ("allowlist_domains.txt", "denylist_hosts.txt.gz"):
        if (ROOT / "data" / "lists" / f).exists():
            shutil.copy(ROOT / "data" / "lists" / f, OUT / f)
    thr = json.loads((MODELS / "thresholds.json").read_text()) if (MODELS / "thresholds.json").exists() else {}
    spec = {
        "version": 1, "feature_names": fu.FEATURE_NAMES, "n_features": len(fu.FEATURE_NAMES), "dtype": "float32",
        "thresholds": thr,
        "lexicons": {k: (sorted(v) if isinstance(v, (set, frozenset)) else v) for k, v in vars(L).items()
                     if k.isupper()},
        "notes": ["registered_domain(): last two labels, or three if the last two are in MULTI_PART_SUFFIXES.",
                  "Count keywords with `in` on the lowercase host / path / query (substring, not whole word).",
                  "ONNX output[1] is a [1,2] probability tensor; phishing probability = output[1][0][1]."],
    }
    (OUT / "feature_spec.json").write_text(json.dumps(spec, indent=1))
    s = Scanner()
    vec = []
    for u in PARITY_URLS:
        v = fu.vector(u)
        vec.append({"url": u, "features": v, "device_prob": s.url_prob(u, prefer="device")})
    (OUT / "parity_vectors.json").write_text(json.dumps(vec, indent=1))
    print("exported to", OUT)


if __name__ == "__main__":
    main()
