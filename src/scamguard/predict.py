"""High-level API: one call -> verdict + explained findings.

    from scamguard.predict import Scanner
    s = Scanner()
    s.scan_url("http://mpesa-loan.xyz/apply", lang="sw")
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

from . import features_url as fu, rules
from .i18n import category_label, explain, verdict_label
from .scoring import combine

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "models"
LISTS = ROOT / "data" / "lists"


class Scanner:
    def __init__(self, models_dir: Path = MODELS, use_ensemble: bool = True):
        self.models_dir = Path(models_dir)
        self.device = self.ens = None
        p = self.models_dir / "url_device.onnx"
        if p.exists():
            import onnxruntime as ort
            self.device = ort.InferenceSession(str(p), providers=["CPUExecutionProvider"])
        j = self.models_dir / "url_ensemble.joblib"
        if use_ensemble and j.exists():
            import joblib
            self.ens = joblib.load(j)["model"]
        self.thr = json.loads((self.models_dir / "thresholds.json").read_text()) if (self.models_dir / "thresholds.json").exists() else {}
        self.allow, self.deny = set(), set()
        a = LISTS / "allowlist_domains.txt"
        if a.exists():
            self.allow = set(a.read_text().split())
        dn = LISTS / "denylist_hosts.txt.gz"
        if dn.exists():
            import gzip
            self.deny = set(gzip.open(dn, "rt").read().split())
        self.deep = None
        d = self.models_dir / "deep_ensemble.joblib"
        if d.exists():
            import joblib
            self.deep = joblib.load(d)

    # --------------------------------------------------------------- ML
    def url_prob(self, url: str, prefer: str = "ensemble") -> Optional[float]:
        x = np.asarray([fu.vector(url)], dtype=np.float32)
        if prefer == "ensemble" and self.ens is not None:
            return float(self.ens.predict_proba(x)[0, 1])
        if self.device is not None:
            out = self.device.run(None, {self.device.get_inputs()[0].name: x})
            return float(out[1][0][1])
        return None

    def deep_prob(self, url: str, content: Dict[str, float]) -> Optional[float]:
        if not self.deep:
            return None
        cols = self.deep["feature_names"]
        f = {**fu.extract(url), **content}
        x = np.asarray([[float(f.get(c, 0.0)) for c in cols]], dtype=np.float32)
        return float(self.deep["model"].predict_proba(x)[0, 1])

    # ----------------------------------------------------------- scans
    def _reputation(self, url: str):
        """-> (extra findings, ml_cap, trusted?) from allow/deny lists."""
        host = fu.split_url(url)[2]
        if host in self.deny:
            return [rules.Finding("known_bad_host", "url", 0.9, host)], None, False
        reg = fu.registered_domain(host)
        f = fu.extract(url)
        if reg in self.allow and not f["is_free_host"] and not f["is_shortener"] and not f["brand_in_subdomain"] \
                and not f["has_userinfo"] and not f["is_ip_host"]:
            return [], 0.12, True
        return [], None, False

    def _pack(self, ml_prob, findings: List[rules.Finding], lang: str, extra=None, ml_cap=None) -> Dict:
        comb = combine(ml_prob, findings, self.thr.get("ensemble", 0.9), ml_cap)
        seen, items = set(), []
        for f in sorted(findings, key=lambda f: -f.weight):
            if f.id in seen:
                continue
            seen.add(f.id)
            e = explain(f.id, lang)
            items.append({"id": f.id, "category": f.category, "category_label": category_label(f.category, lang),
                          "severity": "high" if f.weight >= 0.4 else "medium" if f.weight >= 0.2 else "low",
                          "title": e["title"], "why": e["why"], "tip": e["tip"], "evidence": f.evidence})
        out = {"risk": comb["risk"], "trusted_domain": ml_cap is not None, "verdict": comb["verdict"], "verdict_label": verdict_label(comb["verdict"], lang),
               "ml_probability": None if ml_prob is None else round(ml_prob, 4), "findings": items, "lang": lang}
        if extra:
            out.update(extra)
        return out

    def scan_url(self, url: str, lang: str = "en", prefer: str = "ensemble", context_text: str = "") -> Dict:
        f = rules.check_url(url) + rules.check_whatsapp(url, context_text) + rules.check_oauth_url(url)
        if context_text:
            f += rules.check_text(context_text)
        rf, cap, _ = self._reputation(url)
        return self._pack(self.url_prob(url, prefer), f + rf, lang, {"url": url, "mode": "url"}, cap)

    def scan_text(self, text: str, lang: str = "en") -> Dict:
        urls = [u for u in __import__("re").findall(r"https?://[^\s<>\"']+|wa\.me/[^\s]+", text)]
        f = rules.check_text(text) + rules.check_whatsapp("", text)
        probs = []
        for u in urls[:5]:
            f += rules.check_url(u) + rules.check_whatsapp(u, text) + self._reputation(u)[0]
            p = self.url_prob(u)
            if p is not None:
                probs.append(p)
        return self._pack(max(probs) if probs else None, f, lang, {"urls": urls[:5], "mode": "text"})

    def scan_file(self, name: str, size: Optional[int] = None, mime: str = "", lang: str = "en") -> Dict:
        return self._pack(None, rules.check_file(name, size, mime), lang, {"name": name, "mode": "file"})

    def scan_app(self, permissions, package: str = "", installer: str = "", lang: str = "en") -> Dict:
        return self._pack(None, rules.check_app(permissions, package, installer), lang, {"package": package, "mode": "app"})

    def scan_usb(self, device: Dict, lang: str = "en") -> Dict:
        return self._pack(None, rules.check_usb(device), lang, {"mode": "usb"})

    def scan_page(self, url: str, html: str, content: Optional[Dict] = None, lang: str = "en") -> Dict:
        """Deep scan from already-fetched HTML (use scraper.fetch to get it)."""
        f = rules.check_url(url) + rules.check_html(html, url) + rules.check_whatsapp(url, html[:5000])
        p = self.deep_prob(url, content) if content else None
        if p is None:
            p = self.url_prob(url)
        rf, cap, _ = self._reputation(url)
        return self._pack(p, f + rf, lang, {"url": url, "mode": "page"}, cap)

    def scan_live(self, url: str, lang: str = "en") -> Dict:
        from .scraper import fetch, content_features
        res = fetch(url)
        extra = {"fetch_ok": res.ok, "fetch_error": res.error, "redirects": res.redirects, "tls": res.tls,
                 "domain_age_days": res.domain_age_days}
        if not res.ok:
            r = self.scan_url(url, lang)
            r.update(extra)
            return r
        r = self.scan_page(res.final_url or url, res.html, content_features(res), lang)
        findings = []
        if res.domain_age_days is not None and res.domain_age_days < 30:
            findings.append(rules.Finding("new_domain", "url", 0.3, f"{res.domain_age_days} days old"))
        if res.tls and not res.tls.get("valid", True):
            findings.append(rules.Finding("bad_tls", "url", 0.3, res.tls.get("error", "")))
        if len(res.redirects) >= 3:
            findings.append(rules.Finding("many_redirects", "url", 0.2, f"{len(res.redirects)} hops"))
        if findings:
            ml = r["ml_probability"]
            all_f = [rules.Finding(i["id"], i["category"], {"high": 0.4, "medium": 0.2, "low": 0.1}[i["severity"]]) for i in r["findings"]] + findings
            r = self._pack(ml, all_f, lang, {"url": url, "mode": "page"})
        r.update(extra)
        return r
