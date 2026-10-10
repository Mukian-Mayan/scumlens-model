"""Rule-based detectors. Complements the ML models; every finding carries an id
that maps to a human explanation in i18n/<lang>.json ("key points").

Detectors
  check_url(url)             -> lexical key points (from features_url)
  check_text(text)           -> SMS / chat / page-text scams (mobile money, loans, jobs, investment, ...)
  check_whatsapp(url, text)  -> WhatsApp takeover / fake-app / deep-link lures
  check_html(html, url)      -> API & behaviour sniffing in page source
  check_file(name, ...)      -> dangerous / disguised file names
  check_oauth_url(url)       -> consent-phishing / token-theft handshakes
  check_app(perms, ...)      -> Android permission-combo risk
  check_usb(device)          -> BadUSB-style class heuristics
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from . import features_url as fu
from .lexicons import BRAND_OFFICIAL_DOMAINS

RULES = json.loads((Path(__file__).resolve().parents[2] / "rules" / "rules.json").read_text())

# weights for URL key points (ML does the heavy lifting; these only feed explanations)
URL_POINT_WEIGHT = {
    "ip_host": 0.25, "at_symbol": 0.25, "brand_impersonation": 0.35, "free_host": 0.1, "shortener": 0.1,
    "risky_tld": 0.1, "lookalike_chars": 0.25, "many_subdomains": 0.1, "scam_keywords": 0.15,
    "risky_download": 0.4, "no_https": 0.05, "very_long_url": 0.05, "redirect_param": 0.15, "odd_port": 0.1,
}


@dataclass
class Finding:
    id: str
    category: str
    weight: float
    evidence: str = ""

    def to_dict(self):
        return asdict(self)


def _compile(rule_list, key="patterns"):
    for r in rule_list:
        r["_re"] = [re.compile(p, re.I) for p in r.get(key, [])]
    return rule_list


_compile(RULES["text_rules"])
_compile(RULES["html_rules"])
for _r in RULES["whatsapp_rules"]:
    for k in ("patterns", "host_patterns", "path_patterns", "url_patterns", "context_patterns"):
        _r["_" + k] = [re.compile(p, re.I) for p in _r.get(k, [])]


def _snippet(m, text, pad=30):
    s = max(m.start() - pad, 0)
    return text[s: m.end() + pad].replace("\n", " ").strip()[:140]


# ------------------------------------------------------------------ URL
def check_url(url: str) -> List[Finding]:
    f = fu.extract(url)
    return [Finding(i, "url", URL_POINT_WEIGHT.get(i, 0.1)) for i in fu.key_points(f)]


# ----------------------------------------------------------------- text
def check_text(text: str) -> List[Finding]:
    out = []
    t = text or ""
    for r in RULES["text_rules"]:
        for rx in r["_re"]:
            m = rx.search(t)
            if m:
                out.append(Finding(r["id"], r["category"], r["weight"], _snippet(m, t)))
                break
    return out


# ------------------------------------------------------------- whatsapp
def check_whatsapp(url: str = "", text: str = "") -> List[Finding]:
    out = []
    host = fu.split_url(url)[2] if url else ""
    path = (fu.split_url(url)[3] if url else "") or ""
    official = host in ("whatsapp.com", "www.whatsapp.com", "web.whatsapp.com", "wa.me", "api.whatsapp.com",
                        "chat.whatsapp.com", "faq.whatsapp.com", "business.whatsapp.com", "whatsapp.net", "l.wl.co")
    for r in RULES["whatsapp_rules"]:
        rid = r["id"]
        if rid == "wa_takeover_lure":
            for rx in r["_patterns"]:
                m = rx.search(text or "") or rx.search(unquote(url or ""))
                if m:
                    out.append(Finding(rid, "whatsapp", r["weight"], _snippet(m, (text or url))))
                    break
        elif rid == "wa_fake_app" and host and not official:
            hit = any(rx.search(host) for rx in r["_host_patterns"]) or any(rx.search(path) for rx in r["_path_patterns"])
            if hit:
                out.append(Finding(rid, "whatsapp", r["weight"], host))
        elif rid == "wa_deeplink_abuse" and url:
            if any(rx.search(url) for rx in r["_url_patterns"]):
                out.append(Finding(rid, "whatsapp", r["weight"], url[:140]))
        elif rid == "wa_group_promo" and url and any(rx.search(url) for rx in r["_url_patterns"]):
            if text and any(rx.search(text) for rx in r["_context_patterns"]):
                out.append(Finding(rid, "whatsapp", r["weight"], url[:140]))
    return out


# ----------------------------------------------------------------- html
def check_html(html: str, url: str = "") -> List[Finding]:
    out = []
    h = html or ""
    host = fu.split_url(url)[2] if url else ""
    reg = fu.registered_domain(host)
    for r in RULES["html_rules"]:
        if r.get("needs_brand_mismatch"):
            # password form on a page that mentions a big brand but is not hosted by it
            if r["_re"][0].search(h):
                low = h.lower()
                brands = [b for b in ("paypal", "microsoft", "google", "facebook", "instagram", "whatsapp", "apple",
                                      "netflix", "mpesa", "m-pesa", "safaricom", "mtn", "airtel", "equity", "stanbic", "kcb", "dfcu")
                          if b in low]
                if brands and reg not in BRAND_OFFICIAL_DOMAINS and not any(b in reg for b in brands):
                    out.append(Finding("credential_form_fake_brand", "phishing", r["weight"], ",".join(brands[:3])))
            continue
        for rx in r["_re"]:
            m = rx.search(h)
            if m:
                out.append(Finding(r["id"], r["category"], r["weight"], _snippet(m, h)))
                break
    # form posts to another host
    for m in re.finditer(r"<form[^>]+action=['\"](https?://[^'\"]+|//[^'\"]+)['\"]", h, re.I):
        fh = fu.split_url(m.group(1) if not m.group(1).startswith("//") else "http:" + m.group(1))[2]
        if fh and host and fu.registered_domain(fh) != reg:
            out.append(Finding("external_form_submit", "phishing", 0.3, fh))
            break
    if re.search(r"type=['\"]password['\"]", h, re.I) and url.lower().startswith("http://"):
        out.append(Finding("password_form_no_https", "phishing", 0.35, "http + password field"))
    return out


# ----------------------------------------------------------------- file
def check_file(name: str, size: Optional[int] = None, mime: str = "", source_url: str = "") -> List[Finding]:
    fr = RULES["file_rules"]
    out = []
    n = (name or "").strip()
    low = n.lower()
    if any(c in n for c in fr["bidi_chars"]):
        out.append(Finding("file_rtl_override", "file", 0.7, "right-to-left override character in name"))
    parts = [p for p in re.split(r"\.", low) if p != ""]
    ext = parts[-1] if len(parts) > 1 else ""
    if ext in fr["critical_ext"]:
        out.append(Finding("file_critical_ext", "file", 0.45 if ext != "apk" else 0.35, f".{ext}"))
    if ext in fr["macro_ext"]:
        out.append(Finding("file_macro_doc", "file", 0.4, f".{ext}"))
    if ext in fr["archive_ext"]:
        out.append(Finding("file_archive", "file", 0.15, f".{ext}"))
    if len(parts) >= 3 and parts[-2] in fr["document_ext"] and (ext in fr["critical_ext"] or ext in fr["macro_ext"] or ext in fr["archive_ext"]):
        out.append(Finding("file_double_ext", "file", 0.6, ".".join(parts[-2:])))
    if ext and ext not in set(fr["known_safe_ext"]) | set(fr["critical_ext"]) | set(fr["macro_ext"]) | set(fr["archive_ext"]):
        out.append(Finding("file_unknown_ext", "file", 0.15, f".{ext}"))
    if not ext and len(n) > 0 and mime and "octet-stream" in mime:
        out.append(Finding("file_unknown_ext", "file", 0.15, "no extension / octet-stream"))
    if size is not None and ext in ("pdf", "doc", "docx", "jpg", "png") and size < 2048:
        out.append(Finding("file_unknown_ext", "file", 0.15, "suspiciously tiny document"))
    if len(n) > 90 and ext in fr["critical_ext"]:
        out.append(Finding("file_double_ext", "file", 0.2, "very long name hides the real extension"))
    return out


# ---------------------------------------------------------------- oauth
def check_oauth_url(url: str) -> List[Finding]:
    o = RULES["oauth_rules"]
    out = []
    sp = urlsplit(url)
    q = {k.lower(): v for k, v in parse_qs(sp.query).items()}
    host = (sp.hostname or "").lower()
    looks_oauth = {"client_id", "redirect_uri", "response_type"} & set(q)
    if not looks_oauth and "devicelogin" not in url.lower():
        return out
    scopes = " ".join(q.get("scope", [])).lower().replace("+", " ")
    risky = [s for s in o["risky_scopes"] if s.lower() in scopes]
    if risky:
        out.append(Finding("oauth_broad_scope", "handshake", 0.35, ",".join(risky[:4])))
    if "token" in " ".join(q.get("response_type", [])).lower().split():
        out.append(Finding("oauth_implicit_token", "handshake", 0.3, "response_type=token"))
    ru = (q.get("redirect_uri") or [""])[0]
    if ru:
        rh = fu.split_url(ru)[2]
        if rh and (fu.registered_domain(rh) != fu.registered_domain(host)) and rh not in ("localhost", "127.0.0.1"):
            if host not in o["known_auth_hosts"]:
                out.append(Finding("oauth_redirect_mismatch", "handshake", 0.4, rh))
            elif fu.extract(ru)["is_free_host"] or fu.extract(ru)["tld_risky"] or fu.extract(ru)["is_ip_host"]:
                out.append(Finding("oauth_redirect_mismatch", "handshake", 0.45, rh))
    if host not in o["known_auth_hosts"] and re.search(r"(devicelogin|device-?code|user_code)", url, re.I):
        out.append(Finding("device_code_lure", "handshake", 0.5, host))
    return out


# ------------------------------------------------------------------ app
def check_app(permissions: Iterable[str], package: str = "", installer: str = "", sideloaded: Optional[bool] = None,
              label: str = "") -> List[Finding]:
    a = RULES["app_rules"]
    perms = set(permissions or [])
    out = []
    for p, w in a["dangerous_permissions"].items():
        if p in perms:
            out.append(Finding("app_perm_" + p.rsplit(".", 1)[1].lower(), "app", w, p))
    for c in a["combos"]:
        if set(c["needs"]) <= perms:
            out.append(Finding(c["id"], "app", c["weight"], "+".join(x.rsplit(".", 1)[1] for x in c["needs"])))
    if sideloaded is None:
        sideloaded = bool(installer) and installer not in a["trusted_installers"]
    if sideloaded and out:
        out.append(Finding("app_sideloaded", "app", 0.25, installer or "unknown installer"))
    return out


# ------------------------------------------------------------------ usb
def check_usb(device: Dict) -> List[Finding]:
    """device = {"name": str, "interfaces": [class ints], "expected": "charge"|"data"|"hid"|"unknown"}"""
    cls = RULES["usb_rules"]["classes"]
    ifs = set(device.get("interfaces", []))
    exp = device.get("expected", "unknown")
    out = []
    if cls["hid"] in ifs and exp == "charge":
        out.append(Finding("usb_hid_on_cable", "hardware", 0.7, "keyboard/mouse interface on a charge-only accessory"))
    if cls["hid"] in ifs and cls["mass_storage"] in ifs:
        out.append(Finding("usb_composite_hid_storage", "hardware", 0.55, "keyboard + storage in one device"))
    if ({cls["cdc_comm"], cls["cdc_data"], cls["wireless"]} & ifs) and exp in ("charge", "storage"):
        out.append(Finding("usb_unexpected_network", "hardware", 0.5, "network/serial interface not expected for this accessory"))
    return out
