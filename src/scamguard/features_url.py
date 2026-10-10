"""Lexical URL features (the *on-device* feature set).

Design rules
------------
* Pure string logic, no network, no third-party libraries -> trivially portable
  to Dart. `export.py` writes `feature_spec.json` + `parity_vectors.json` so the
  Flutter implementation can be unit-tested against this one.
* The order of FEATURE_NAMES *is* the model input order. Never reorder without
  retraining and re-exporting.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Tuple

from .lexicons import (
    BRANDS, BRAND_OFFICIAL_DOMAINS, FREE_HOSTS, MULTI_PART_SUFFIXES,
    RISKY_FILE_EXTENSIONS_IN_URL, RISKY_TLDS, SUSPICIOUS_KEYWORDS,
    URL_SHORTENERS,
)

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_IP = re.compile(r"^0x[0-9a-f]+$")
_DIGIT_RUN = re.compile(r"\d+")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------
def split_url(url: str) -> Tuple[str, str, str, str, str, int]:
    """Return (scheme, userinfo, host, path, query, port) - lowercase host.

    Tolerant: accepts URLs without scheme and with junk. Never raises.
    """
    u = (url or "").strip()
    scheme = ""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", u)
    if m:
        scheme = m.group(1).lower()
        u = u[m.end():]
    # fragment off
    u = u.split("#", 1)[0]
    # authority ends at first / ?
    cut = len(u)
    for ch in "/?":
        i = u.find(ch)
        if i != -1:
            cut = min(cut, i)
    authority, rest = u[:cut], u[cut:]
    userinfo = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
    port = -1
    host = authority
    if host.startswith("["):  # IPv6 literal
        end = host.find("]")
        if end != -1:
            if host[end + 1:].startswith(":") and host[end + 2:].isdigit():
                port = int(host[end + 2:])
            host = host[: end + 1]
    elif ":" in host:
        h, _, p = host.rpartition(":")
        if p.isdigit():
            host, port = h, int(p)
    host = host.lower().strip(".")
    path, query = rest, ""
    if "?" in rest:
        path, query = rest.split("?", 1)
    return scheme, userinfo, host, path, query, port


def registered_domain(host: str) -> str:
    """eTLD+1 approximation (see MULTI_PART_SUFFIXES)."""
    if not host or _IPV4.match(host) or host.startswith("["):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last2 = ".".join(labels[-2:])
    if last2 in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def tld_of(host: str) -> str:
    if not host or "." not in host:
        return ""
    return host.rsplit(".", 1)[1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _count_in(text: str, tokens) -> int:
    return sum(1 for t in tokens if t in text)


def _on_list(host: str, listing) -> bool:
    """True if host equals or is a subdomain of an entry in `listing`."""
    return any(host == d or host.endswith("." + d) for d in listing)


# --------------------------------------------------------------------------
# Feature definition
# --------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    "url_len", "host_len", "path_len", "query_len",
    "n_dots_host", "n_hyphens_host", "n_digits_host", "digit_ratio_host",
    "letter_ratio_url", "n_subdomains", "is_ip_host", "has_at_symbol",
    "has_userinfo", "nonstd_port", "is_https", "n_slashes_path",
    "path_depth", "n_params", "n_pct_encoded", "n_special_chars",
    "entropy_host", "entropy_path", "has_punycode", "tld_len",
    "tld_risky", "longest_label_len", "max_digit_run_host",
    "kw_in_host", "kw_in_path", "kw_in_query", "brand_in_subdomain",
    "brand_in_regdomain_extra", "brand_in_path", "is_shortener",
    "is_free_host", "double_slash_in_path", "risky_file_ext",
    "double_extension", "has_hex_or_octal_ip", "repeated_chars_host",
    "avg_label_len", "n_labels", "hyphen_digit_mix_host",
    "path_has_php_or_html", "query_has_url", "query_has_email",
    "scheme_in_path", "is_homoglyph_like",
]


def _brand_features(host: str, reg: str, path_q: str) -> Tuple[int, int, int]:
    sub_part = host[: -len(reg)].rstrip(".") if host.endswith(reg) else host
    reg_label = reg.split(".")[0] if reg else ""
    official = reg in BRAND_OFFICIAL_DOMAINS
    in_sub = in_extra = in_path = 0
    if not official:
        for b in BRANDS:
            if b in sub_part:
                in_sub = 1
            if b in reg_label and b != reg_label:
                in_extra = 1
            if in_sub and in_extra:
                break
    # brand token in the path of a host that is not that brand
    if not official:
        low = path_q.lower()
        in_path = int(any(b in low for b in BRANDS))
    return in_sub, in_extra, in_path


def extract(url: str) -> Dict[str, float]:
    """Compute the feature dict for one URL. Never raises."""
    url = (url or "").strip()
    scheme, userinfo, host, path, query, port = split_url(url)
    reg = registered_domain(host)
    tld = tld_of(host)
    labels = [l for l in host.split(".") if l] if host else []
    is_ip = int(bool(_IPV4.match(host)) or host.startswith("["))
    n_digits_host = sum(ch.isdigit() for ch in host)
    low_path = path.lower()
    low_query = query.lower()
    low_host = host

    sub_part = host[: -len(reg)].rstrip(".") if (reg and host.endswith(reg)) else ""
    n_sub = len([l for l in sub_part.split(".") if l]) if sub_part else 0
    if low_host.startswith("www.") and n_sub:
        n_sub -= 1

    in_sub, in_extra, in_path = _brand_features(host, reg, low_path + "?" + low_query)

    last_seg = low_path.rsplit("/", 1)[-1]
    ext = last_seg.rsplit(".", 1)[1] if "." in last_seg else ""
    parts = last_seg.split(".")
    double_ext = int(
        len(parts) >= 3 and parts[-1] in RISKY_FILE_EXTENSIONS_IN_URL
        and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp4", "mp3"}
    )
    digit_runs = _DIGIT_RUN.findall(host)
    letters_url = sum(ch.isalpha() for ch in url)
    rep = 1 if re.search(r"(.)\1\1", host) else 0
    # homoglyph-ish: digits swapped into alphabetic tokens (paypa1, g00gle) or mixed scripts
    homoglyph = int(bool(re.search(r"[a-z][0135][a-z]|[a-z]{2,}[01]\.", reg + ".")) or any(ord(c) > 127 for c in host))

    f = {
        "url_len": len(url),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "n_dots_host": host.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": n_digits_host,
        "digit_ratio_host": n_digits_host / len(host) if host else 0.0,
        "letter_ratio_url": letters_url / len(url) if url else 0.0,
        "n_subdomains": n_sub,
        "is_ip_host": is_ip,
        "has_at_symbol": int("@" in url.split("?", 1)[0]),
        "has_userinfo": int(bool(userinfo)),
        "nonstd_port": int(port not in (-1, 80, 443)),
        "is_https": int(scheme == "https"),
        "n_slashes_path": path.count("/"),
        "path_depth": len([s for s in path.split("/") if s]),
        "n_params": len([p for p in query.split("&") if p]) if query else 0,
        "n_pct_encoded": len(_PCT.findall(url)),
        "n_special_chars": sum(url.count(c) for c in "=&%?_~$!*"),
        "entropy_host": entropy(host),
        "entropy_path": entropy(path),
        "has_punycode": int("xn--" in host),
        "tld_len": len(tld),
        "tld_risky": int(tld in RISKY_TLDS),
        "longest_label_len": max((len(l) for l in labels), default=0),
        "max_digit_run_host": max((len(r) for r in digit_runs), default=0),
        "kw_in_host": _count_in(host, SUSPICIOUS_KEYWORDS),
        "kw_in_path": _count_in(low_path, SUSPICIOUS_KEYWORDS),
        "kw_in_query": _count_in(low_query, SUSPICIOUS_KEYWORDS),
        "brand_in_subdomain": in_sub,
        "brand_in_regdomain_extra": in_extra,
        "brand_in_path": in_path,
        "is_shortener": int(_on_list(host, URL_SHORTENERS)),
        "is_free_host": int(_on_list(host, FREE_HOSTS)),
        "double_slash_in_path": int("//" in path),
        "risky_file_ext": int(ext in RISKY_FILE_EXTENSIONS_IN_URL),
        "double_extension": double_ext,
        "has_hex_or_octal_ip": int(bool(_HEX_IP.match(host)) or bool(re.match(r"^0\d+(\.\d+){3}$", host))),
        "repeated_chars_host": rep,
        "avg_label_len": (sum(len(l) for l in labels) / len(labels)) if labels else 0.0,
        "n_labels": len(labels),
        "hyphen_digit_mix_host": int("-" in reg and any(ch.isdigit() for ch in reg)),
        "path_has_php_or_html": int(bool(re.search(r"\.(php|html?|aspx?|jsp|cgi)(\b|$)", low_path))),
        "query_has_url": int(bool(re.search(r"(https?%3a|https?://|=www\.)", low_query))),
        "query_has_email": int(bool(re.search(r"[\w.+-]+(@|%40)[\w-]+\.[\w.]+", low_query))),
        "scheme_in_path": int(bool(re.search(r"https?(:|%3a)(//|%2f%2f)", low_path))),
        "is_homoglyph_like": homoglyph,
    }
    return f


def vector(url: str) -> List[float]:
    f = extract(url)
    return [float(f[n]) for n in FEATURE_NAMES]


def matrix(urls):
    import numpy as np
    return np.asarray([vector(u) for u in urls], dtype="float32")


# Human-readable key points used for explanations (id -> predicate on feature dict)
def key_points(f: Dict[str, float]) -> List[str]:
    """Return explanation ids (see i18n.py) for features that fired."""
    out = []
    if f["is_ip_host"]:
        out.append("ip_host")
    if f["has_userinfo"] or f["has_at_symbol"]:
        out.append("at_symbol")
    if f["brand_in_subdomain"] or f["brand_in_regdomain_extra"]:
        out.append("brand_impersonation")
    if f["is_free_host"]:
        out.append("free_host")
    if f["is_shortener"]:
        out.append("shortener")
    if f["tld_risky"]:
        out.append("risky_tld")
    if f["has_punycode"] or f["is_homoglyph_like"]:
        out.append("lookalike_chars")
    if f["n_subdomains"] >= 3:
        out.append("many_subdomains")
    if f["kw_in_host"] + f["kw_in_path"] >= 3:
        out.append("scam_keywords")
    if f["risky_file_ext"] or f["double_extension"]:
        out.append("risky_download")
    if not f["is_https"]:
        out.append("no_https")
    if f["url_len"] > 120:
        out.append("very_long_url")
    if f["query_has_url"] or f["scheme_in_path"]:
        out.append("redirect_param")
    if f["nonstd_port"]:
        out.append("odd_port")
    return out
