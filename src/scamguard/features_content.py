"""Page-content features for the *backend* deep model.

Column names deliberately match the PhiUSIIL dataset (UCI #967) so the same
feature set can be trained from PhiUSIIL's CSV or from pages you scrape yourself.
Only features we can compute reliably from one HTML response are included.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlsplit

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

CONTENT_FEATURES: List[str] = [
    "LineOfCode", "LargestLineLength", "HasTitle", "HasFavicon", "IsResponsive",
    "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "Bank", "Pay", "Crypto", "HasCopyrightInfo", "NoOfImage", "NoOfCSS",
    "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    "DomainTitleMatchScore", "NoOfURLRedirect",
]
_SOCIAL = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com", "whatsapp.com", "t.me", "tiktok.com")


def _host(u: str) -> str:
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def empty() -> Dict[str, float]:
    return {k: 0.0 for k in CONTENT_FEATURES}


def extract_content(html: str, url: str, n_redirects: int = 0) -> Dict[str, float]:
    f = empty()
    if not html or BeautifulSoup is None:
        return f
    lines = html.splitlines() or [html]
    f["LineOfCode"] = len(lines)
    f["LargestLineLength"] = max(len(l) for l in lines)
    f["NoOfURLRedirect"] = n_redirects
    soup = BeautifulSoup(html, "lxml")
    host = _host(url)
    low = html.lower()

    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    f["HasTitle"] = int(bool(title))
    f["HasFavicon"] = int(bool(soup.find("link", rel=lambda v: v and "icon" in " ".join(v).lower() if isinstance(v, list) else v and "icon" in v.lower())))
    f["IsResponsive"] = int(bool(soup.find("meta", attrs={"name": "viewport"})))
    f["HasDescription"] = int(bool(soup.find("meta", attrs={"name": "description"})))
    f["NoOfPopup"] = len(re.findall(r"window\.open\s*\(", low))
    f["NoOfiFrame"] = len(soup.find_all("iframe"))
    f["NoOfImage"] = len(soup.find_all("img"))
    f["NoOfCSS"] = len(soup.find_all("link", rel=lambda v: v and "stylesheet" in (" ".join(v) if isinstance(v, list) else v).lower()))
    f["NoOfJS"] = len(soup.find_all("script"))

    ext_submit = 0
    for form in soup.find_all("form"):
        act = (form.get("action") or "").strip()
        h = _host(act) if act.startswith(("http://", "https://", "//")) else ""
        if act.startswith("//"):
            h = _host("http:" + act)
        if h and h != host:
            ext_submit = 1
        if act in ("", "#") or act.lower().startswith("javascript:") or act.lower().startswith("mailto:"):
            ext_submit = ext_submit or 0
    f["HasExternalFormSubmit"] = ext_submit
    f["HasSubmitButton"] = int(bool(soup.find(["button", "input"], attrs={"type": "submit"})) or bool(soup.find("button")))
    f["HasHiddenFields"] = int(bool(soup.find("input", attrs={"type": "hidden"})))
    f["HasPasswordField"] = int(bool(soup.find("input", attrs={"type": "password"})))

    self_ref = empty_ref = ext_ref = 0
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href in ("", "#") or href.lower().startswith(("javascript:", "#")):
            empty_ref += 1
        elif href.startswith(("http://", "https://", "//")):
            h = _host(href if not href.startswith("//") else "http:" + href)
            if h == host or h.endswith("." + host):
                self_ref += 1
            else:
                ext_ref += 1
                if any(h == s or h.endswith("." + s) for s in _SOCIAL):
                    f["HasSocialNet"] = 1
        else:
            self_ref += 1
    f["NoOfSelfRef"], f["NoOfEmptyRef"], f["NoOfExternalRef"] = self_ref, empty_ref, ext_ref

    text = soup.get_text(" ", strip=True).lower()
    f["Bank"] = int(bool(re.search(r"\b(bank|banking|iban|swift|account number|sacco)\b", text)))
    f["Pay"] = int(bool(re.search(r"\b(pay now|payment|checkout|credit card|debit card|m-?pesa|mobile money|momo|airtel money)\b", text)))
    f["Crypto"] = int(bool(re.search(r"\b(bitcoin|btc|ethereum|usdt|crypto|wallet connect|airdrop|metamask)\b", text)))
    f["HasCopyrightInfo"] = int(bool(re.search(r"(©|&copy;|copyright)", low)))

    reg_label = host.split(".")[-2] if host.count(".") >= 1 else host
    if title and reg_label:
        tt = re.sub(r"[^a-z0-9]", "", title.lower())
        f["DomainTitleMatchScore"] = 100.0 if reg_label in tt else 0.0
    return f
