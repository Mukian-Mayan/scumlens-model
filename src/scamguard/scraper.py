"""Safety-conscious page fetcher (NO JavaScript execution).

Run this on the backend, ideally inside a throw-away container. Guards:
  * refuses private / loopback / link-local targets (SSRF)
  * http/https only, hard timeout, hard size cap, max 5 redirects
  * never writes fetched content to disk, never follows downloads
For JavaScript-heavy pages, swap `fetch()` for a Playwright-based fetcher with
the same return shape (see README, "Dynamic pages").
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import datetime as dt
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import requests

from .features_content import extract_content
from .features_url import registered_domain, split_url

MAX_BYTES = 1_500_000
UA = "Mozilla/5.0 (Linux; Android 14) ScamGuardScanner/0.1 (+safety-research)"


class UnsafeTarget(Exception):
    pass


def assert_public(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise UnsafeTarget(f"dns failure: {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise UnsafeTarget(f"non-public address {ip}")


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    ok: bool = False
    status: int = 0
    html: str = ""
    redirects: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""
    tls: Dict = field(default_factory=dict)
    domain_age_days: Optional[int] = None


def tls_info(host: str, port: int = 443, timeout: float = 4.0) -> Dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
        nb = dt.datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z")
        na = dt.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in c.get("issuer", ()))
        return {"valid": True, "issuer": issuer.get("organizationName", ""), "age_days": (dt.datetime.utcnow() - nb).days,
                "lifetime_days": (na - nb).days}
    except Exception as e:  # invalid cert, timeout, etc. is itself a signal
        return {"valid": False, "error": type(e).__name__}


def domain_age_days(domain: str) -> Optional[int]:
    try:
        import whois  # python-whois, optional
        w = whois.whois(domain)
        c = w.creation_date
        c = c[0] if isinstance(c, list) else c
        return (dt.datetime.utcnow() - c).days if c else None
    except Exception:
        return None


def fetch(url: str, timeout: float = 6.0, with_whois: bool = True) -> FetchResult:
    if "://" not in url:
        url = "http://" + url
    r = FetchResult(url=url)
    sch, _, host, _, _, _ = split_url(url)
    if sch not in ("http", "https"):
        r.error = "unsupported scheme"
        return r
    try:
        assert_public(host)
        sess = requests.Session()
        sess.max_redirects = 5
        cur = url
        for _ in range(6):
            resp = sess.get(cur, headers={"User-Agent": UA}, timeout=timeout, allow_redirects=False, stream=True)
            if resp.is_redirect or resp.is_permanent_redirect:
                nxt = urljoin(cur, resp.headers.get("Location", ""))
                assert_public(split_url(nxt)[2])
                r.redirects.append(nxt)
                cur = nxt
                continue
            ctype = resp.headers.get("Content-Type", "")
            r.status, r.final_url = resp.status_code, cur
            r.headers = {k.lower(): v for k, v in resp.headers.items()}
            if "text/html" in ctype or "xml" in ctype or not ctype:
                buf = b""
                for chunk in resp.iter_content(16384):
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        break
                r.html = buf.decode(resp.encoding or "utf-8", errors="ignore")
            r.ok = True
            break
    except UnsafeTarget as e:
        r.error = f"blocked: {e}"
    except requests.RequestException as e:
        r.error = type(e).__name__
    if split_url(r.final_url or url)[0] == "https":
        r.tls = tls_info(split_url(r.final_url or url)[2])
    if with_whois:
        r.domain_age_days = domain_age_days(registered_domain(host))
    return r


def content_features(res: FetchResult):
    return extract_content(res.html, res.final_url or res.url, len(res.redirects))
