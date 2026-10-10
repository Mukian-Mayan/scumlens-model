"""Explanation lookup with English fallback."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

D = Path(__file__).with_name("locales")
LANGS = sorted(p.stem for p in D.glob("*.json"))


@lru_cache(maxsize=None)
def _load(lang: str):
    p = D / f"{lang}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def explain(fid: str, lang: str = "en") -> dict:
    en = _load("en")["findings"].get(fid, {"title": fid, "why": "", "tip": ""})
    loc = _load(lang).get("findings", {}).get(fid, {}) if lang != "en" else {}
    return {"title": loc.get("title", en["title"]), "why": loc.get("why", en["why"]), "tip": loc.get("tip", en["tip"]),
            "lang": lang if loc else "en"}


def verdict_label(v: str, lang: str = "en") -> str:
    return _load(lang).get("verdicts", {}).get(v) or _load("en")["verdicts"][v]


def category_label(c: str, lang: str = "en") -> str:
    return _load(lang).get("categories", {}).get(c) or _load("en")["categories"].get(c, c)
