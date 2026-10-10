"""FastAPI backend (deep checks + model updates).

  pip install -r requirements.txt
  uvicorn scamguard.serve:app --app-dir src --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .i18n import LANGS
from .predict import MODELS, Scanner

app = FastAPI(title="ScamGuard API", version="0.1.0")
_scanner: Optional[Scanner] = None


def sc() -> Scanner:
    global _scanner
    if _scanner is None:
        _scanner = Scanner()
    return _scanner


class UrlReq(BaseModel):
    url: str
    lang: str = "en"
    context_text: str = ""


class TextReq(BaseModel):
    text: str
    lang: str = "en"


class FileReq(BaseModel):
    name: str
    size: Optional[int] = None
    mime: str = ""
    lang: str = "en"


class AppReq(BaseModel):
    permissions: List[str]
    package: str = ""
    installer: str = ""
    lang: str = "en"


class UsbReq(BaseModel):
    name: str = ""
    interfaces: List[int] = []
    expected: str = "unknown"
    lang: str = "en"


@app.get("/health")
def health():
    return {"ok": True, "device_model": sc().device is not None, "ensemble": sc().ens is not None,
            "deep": sc().deep is not None, "languages": LANGS}


@app.post("/v1/scan/url")
def scan_url(r: UrlReq):
    return sc().scan_url(r.url, r.lang, context_text=r.context_text)


@app.post("/v1/scan/live")
def scan_live(r: UrlReq):
    """Fetches the page (sandboxed, no JS) and runs the deep checks."""
    return sc().scan_live(r.url, r.lang)


@app.post("/v1/scan/text")
def scan_text(r: TextReq):
    return sc().scan_text(r.text, r.lang)


@app.post("/v1/scan/file")
def scan_file(r: FileReq):
    return sc().scan_file(r.name, r.size, r.mime, r.lang)


@app.post("/v1/scan/app")
def scan_app(r: AppReq):
    return sc().scan_app(r.permissions, r.package, r.installer, r.lang)


@app.post("/v1/scan/usb")
def scan_usb(r: UsbReq):
    return sc().scan_usb(r.model_dump(), r.lang)


@app.get("/v1/model/manifest")
def manifest():
    """The Flutter app polls this to know whether to download a newer on-device model."""
    p = MODELS / "url_device.onnx"
    if not p.exists():
        raise HTTPException(404, "model not built")
    return {"name": "url_device", "format": "onnx", "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "bytes": p.stat().st_size, "download": "/v1/model/url_device.onnx"}


@app.get("/v1/model/url_device.onnx")
def dl():
    return FileResponse(MODELS / "url_device.onnx", media_type="application/octet-stream")
