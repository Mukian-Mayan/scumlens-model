"""Shared lexicons used by the URL feature extractor and the rules engine.

Everything here is plain data (lists / sets of lowercase strings) so it can be
exported to JSON (see export.py) and re-used verbatim by the Flutter app. Keep
this file free of logic.
"""

# Public-suffix approximation: suffixes made of two labels. We deliberately do
# not depend on the full Public Suffix List so that the exact same logic can be
# ported to Dart without a 200 KB dependency. Extend freely.
MULTI_PART_SUFFIXES = {
    # East Africa
    "co.ug", "or.ug", "go.ug", "ac.ug", "ne.ug", "sc.ug", "com.ug",
    "co.ke", "or.ke", "go.ke", "ac.ke", "ne.ke", "sc.ke",
    "co.tz", "or.tz", "go.tz", "ac.tz", "co.rw", "ac.rw", "gov.rw",
    "co.zm", "ac.zm", "gov.zm", "co.zw", "ac.zw", "com.et", "gov.et",
    # rest of Africa
    "co.za", "org.za", "gov.za", "ac.za", "com.ng", "gov.ng", "org.ng",
    "edu.ng", "com.gh", "gov.gh", "edu.gh", "com.eg", "gov.eg",
    # world
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "org.au", "gov.au",
    "co.in", "org.in", "gov.in", "ac.in", "com.br", "gov.br", "com.mx",
    "com.cn", "org.cn", "gov.cn", "co.jp", "or.jp", "com.tr", "com.sa",
    "com.pk", "com.bd", "com.my", "com.sg", "co.id", "co.nz", "co.il",
    "com.ar", "com.co", "com.pe", "com.ua", "com.ru",
}

# Hosting / tunnelling / site-builder providers that anyone can use for free.
# A bare domain on one of these is not "bad" by itself, but is heavily abused.
FREE_HOSTS = {
    "000webhostapp.com", "web.app", "firebaseapp.com", "pages.dev",
    "workers.dev", "github.io", "gitlab.io", "weebly.com", "wixsite.com",
    "blogspot.com", "netlify.app", "vercel.app", "glitch.me", "duckdns.org",
    "ngrok.io", "ngrok-free.app", "jimdofree.com", "jimdosite.com",
    "godaddysites.com", "repl.co", "replit.app", "infinityfreeapp.com",
    "epizy.com", "rf.gd", "000webhost.com", "sites.google.com",
    "forms.gle", "run.goorm.io", "herokuapp.com", "onrender.com",
    "surge.sh", "bubbleapps.io", "carrd.co", "webflow.io", "framer.app",
    "mybluehost.me", "yolasite.com", "weeblysite.com", "webcindario.com",
    "wordpress.com", "tumblr.com", "typedream.app", "notion.site",
    "ukit.me", "square.site", "strikingly.com", "godaddysites.com",
    "myfreesites.net", "hpage.com", "bravesites.com", "dynu.net",
    "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "serveo.net",
    "trycloudflare.com", "loca.lt", "tiiny.site", "cf-ipfs.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "s.id", "bl.ink", "lnkd.in", "soo.gd", "v.gd", "clck.ru", "qr.ae",
    "shorte.st", "adf.ly", "bc.vc", "linktr.ee", "wa.link", "l.wl.co",
}

# TLDs with a disproportionate share of abuse (free / cheap registrations).
RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work",
    "support", "country", "kim", "loan", "men", "party", "review", "stream",
    "download", "racing", "win", "bid", "trade", "science", "date", "faith",
    "accountant", "cricket", "zip", "mov", "rest", "fit", "surf", "monster",
    "buzz", "icu", "cyou", "cfd", "sbs", "bond", "quest", "vip", "live",
    "site", "online", "shop", "store", "website", "space", "fun", "life",
}

SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "password",
    "passcode", "credential", "billing", "invoice", "payment", "suspend",
    "suspended", "unlock", "recover", "recovery", "appeal", "alert",
    "authenticate", "authentication", "validate", "restore", "limited",
    "wallet", "refund", "reward", "bonus", "claim", "prize", "winner",
    "gift", "free", "voucher", "giveaway", "promo", "lucky", "offer",
    "loan", "invest", "investment", "crypto", "bitcoin", "airdrop",
    "double", "profit", "forex", "binary", "mining", "staking",
    "job", "jobs", "vacancy", "recruit", "hiring", "visa", "abroad",
    "webmail", "helpdesk", "support", "service", "online", "portal",
    "mpesa", "m-pesa", "momo", "mobilemoney", "pesa", "sacco", "fuliza",
    "tax", "customs", "parcel", "delivery", "tracking", "unpaid",
]

# Brand tokens commonly impersonated (global + East Africa). Tokens are
# matched as substrings of the host / path, lowercase, no spaces.
BRANDS = [
    "paypal", "apple", "icloud", "google", "gmail", "microsoft", "outlook",
    "office365", "onedrive", "sharepoint", "facebook", "instagram",
    "whatsapp", "telegram", "tiktok", "twitter", "linkedin", "amazon",
    "netflix", "spotify", "dhl", "fedex", "ups", "usps", "binance",
    "coinbase", "metamask", "blockchain", "trustwallet", "yahoo", "adobe",
    "dropbox", "docusign", "wellsfargo", "chase", "citibank", "hsbc",
    "barclays", "standardchartered", "stanbic", "absa", "equity", "kcb",
    "dfcu", "centenary", "ecobank", "cooperative", "ncba", "nmb", "crdb",
    "safaricom", "mpesa", "airtel", "mtn", "vodacom", "tigo", "orange",
    "ura", "kra", "nssf", "nhif", "ecitizen", "jumia", "kilimall",
    "flutterwave", "paystack", "chipper", "wave", "mukuru",
]

# Legitimate registered domains for the brands above. A brand token that
# appears in a host whose registered domain is NOT in this set is a classic
# impersonation signal. Partial on purpose - extend as you collect more.
BRAND_OFFICIAL_DOMAINS = {
    "paypal.com", "apple.com", "icloud.com", "google.com", "gmail.com",
    "microsoft.com", "outlook.com", "live.com", "office.com", "office365.com",
    "onedrive.com", "sharepoint.com", "facebook.com", "fb.com", "instagram.com",
    "whatsapp.com", "whatsapp.net", "wa.me", "telegram.org", "t.me",
    "tiktok.com", "twitter.com", "x.com", "linkedin.com", "amazon.com",
    "netflix.com", "spotify.com", "dhl.com", "fedex.com", "ups.com",
    "usps.com", "binance.com", "coinbase.com", "metamask.io", "blockchain.com",
    "trustwallet.com", "yahoo.com", "adobe.com", "dropbox.com", "docusign.com",
    "wellsfargo.com", "chase.com", "citibank.com", "hsbc.com", "barclays.co.uk",
    "sc.com", "stanbicbank.co.ug", "stanbicbank.co.ke", "absa.co.ke",
    "absa.co.ug", "equitybankgroup.com", "equitygroupholdings.com",
    "equitybank.co.ke", "kcbgroup.com", "dfcugroup.com", "centenarybank.co.ug",
    "ecobank.com", "co-opbank.co.ke", "ncbagroup.com", "nmbbank.co.tz",
    "crdbbank.co.tz", "safaricom.co.ke", "mpesa.africa", "airtel.africa",
    "airtel.co.ug", "airtel.co.ke", "mtn.com", "mtn.co.ug", "vodacom.co.tz",
    "tigo.co.tz", "orange.com", "ura.go.ug", "kra.go.ke", "nssfug.org",
    "nhif.or.ke", "ecitizen.go.ke", "jumia.com", "jumia.co.ug", "jumia.co.ke",
    "kilimall.co.ke", "flutterwave.com", "paystack.com", "chipper.cash",
    "wave.com", "mukuru.com",
}

RISKY_FILE_EXTENSIONS_IN_URL = {
    "apk", "exe", "scr", "bat", "cmd", "msi", "jar", "vbs", "ps1", "lnk",
    "iso", "img", "dll", "hta", "docm", "xlsm", "pptm", "zip", "rar", "7z",
    "dmg", "pkg", "deb", "apkm", "xapk", "wsf", "reg", "cpl", "com",
}
