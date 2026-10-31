"""
phish_utils.py - helper code copied from the PhishCheck training notebook.
Only what the app needs: URL cleaning, redirect resolver, feature extraction.
No training code, no datasets.

The app must set these two after loading the joblib file:
    import phish_utils as pu
    pu.TRANCO_SET = art["tranco"]
    pu.SHORTENER_DOMAINS = art["shorteners"]
"""
import os, re, html, socket, ipaddress, math, sqlite3
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse, urljoin, parse_qs, unquote

import numpy as np
import requests
import tldextract
from scipy.sparse import hstack, csr_matrix

# QR scanning is optional (needs opencv + pyzbar + libzbar0)
try:
    import cv2
    from pyzbar.pyzbar import decode
    QR_AVAILABLE = True
except Exception:
    QR_AVAILABLE = False

# ---------- Filled in by the app from the joblib file ----------
TRANCO_SET = set()
SHORTENER_DOMAINS = set()
USE_TRANCO = True

# ---------- Redirect resolver settings ----------
RESOLVE_TIMEOUT        = 8
RESOLVE_MAX_REDIRECTS  = 6
RESOLVE_VERIFY_TLS     = True
ALLOW_PRIVATE_NETWORKS = False

# Query params that indicate an open-redirect wrapper
REDIRECT_PARAMS = {
    "url", "continue", "next", "redirect", "redirect_uri",
    "return", "return_url", "returnurl", "dest", "destination",
    "target", "goto",
}

# ---------- Feature constants ----------
SUSPICIOUS_TLDS = {"top","xyz","icu","tk","ml","ga","cf","gq","click","link","work",
                   "support","live","buzz","cyou","rest","monster","cam","zip","mov"}
COMMON_TLDS     = ("com","net","org","co","io","gov","edu")
PHISH_HINTS     = ("login","signin","verify","secure","account","update","confirm",
                   "bank","paypal","wallet","password","billing","invoice","support")
BRANDS = ("google","paypal","microsoft","apple","amazon","facebook","netflix",
          "instagram","whatsapp","dropbox","linkedin","outlook","office")

# ---------- URL helpers ----------
_te = tldextract.TLDExtract(suffix_list_urls=None, include_psl_private_domains=True)


def normalize_url(url):
    """Unescape &amp; -> &, trim whitespace."""
    return html.unescape(str(url)).strip()


def canon(u):
    u = normalize_url(u).lower()
    u = re.sub(r"^https?://", "", u)   # drop scheme
    u = re.sub(r"^www\.", "", u)       # drop www
    return u.rstrip("/")


def extract_domain(url):
    """Hostname, lowercase, www. stripped. Never raises."""
    try:
        s = normalize_url(url)
        if not s:
            return ""
        if "://" not in s:
            s = "http://" + s
        host = (urlparse(s).hostname or "").lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return str(url)


def root_domain(hostname):
    """Registrable domain via tldextract (amazon.co.uk -> amazon.co.uk)."""
    if not hostname:
        return ""
    try:
        return _te.extract_str(hostname).registered_domain or hostname
    except Exception:
        parts = hostname.lower().rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def has_ip_address(url):
    """1 only if the HOSTNAME is an IP literal (query-string IPs don't count)."""
    try:
        s = normalize_url(url)
        if "://" not in s:
            s = "http://" + s
        host = (urlparse(s).hostname or "").lower()
        if not host:
            return 0
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
            try:
                ipaddress.IPv4Address(host)
                return 1
            except ValueError:
                return 0
        if re.fullmatch(r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}", host):
            return 1
        return 0
    except Exception:
        return 0


def has_open_redirect_param(url):
    """1 if a known redirect param carries a URL-shaped value."""
    try:
        s = normalize_url(url)
        if "://" not in s:
            s = "http://" + s
        for k, vals in parse_qs(urlparse(s).query).items():
            if k.lower() not in REDIRECT_PARAMS:
                continue
            for v in vals:
                v_dec = unquote(v)
                if v_dec.startswith(("http://", "https://", "//")):
                    return 1
        return 0
    except Exception:
        return 0


def has_encoded_url_in_query(url):
    """1 if the raw query contains '=http%3A' style encoding."""
    try:
        raw = normalize_url(url)
        q = urlparse(raw if "://" in raw else "http://" + raw).query or ""
        q = q.lower()
        return int("=http%3a" in q or "=https%3a" in q or "=%2f%2f" in q)
    except Exception:
        return 0


# ---------- SSRF guard + redirect resolver ----------
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n) for n in [
        "0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
        "169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.168.0.0/16",
        "198.18.0.0/15","224.0.0.0/4","240.0.0.0/4","::1/128","fc00::/7","fe80::/10",
    ]
]


def _is_private_host(hostname):
    if ALLOW_PRIVATE_NETWORKS:
        return False
    if not hostname:
        return True
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if ip.is_private or ip.is_loopback or ip.is_link_local \
           or ip.is_reserved or ip.is_multicast:
            return True
        if any(ip in net for net in _BLOCKED_NETWORKS):
            return True
    return False


def resolve_final_url(url, timeout=RESOLVE_TIMEOUT, max_redirects=RESOLVE_MAX_REDIRECTS):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishCheck/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    current = normalize_url(url)
    history = []
    for _ in range(max_redirects + 1):
        parsed = urlparse(current if "://" in current else "http://" + current)
        if parsed.scheme not in ("http", "https"):
            return {"final_url": current, "error": f"Unsupported scheme: {parsed.scheme!r}", "history": history}
        if not parsed.hostname:
            return {"final_url": current, "error": "Missing hostname", "history": history}
        if _is_private_host(parsed.hostname):
            return {"final_url": current,
                    "error": f"Blocked host (private/loopback/unresolvable): {parsed.hostname}",
                    "history": history}
        try:
            r = requests.get(current, headers=headers, allow_redirects=False,
                             timeout=timeout, verify=RESOLVE_VERIFY_TLS, stream=True)
        except requests.exceptions.RequestException as e:
            return {"final_url": current, "error": str(e), "history": history}
        history.append((current, r.status_code))
        location = r.headers.get("Location")
        r.close()
        if 300 <= r.status_code < 400 and location:
            current = urljoin(current, location)
            continue
        return {"final_url": current, "error": None, "history": history}
    return {"final_url": current, "error": f"Too many redirects (>{max_redirects})", "history": history}


# ---------- Features (14 + 34 = 48) ----------
def extract_lexical_features(urls):
    """14 numerical features per URL."""
    feats = []
    for url in urls:
        s = normalize_url(url).lower()
        host = extract_domain(s)
        root = root_domain(host)
        try:
            deep_path = int(len([p for p in urlparse(
                s if "://" in s else "http://" + s).path.split("/") if p]) > 4)
        except Exception:
            deep_path = 0

        feats.append([
            len(s),
            s.count('.'),
            s.count('-'),
            s.count('@'),
            has_ip_address(s),
            sum(c.isdigit() for c in s),
            int(s.startswith('https')),
            int('?' in s),
            s.count('%'),
            deep_path,
            int(root in SHORTENER_DOMAINS),
            int(root in TRANCO_SET) if (USE_TRANCO and TRANCO_SET) else 0,
            has_open_redirect_param(s),
            has_encoded_url_in_query(s),
        ])
    return np.array(feats, dtype=float)


def _entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def extra_features(urls):
    rows = []
    for u in urls:
        s    = re.sub(r"^https?://", "", normalize_url(u).lower())
        host = extract_domain(s)
        ext  = _te.extract_str(host)
        sub  = ext.subdomain
        pq   = s.split("/", 1)[1] if "/" in s else ""
        path = pq.split("?")[0]
        words = [w for w in re.split(r"[^a-z0-9]+", s) if w]
        wl    = [len(w) for w in words] or [0]
        letters = sum(c.isalpha() for c in host)
        digits  = sum(c.isdigit() for c in host)
        sv = sum(c in "aeiou" for c in sub)
        sc = sum(c.isalpha() and c not in "aeiou" for c in sub)
        rows.append([
            len(host),                                           # hostname length
            len(sub.split(".")) if sub else 0,                   # subdomain count
            digits / max(letters, 1),                            # digit-letter ratio (host)
            sum(c.isdigit() for c in s) / max(len(s), 1),        # digit ratio (URL)
            _entropy(s),                                         # URL entropy
            _entropy(host),                                      # hostname entropy
            max(wl), min(wl), sum(wl) / len(wl),                 # longest/shortest/avg word
            max((len(m.group(0)) for m in re.finditer(r"(.)\1*", s)), default=0),  # char repeat
            sv / max(sc, 1),                                     # vowel-consonant (subdomain)
            int(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),   # suspicious TLD
            int(any(f".{t}" in path for t in COMMON_TLDS)),      # TLD in path
            int(any(t in sub.split(".") for t in COMMON_TLDS)),  # TLD in subdomain
            int("xn--" in host),                                 # punycode
            int(bool(re.match(r"^[^/]*:\d+", s))),               # port
            sum(k in s for k in PHISH_HINTS),                    # phishing hints
            len(path.rsplit(".", 1)[-1]) if "." in path.split("/")[-1] else 0,  # path extension length
            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", s))),                  # host is an IP
            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", s)) and "signin" in s),  # IP + signin
            len(re.findall(r"https?://|https?%3a", s)),                         # embedded URLs
            int("accounts.google" in s and not host.endswith("google.com")),    # brand, wrong host
            len(pq.split("?", 1)[1]) if "?" in pq else 0,                       # query length
            int(any(b in s and b not in ext.domain for b in BRANDS)),           # brand, wrong domain
            _entropy(sub),                                                      # random-looking subdomain
            s.count("/"), s.count("_"), s.count("="), s.count("&"),
            s.count("~"), s.count(","), s.count(";"), s.count(":"),
            s.count("$"), s.count("!"),
        ])
    return np.array(rows, dtype=float)


def full_lex(urls):
    return np.hstack([extract_lexical_features(urls), extra_features(urls)])


# ---------- QR (optional) ----------
def scan_qr_from_image(image_path):
    if not QR_AVAILABLE:
        return {"ok": False, "error": "opencv/pyzbar not installed", "data": []}
    try:
        img = image_path if isinstance(image_path, np.ndarray) else cv2.imread(str(image_path))
        if img is None:
            return {"ok": False, "error": f"Could not load image: {image_path}", "data": []}
        results = decode(img)
        if not results:
            return {"ok": False, "error": "No QR code detected in image", "data": []}
        return {"ok": True, "error": None,
                "data": [r.data.decode("utf-8", errors="replace") for r in results]}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "data": []}


# ---------- Input validation ----------
MAX_URL_LEN = 2048
_INVISIBLE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u2028-\u202e\u2060\ufeff]")


def validate_url_input(raw):
    """Returns (clean_url, error). error is None when the input is acceptable.
    Only http/https links (or bare hostnames) are accepted."""
    if raw is None:
        return None, "Enter a link."
    s = _INVISIBLE.sub("", str(raw)).strip()
    if not s:
        return None, "Enter a link."
    if len(s) > MAX_URL_LEN:
        return None, f"That link is too long (max {MAX_URL_LEN} characters)."
    if re.search(r"\s", s):
        return None, "Links can't contain spaces."
    m = re.match(r"^([a-z][a-z0-9+.\-]*):(?!\d)", s, re.I)   # scheme-like prefix, not host:port
    if m and m.group(1).lower() not in ("http", "https"):
        return None, "Only http and https links are supported."
    try:
        host = urlparse(s if "://" in s else "http://" + s).hostname
    except ValueError:
        return None, "That doesn't look like a valid web address."
    if not host or "." not in host:
        return None, "That doesn't look like a valid web address."
    return s, None


# ---------- Known-phishing database (read-only SQLite) ----------
PHISH_DB_PATH = str(Path(__file__).resolve().parent / "phish.db")


def _open_ro(db_path=None):
    path = Path(db_path or PHISH_DB_PATH).resolve()
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)


def phish_db_count(db_path=None):
    """Number of entries, or None if the database is missing/unreadable."""
    try:
        con = _open_ro(db_path)
        try:
            return con.execute("SELECT COUNT(*) FROM phish").fetchone()[0]
        finally:
            con.close()
    except (sqlite3.Error, OSError):
        return None


def lookup_known_phish(url, db_path=None):
    """True if the canonical URL is an exact match in the known-phishing table.
    Read-only connection and a parameterised query: user text is never put into SQL."""
    key = canon(url)
    if not key:
        return False
    try:
        con = _open_ro(db_path)
        try:
            row = con.execute("SELECT 1 FROM phish WHERE url = ? LIMIT 1", (key,)).fetchone()
        finally:
            con.close()
        return row is not None
    except (sqlite3.Error, OSError):
        return False


def _known_result(original, matched_url, match, error=None, chain=None):
    return {
        "url": original,
        "analysis_url": matched_url,
        "domain": extract_domain(matched_url),
        "label": 0,
        "status": "Known phishing link",
        "confidence": None,
        "known_phish": True,
        "match": match,                      # "original" or "final"
        "resolution_error": error,
        "redirect_chain": chain or [],
    }


# ---------- One-call analysis for the app ----------
def analyze(url, art, resolve_redirects=True, use_db=True):
    """
    Order: (1) look the typed link up in the known-phishing database, and stop on a hit
    (the redirect resolver is never run, so the app does not visit a known-bad page);
    (2) resolve redirects; (3) look the final link up; (4) run the model.
    Returns a dict with label (0 = risky, 1 = legit), confidence (% or None on a database hit).
    """
    original = normalize_url(url)
    if not original:
        return {"error": "Empty URL"}

    if use_db and lookup_known_phish(original):
        return _known_result(original, canon(original), "original")

    final, error, chain = original, None, []
    if resolve_redirects:
        res = resolve_final_url(original)
        error, chain = res["error"], res["history"]
        if res["error"] is None:
            final = res["final_url"]
    analysis_url = canon(final)

    if use_db and analysis_url != canon(original) and lookup_known_phish(analysis_url):
        return _known_result(original, analysis_url, "final", error, chain)

    X = hstack([
        art["tfidf_url"].transform([analysis_url]),
        csr_matrix(art["scaler"].transform(full_lex([analysis_url]))),
    ]).tocsr()

    model = art["model"]
    probs = model.predict_proba(X)[0]
    label = int(np.argmax(probs))
    return {
        "url": original,
        "analysis_url": analysis_url,
        "domain": extract_domain(analysis_url),
        "label": label,
        "status": "Legitimate / Secure" if label == 1 else "Scam / Phishing / Risky",
        "confidence": float(probs[label] * 100),
        "known_phish": False,
        "match": None,
        "resolution_error": error,
        "redirect_chain": chain,
    }
