import streamlit as st
import pickle
import numpy as np
import re
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
import math
from collections import Counter
import tldextract

# --- Page Configuration ---
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ AI-Powered Phishing URL Detector")
st.write("Enter any URL below to run real-time machine learning security analysis.")

# --- Load Model Artifacts ---
@st.cache_resource
def load_artifacts():
    with open("phishcheck_v2_2.pkl", "rb") as f:
        data = pickle.load(f)
        
    model = data["results"]["Support Vector Machine (LinearSVC)"]["model"]
    tfidf_url = data["tfidf_url"]
    scaler = data["scaler"]
    
    # --- BULLETPROOF SCALER COMPATIBILITY PATCH ---
    if scaler and not hasattr(scaler, 'clip'):
        scaler.clip = False
        
    return model, tfidf_url, scaler

try:
    model, tfidf_url, scaler = load_artifacts()
except Exception as e:
    st.error(f"Error loading model artifacts: {e}. Make sure 'phishcheck_v2_2.pkl' is in the repository.")
    st.stop()

# --- Helper & Feature Extraction Functions ---
_te = tldextract.TLDExtract(suffix_list_urls=None, include_psl_private_domains=True)

SUSPICIOUS_TLDS = {"top", "xyz", "icu", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
                   "support", "live", "buzz", "cyou", "rest", "monster", "cam", "zip", "mov"}
COMMON_TLDS = ("com", "net", "org", "co", "io", "gov", "edu")
PHISH_HINTS = ("login", "signin", "verify", "secure", "account", "update", "confirm",
               "bank", "paypal", "wallet", "password", "billing", "invoice", "support")
BRANDS = ("google", "paypal", "microsoft", "apple", "amazon", "facebook", "netflix",
          "instagram", "whatsapp", "dropbox", "linkedin", "outlook", "office")

def normalize_url(url):
    return str(url).strip()

def extract_domain(url):
    try:
        s = normalize_url(url)
        if not s: return ""
        if "://" not in s: s = "http://" + s
        host = (urlparse(s).hostname or "").lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return str(url)

def root_domain(hostname):
    if not hostname: return ""
    try:
        return _te.extract_str(hostname).registered_domain or hostname
    except Exception:
        parts = hostname.lower().rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def has_ip_address(url):
    try:
        s = normalize_url(url)
        if "://" not in s: s = "http://" + s
        host = (urlparse(s).hostname or "").lower()
        return int(bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host)))
    except Exception:
        return 0

def _entropy(s):
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum(v/n * math.log2(v/n) for v in c.values())

def full_lex(urls):
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

        # 1. Primary Lexical Features (14 features matching notebook)
        primary = [
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
            0, # shortener flag placeholder
            0, # tranco flag placeholder
            0, # open redirect placeholder
            0  # encoded url placeholder
        ]
        
        # 2. Extra Heuristic Features (31 features matching notebook)
        ext = _te.extract_str(host)
        sub = ext.subdomain
        pq = s.split("/", 1)[1] if "/" in s else ""
        path = pq.split("?")[0]
        words = [w for w in re.split(r"[^a-z0-9]+", s) if w]
        wl = [len(w) for w in words] or [0]
        letters = sum(c.isalpha() for c in host)
        digits = sum(c.isdigit() for c in host)
        sv = sum(c in "aeiou" for c in sub)
        sc = sum(c.isalpha() and c not in "aeiou" for c in sub)
        
        extra = [
            len(host),
            len(sub.split(".")) if sub else 0,
            digits / max(letters, 1),
            sum(c.isdigit() for c in s) / max(len(s), 1),
            _entropy(s),
            _entropy(host),
            max(wl), min(wl), sum(wl) / len(wl),
            max((len(m.group(0)) for m in re.finditer(r"(.)\1*", s)), default=0),
            sv / max(sc, 1),
            int(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
            int(any(f".{t}" in path for t in COMMON_TLDS)),
            int(any(t in sub.split(".") for t in COMMON_TLDS)),
            int("xn--" in host),
            int(bool(re.match(r"^[^/]*:\d+", s))),
            sum(k in s for k in PHISH_HINTS),
            len(path.rsplit(".", 1)[-1]) if "." in path.split("/")[-1] else 0,
            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", s))),
            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", s)) and "signin" in s),
            len(re.findall(r"https?://|https?%3a", s)),
            int("accounts.google" in s and not host.endswith("google.com")),
            len(pq.split("?", 1)[1]) if "?" in pq else 0,
            int(any(b in s and b not in ext.domain for b in BRANDS)),
            _entropy(sub),
            s.count("/"), s.count("_"), s.count("="), s.count("&"),
            s.count("~"), s.count(","), s.count(";"), s.count(":"),
            s.count("$"), s.count("!")
        ]
        feats.append(primary + extra)
    return np.array(feats, dtype=float)

# --- User Input Form ---
url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com/login")

if st.button("Analyze URL", type="primary"):
    if not url_input.strip():
        st.warning("Please enter a valid URL.")
    else:
        with st.spinner("Running full machine learning analysis..."):
            try:
                # Transform input URL directly through the ML pipeline
                X_ngram = tfidf_url.transform([url_input])
                X_lex = csr_matrix(scaler.transform(full_lex([url_input])))
                X_features = hstack([X_ngram, X_lex]).tocsr()
                
                pred = int(model.predict(X_features)[0])
                
                # Dynamic Confidence Score calculation
                if hasattr(model, "predict_proba"):
                    conf = float(model.predict_proba(X_features)[0][pred] * 100)
                else:
                    score = float(model.decision_function(X_features)[0])
                    p = 1.0 / (1.0 + np.exp(-abs(score)))
                    conf = float((p if score < 0 else 1 - p) * 100)
                
                # Render Real Results based strictly on ML Prediction
                if pred == 0:
                    st.error(f"🚨 **Result: Phishing / Scam Detected!**")
                    st.metric(label="Malicious Risk Score", value=f"{conf:.1f}%")
                    st.warning("Warning: The machine learning model identified suspicious structural and lexical patterns in this URL.")
                else:
                    st.success(f"✅ **Result: Safe / Legitimate**")
                    st.metric(label="Safety Confidence Score", value=f"{conf:.1f}%")
                    st.info("The machine learning model verified this URL structure as benign.")
                    
            except Exception as e:
                st.error(f"Error during ML analysis: {e}")

# --- Sidebar Info ---
with st.sidebar:
    st.header("About")
    st.write("Powered entirely by your Support Vector Machine (LinearSVC) model and live lexical feature extraction.")
    st.markdown("---")
    st.write("🎯 **Model:** SVM Linear Classifier")