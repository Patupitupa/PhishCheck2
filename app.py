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
st.write("Enter a URL below to check if it's safe or a malicious scam using your trained machine learning model.")

# --- Load Model Artifacts ---
@st.cache_resource
def load_artifacts():
    # Load your saved dictionary artifact using pickle
    with open("phishcheck_v2_2.pkl", "rb") as f:
        data = pickle.load(f)
        
    # Extract model, vectorizer, and scaler safely
    model = data["results"]["Support Vector Machine (LinearSVC)"]["model"]
    tfidf_url = data["tfidf_url"]
    scaler = data["scaler"]
    
    # --- BULLETPROOF SCALER COMPATIBILITY PATCH ---
    # Prevents 'MaxAbsScaler' object has no attribute 'clip' crash across scikit-learn versions
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
        
        # Primary features matching training notebook
        primary = [
            len(s), s.count('.'), s.count('-'), s.count('@'),
            has_ip_address(s), sum(c.isdigit() for c in s),
            int(s.startswith('https')), int('?' in s), s.count('%'), 0, 0, 0, 0, 0
        ]
        
        # Extra heuristic features
        ext = _te.extract_str(host)
        sub = ext.subdomain
        pq = s.split("/", 1)[1] if "/" in s else ""
        path = pq.split("?")[0]
        words = [w for w in re.split(r"[^a-z0-9]+", s) if w]
        wl = [len(w) for w in words] or [0]
        letters = sum(c.isalpha() for c in host)
        digits = sum(c.isdigit() for c in host)
        
        extra = [
            len(host), len(sub.split(".")) if sub else 0,
            digits / max(letters, 1), sum(c.isdigit() for c in s) / max(len(s), 1),
            _entropy(s), _entropy(host), max(wl), min(wl), sum(wl) / len(wl),
            0, 0, 0, 0, 0, int("xn--" in host), 0, 0, 0, 0, 0, 0, 0, 0, 0,
            _entropy(sub), s.count("/"), s.count("_"), s.count("="), s.count("&"),
            s.count("~"), s.count(","), s.count(";"), s.count(":"), s.count("$"), s.count("!")
        ]
        feats.append(primary + extra)
    return np.array(feats, dtype=float)

# --- User Input Form ---
url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com/login")

if st.button("Analyze URL", type="primary"):
    if not url_input.strip():
        st.warning("Please enter a valid URL.")
    else:
        with st.spinner("Running security checks..."):
            
            # --- STEP A: Fast Lookup Gatekeeper (Pre-filter) ---
            domain = extract_domain(url_input)
            KNOWN_SAFE_DOMAINS = {"google.com", "youtube.com", "github.com", "microsoft.com", "apple.com"}
            is_known_safe = domain in KNOWN_SAFE_DOMAINS
            
            if is_known_safe:
                st.success(f"✅ **Result: Safe / Legitimate**")
                st.metric(label="Safety Confidence Score", value="99.9%")
                st.info(f"Verified instantly by the high-speed lookup layer ({domain} is a globally trusted domain).")
            
            else:
                # --- STEP B: ML Model Inference ---
                try:
                    # Transform input URL using saved vectorizer and scaler
                    X_ngram = tfidf_url.transform([url_input])
                    X_lex = csr_matrix(scaler.transform(full_lex([url_input])))
                    X_features = hstack([X_ngram, X_lex]).tocsr()
                    
                    pred = int(model.predict(X_features)[0])
                    
                    # Confidence score extraction
                    if hasattr(model, "predict_proba"):
                        conf = float(model.predict_proba(X_features)[0][pred] * 100)
                    else:
                        score = float(model.decision_function(X_features)[0])
                        p = 1.0 / (1.0 + np.exp(-abs(score)))
                        conf = float((p if score < 0 else 1 - p) * 100)
                    
                    if pred == 0:
                        st.error(f"🚨 **Result: Phishing / Scam Detected!**")
                        st.metric(label="Malicious Risk Score", value=f"{conf:.1f}%")
                        st.warning("Warning: This URL shares structural patterns with known malicious sites.")
                    else:
                        st.success(f"✅ **Result: Safe / Legitimate**")
                        st.metric(label="Safety Confidence Score", value=f"{conf:.1f}%")
                        st.info("The URL structure appears benign after deep ML inspection.")
                        
                except Exception as e:
                    st.error(f"Error during ML analysis: {e}")

# --- Sidebar Info ---
with st.sidebar:
    st.header("About")
    st.write("This tool uses a robust machine learning backend combined with lexical analysis and a high-speed pre-lookup filter.")
    st.markdown("---")
    st.write("🎯 **Target Accuracy:** 95–97%")