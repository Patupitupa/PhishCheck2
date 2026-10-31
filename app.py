import joblib
import streamlit as st

import phish_utils as pu
import security as sec

st.set_page_config(page_title="PhishCheck", page_icon="🔍")
st.title("PhishCheck")
st.caption("URL-based risk estimate. Not a guarantee. Always verify important links yourself.")

CHECKS_PER_MINUTE_SESSION = 10     # per visitor session
CHECKS_PER_MINUTE_GLOBAL = 60      # all visitors together (protects the redirect resolver)
MAX_QR_LINKS = 3                   # links read from one QR image
LEGIT_CUTOFF = 0.80                # model legit score needed for "Likely legit"; 0.5 up to this = "Not sure"
STATUS_TEXT = {
    200: "OK (page loaded)",
    301: "Moved permanently",
    302: "Moved temporarily",
    303: "See other",
    307: "Temporary redirect",
    308: "Permanent redirect",
    403: "Access refused",
    404: "Page not found",
}


@st.cache_resource
def load_artifacts():
    art = joblib.load("phishcheck_final.joblib")
    pu.TRANCO_SET = art["tranco"]
    pu.SHORTENER_DOMAINS = art["shorteners"]
    return art


@st.cache_resource
def global_limiter():
    return sec.RateLimiter(CHECKS_PER_MINUTE_GLOBAL, 60)


art = load_artifacts()

if "limiter" not in st.session_state:
    st.session_state.limiter = sec.RateLimiter(CHECKS_PER_MINUTE_SESSION, 60)

n_db = pu.phish_db_count()
st.caption(f"Known-phishing database: {n_db:,} reported links." if n_db
           else "Known-phishing database not loaded; using the model only.")
st.caption(f"Results: likely legit (model confidence {LEGIT_CUTOFF:.0%} or higher), not sure, or likely phishing. "
           "These are the model's confidence scores, not probabilities.")


def allowed():
    ok, wait = st.session_state.limiter.hit()
    if not ok:
        st.warning(f"Too many checks from this session. Please wait {wait:.0f} seconds.")
        return False
    ok, wait = global_limiter().hit()
    if not ok:
        st.warning("The service is busy right now. Please try again in a minute.")
        return False
    return True


def show(raw):
    url, err = pu.validate_url_input(raw)
    if err:
        st.error(err)
        return
    if not allowed():
        return
    try:
        with st.spinner("Checking..."):
            r = pu.analyze(url, art)
    except Exception:
        st.error("Something went wrong while checking that link. Please try another one.")
        return
    if "error" in r:
        st.error(r["error"])
        return

    if r["known_phish"]:
        where = "The link you entered" if r["match"] == "original" else "The page this link redirects to"
        st.error(f"Known phishing link. {where} is in the reported-phishing database. Do not open it.")
    else:
        p = r["p_legit"]
        tier = pu.tier_from_score(p, LEGIT_CUTOFF)
        if tier == "legit":
            st.success(f"Likely legit. The model is {p * 100:.0f}% confident this link is legitimate.")
        elif tier == "unsure":
                        st.warning(f"Unverified ({p * 100:.0f}% legit score). The model leans legit but can't confirm it. "
                       "Don't enter passwords or payment details until you've checked the site yourself.")
        else:
            st.error(f"Likely phishing. The model is {(1 - p) * 100:.0f}% confident this link is a scam.")

    # st.code shows text literally, so a crafted link can never render as markdown or a clickable link
    st.caption("Scanned:")
    st.code(r["analysis_url"], language=None)
    if r["resolution_error"]:
        st.warning("Could not follow all redirects, so the link was checked as typed.")
    if r["redirect_chain"]:
        st.caption("Redirect chain (each link has its own copy button):")
        for i, (hop_url, code) in enumerate(r["redirect_chain"], start=1):
            st.caption(f"{i}. HTTP {code} {STATUS_TEXT.get(code, '')}".strip())
            st.code(hop_url, language=None)


tab1, tab2 = st.tabs(["Paste a link", "Scan a QR code"])

with tab1:
    with st.form("url_form"):
        url = st.text_input("URL", max_chars=4096)
        submitted = st.form_submit_button("Check")
    if submitted:
        show(url)

with tab2:
    with st.form("qr_form"):
        img = st.file_uploader("QR image (PNG or JPG, max 2 MB)", type=["png", "jpg", "jpeg"])
        scan = st.form_submit_button("Scan")
    if scan:
        if img is None:
            st.error("Choose an image first.")
        else:
            arr, err = sec.load_qr_image(img.getvalue())
            if err:
                st.error(err)
            else:
                res = pu.scan_qr_from_image(arr)
                if res["ok"]:
                    for link in res["data"][:MAX_QR_LINKS]:
                        st.caption("QR code contains:")
                        st.code(link, language=None)
                        show(link)
                elif "not installed" in (res["error"] or ""):
                    st.warning("QR scanning is not available on this server.")
                else:
                    st.warning("No QR code was found in that image.")