import tempfile, joblib, streamlit as st
import phish_utils as pu

st.set_page_config(page_title="PhishCheck", page_icon="🔍")
st.title("PhishCheck")
st.caption("URL-based risk estimate. Not a guarantee. Always verify important links yourself.")

@st.cache_resource
def load():
    art = joblib.load("phishcheck_final.joblib")
    pu.TRANCO_SET = art["tranco"]
    pu.SHORTENER_DOMAINS = art["shorteners"]
    return art

art = load()

def show(url):
    with st.spinner("Checking..."):
        r = pu.analyze(url, art)
    if "error" in r:
        st.error(r["error"]); return
    (st.success if r["label"] == 1 else st.error)(f"{r['status']} ({r['confidence']:.1f}% confidence)")
    st.write("Scanned:", r["analysis_url"])
    if r["resolution_error"]:
        st.warning(f"Could not follow redirects: {r['resolution_error']}")
    if r["redirect_chain"]:
        st.write("Redirect chain:", r["redirect_chain"])

tab1, tab2 = st.tabs(["Paste a link", "Scan a QR code"])
with tab1:
    url = st.text_input("URL")
    if st.button("Check") and url:
        show(url)
with tab2:
    img = st.file_uploader("QR image", type=["png", "jpg", "jpeg"])
    if img:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img.read())
        res = pu.scan_qr_from_image(f.name)
        if res["ok"]:
            for link in res["data"]:
                st.write("QR contains:", link)
                show(link)
        else:
            st.warning(res["error"])
