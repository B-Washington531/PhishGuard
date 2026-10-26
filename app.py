import streamlit as st
import tempfile
import os
from email_parser import get_email_analysis

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PhishGuard")

st.subheader("Phishing Email Investigation Dashboard")

st.write("Upload an email to analyze potential phishing threats.")

uploaded_file = st.file_uploader(
    "Choose an email file",
    type=["eml"]
)

if uploaded_file is not None:

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".eml"
    ) as temp_file:
        temp_file.write(uploaded_file.getvalue())
        temp_path = temp_file.name

    try:
        results = get_email_analysis(temp_path)
    finally:
        os.remove(temp_path)

    st.success("Email analyzed successfully!")

    st.subheader("Email Information")
    st.write("Sender:", results["sender"])
    st.write("Subject:", results["subject"])

    st.subheader("Phishing Risk Assessment")

    score = results["risk_score"]
    st.metric("Risk Score", f"{score}/100")

    if score >= 60:
        st.error("HIGH RISK")
    elif score >= 30:
        st.warning("MEDIUM RISK")
    else:
        st.success("LOW RISK")

    st.subheader("Suspicious Phrases")

    if results["urgency_phrases"]:
        for phrase in results["urgency_phrases"]:
            st.write("⚠️", phrase)
    else:
        st.write("No suspicious phrases detected.")

    st.subheader("Extracted URLs")

    if results["urls"]:
        for url in results["urls"]:
            st.code(url)
    else:
        st.write("No URLs detected.")

    st.subheader("Security Findings")

    if results["url_warnings"]:
        for warning in results["url_warnings"]:
            st.warning(warning)
    else:
        st.success("No URL-related warnings detected.")