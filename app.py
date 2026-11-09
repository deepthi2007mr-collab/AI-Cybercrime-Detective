import streamlit as st
import pandas as pd
import joblib
import ipaddress
import time
import html
from datetime import datetime
from urllib.parse import urlparse

# ------------------------------------------
# 1. PAGE CONFIGURATION
# ------------------------------------------

st.set_page_config(
    page_title="AI Cybercrime Detective",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ------------------------------------------
# 2. LOAD TRAINED AI MODEL
# ------------------------------------------

@st.cache_resource
def load_model():
    saved_data = joblib.load("cyber_detective_model.pkl")
    return saved_data["model"], saved_data["feature_names"]

try:
    model, feature_names = load_model()
except Exception as e:
    st.error("Unable to load the AI model.")
    st.error(f"Details: {e}")
    st.info(
        "Check that cyber_detective_model.pkl is in the "
        "same GitHub folder as app.py."
    )
    st.stop()

# ------------------------------------------
# 3. URL FEATURE EXTRACTION
# ------------------------------------------

suspicious_words = [
    "login", "verify", "update", "secure",
    "account", "password", "signin", "banking"
]

shortener_domains = [
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "ow.ly", "buff.ly"
]


def extract_features(raw_url):

    url = str(raw_url).strip()
    lower_url = url.lower()

    parse_input = (
        url if "://" in url else "//" + url
    )

    parsed = urlparse(parse_input)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    parts = hostname.split(".") if hostname else []
    subdomains = max(0, len(parts) - 2)

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    suspicious_count = sum(
        word in lower_url for word in suspicious_words
    )

    is_shortener = int(any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in shortener_domains
    ))

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_slashes": url.count("/"),
        "num_question_marks": url.count("?"),
        "num_equal": url.count("="),
        "num_ampersands": url.count("&"),
        "num_percent": url.count("%"),
        "num_at": url.count("@"),
        "num_digits": sum(char.isdigit() for char in url),
        "num_subdomains": subdomains,
        "has_https": int(lower_url.startswith("https://")),
        "has_http": int(lower_url.startswith("http://")),
        "has_ip_address": has_ip,
        "suspicious_word_count": suspicious_count,
        "uses_shortener": is_shortener,
        "has_fragment": int(bool(parsed.fragment))
    }

    return features


# ------------------------------------------
# 4. CYBERSECURITY NEON DESIGN
# ------------------------------------------

st.markdown("""
<style>

.stApp {
    background:
        radial-gradient(ellipse at top left, #14234b 0%, transparent 45%),
        radial-gradient(ellipse at bottom right, #251044 0%, transparent 45%),
        #070b18;
    color: #e8f0ff;
}

header[data-testid="stHeader"] {
    background: transparent;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1250px;
}

h1, h2, h3 {
    color: #eaf5ff !important;
}

p, label, li {
    color: #c5d5ed;
}

.hero {
    background: linear-gradient(120deg, #101e3d, #21113e);
    border: 1px solid #347bff;
    border-radius: 18px;
    padding: 28px;
    text-align: center;
    box-shadow: 0 0 25px rgba(38, 130, 255, 0.18);
    margin-bottom: 25px;
}

.hero-title {
    font-size: 36px;
    font-weight: 900;
    letter-spacing: 2px;
    color: #63d9ff;
    text-shadow: 0 0 15px #167cff;
}

.hero-subtitle {
    color: #c5d5ed;
    font-size: 16px;
    margin-top: 8px;
}

.panel {
    background: rgba(17, 29, 56, 0.88);
    border: 1px solid #304d83;
    border-radius: 16px;
    padding: 22px;
    margin: 12px 0;
}

.success-card {
    background: rgba(0, 180, 120, 0.10);
    border: 1px solid #00e6a0;
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 0 15px rgba(0, 230, 160, 0.12);
}

.danger-card {
    background: rgba(255, 50, 90, 0.10);
    border: 1px solid #ff426d;
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 0 15px rgba(255, 66, 109, 0.15);
}

.result-title {
    font-size: 23px;
    font-weight: 800;
    margin-bottom: 8px;
}

.small-note {
    color: #9bb1d0;
    font-size: 13px;
}

.stButton > button {
    background: linear-gradient(90deg, #087bff, #873cff);
    color: white;
    border: 1px solid #70caff;
    border-radius: 12px;
    padding: 12px 20px;
    font-weight: 800;
    width: 100%;
    box-shadow: 0 0 16px rgba(48, 130, 255, 0.3);
    transition: 0.25s;
}

.stButton > button:hover {
    border-color: #ffffff;
    box-shadow: 0 0 25px rgba(80, 170, 255, 0.65);
    transform: translateY(-2px);
}

.stTextInput input {
    background: #111c35;
    color: white;
    border: 1px solid #3978d9;
    border-radius: 10px;
}

div[data-testid="stProgressBar"] > div > div {
    background: linear-gradient(90deg, #00d5ff, #a44dff);
}

[data-testid="stSidebar"] {
    background: #0c1428;
    border-right: 1px solid #304d83;
}

.stTabs [data-baseweb="tab"] {
    color: #bcd7ff;
}

.stTabs [aria-selected="true"] {
    color: #55d7ff !important;
}

</style>
""", unsafe_allow_html=True)


# ------------------------------------------
# 5. SESSION STATE / SCAN HISTORY
# ------------------------------------------

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None


# ------------------------------------------
# 6. SIDEBAR
# ------------------------------------------

with st.sidebar:

    st.markdown("## 🛡️ CYBER DETECTIVE")

    st.markdown("---")

    st.markdown("### SYSTEM STATUS")

    st.success("AI Model Loaded")

    st.info("Random Forest Classifier")

    st.markdown("---")

    st.markdown("### PROJECT INFORMATION")

    st.write("🔍 URL Feature Analysis")
    st.write("🤖 Machine Learning")
    st.write("🌐 Phishing Detection")

    st.markdown("---")

    st.caption("AI Cybercrime Detective")
    st.caption("Science Exhibition Project")


# ------------------------------------------
# 7. MAIN HEADER
# ------------------------------------------

st.markdown("""
<div class="hero">
    <div style="font-size:55px;">🛡️</div>
    <div class="hero-title">AI CYBERCRIME DETECTIVE</div>
    <div class="hero-subtitle">
        ADVANCED AI-POWERED PHISHING URL DETECTION SYSTEM
    </div>
    <p style="color:#58d7ff; margin-top:15px;">
        SCAN • DETECT • PROTECT
    </p>
</div>
""", unsafe_allow_html=True)


# ------------------------------------------
# 8. DASHBOARD TABS
# ------------------------------------------

scan_tab, history_tab, about_tab = st.tabs([
    "🔍 URL SCANNER",
    "📜 SCAN HISTORY",
    "🛡️ ABOUT PROJECT"
])


# ------------------------------------------
# 9. URL SCANNER
# ------------------------------------------

with scan_tab:

    st.markdown("## 🔍 Website Security Scanner")

    st.write(
        "Enter a website URL below. Our AI model will "
        "analyse its structure and estimate whether it "
        "may be a phishing URL."
    )

    with st.form("scanner_form"):

        url = st.text_input(
            "ENTER URL TO SCAN",
            placeholder="https://www.example.com/"
        )

        scan_button = st.form_submit_button(
            "⚡ SCAN URL"
        )

    if scan_button:

        if not url.strip():

            st.warning("Please enter a URL.")

        else:

            try:

                # Animated scanning effect
                with st.spinner(
                    "🔎 Analysing URL features... Please wait."
                ):

                    time.sleep(1.2)

                    features = extract_features(url)

                    input_data = pd.DataFrame(
                        [features]
                    )[feature_names]

                    prediction = model.predict(
                        input_data
                    )[0]

                    probabilities = model.predict_proba(
                        input_data
                    )[0]

                    phishing_probability = probabilities[
                        list(model.classes_).index(1)
                    ]

                # Store scan result
                result = {
                    "url": url.strip(),
                    "prediction": int(prediction),
                    "probability": float(phishing_probability),
                    "time": datetime.now().strftime(
                        "%d-%m-%Y %H:%M:%S"
                    )
                }

                st.session_state.last_result = result

                st.session_state.scan_history.insert(
                    0, result
                )

                st.toast("URL scan completed!")

            except Exception as e:

                st.error("Unable to analyse this URL.")
                st.error(f"Error details: {e}")

    # Display latest result
    if st.session_state.last_result is not None:

        result = st.session_state.last_result

        st.markdown("---")

        st.markdown("## 🧠 AI SCAN RESULT")

        safe_url = html.escape(result["url"])

        st.markdown(f"""
            <div class="panel">
                <div class="small-note">SCANNED URL</div>
                <div style="font-size:16px; color:#63d9ff;
                            overflow-wrap:anywhere;">
                    {safe_url}
                </div>
            </div>
            """,unsafe_allow_html=True
        )

        probability = result["probability"]

        if result["prediction"] == 1:

            st.markdown("""
            <div class="danger-card">
                <div style="font-size:42px;">⚠️</div>
                <div class="result-title" style="color:#ff5579;">
                    POSSIBLE PHISHING URL
                </div>
                <p>This URL has been classified as potentially suspicious by the AI model.</p>
            </div>
            """, unsafe_allow_html=True)

        else:

            st.markdown("""
            <div class="success-card">
                <div style="font-size:42px;">✅</div>
                <div class="result-title" style="color:#00e6a0;">
                    LIKELY LEGITIMATE URL
                </div>
                <p>The AI model classified this URL as likely legitimate.</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### 📊 Model-Estimated Phishing Score")

        st.progress(
            int(round(probability * 100)),
            text=f"{probability * 100:.2f}%"
        )

        st.caption(
            "This is the model's estimated phishing score, "
            "not a guaranteed real-world probability."
        )

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Phishing score",
                f"{probability * 100:.2f}%"
            )

        with col2:
            st.metric(
                "Legitimate-class score",
                f"{(1 - probability) * 100:.2f}%"
            )

        st.markdown("---")

        st.markdown(
            f"<div class='small-note'>Scan completed: "
            f"{html.escape(result['time'])}</div>",
            unsafe_allow_html=True
        )

    else:

        st.markdown("""
        <div class="panel" style="text-align:center;">
            <div style="font-size:40px;">🔐</div>
            <h3>READY TO SCAN</h3>
            <p>Your AI security scanner is waiting for a URL.</p>
        </div>
        """, unsafe_allow_html=True)


# ------------------------------------------
# 10. SCAN HISTORY
# ------------------------------------------

with history_tab:

    st.markdown("## 📜 Previous Scan Records")

    st.write(
        "View the URLs scanned during this browser session."
    )

    if st.session_state.scan_history:

        history_data = []

        for item in st.session_state.scan_history:

            history_data.append({
                "Date & Time": item["time"],
                "URL": item["url"],
                "AI Result": (
                    "Possible Phishing"
                    if item["prediction"] == 1
                    else "Likely Legitimate"
                ),
                "Phishing Score": (
                    f"{item['probability'] * 100:.2f}%"
                )
            })

        history_df = pd.DataFrame(history_data)

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        st.markdown("---")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Total scans",
                len(history_data)
            )

        with col2:
            suspicious_total = sum(
                item["prediction"] == 1
                for item in st.session_state.scan_history
            )

            st.metric(
                "Possible phishing results",
                suspicious_total
            )

        if st.button("🗑️ CLEAR SCAN HISTORY"):

            st.session_state.scan_history = []
            st.session_state.last_result = None
            st.rerun()

    else:

        st.info(
            "No scans yet. Visit the URL Scanner tab "
            "to scan your first URL."
        )


# ------------------------------------------
# 11. ABOUT PROJECT
# ------------------------------------------

with about_tab:

    st.markdown("## 🛡️ About AI Cybercrime Detective")

    st.markdown("""
    <div class="panel">

        <h3 style="color:#63d9ff;">
            What is this project?
        </h3>

        AI Cybercrime Detective is a machine-learning
        project designed to identify URLs that may be
        associated with phishing attacks.

        It analyses URL text and extracts structural
        and lexical features before making a prediction.

    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ How does it work?")

    st.markdown("""
    <div class="panel">

        <h4>STEP 1 — URL INPUT</h4>
        The user enters a website URL.

        <h4>STEP 2 — FEATURE EXTRACTION</h4>
        The system extracts 20 URL features, such as
        URL length, dots, hyphens, suspicious words,
        IP address usage and more.

        <h4>STEP 3 — AI ANALYSIS</h4>
        A trained Random Forest machine-learning model
        analyses the extracted features.

        <h4>STEP 4 — PREDICTION</h4>
        The system displays whether the URL is classified
        as likely legitimate or possible phishing.

    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🧠 Technologies Used")

    tech1, tech2, tech3 = st.columns(3)

    with tech1:
        st.info("🐍 Python")

    with tech2:
        st.info("🤖 Random Forest")

    with tech3:
        st.info("🌐 Streamlit")

    st.markdown("### ⚠️ Important Security Notice")

    st.warning(
        "This is an educational science exhibition prototype. "
        "It analyses URL text only and does not open websites. "
        "Its predictions are not a security guarantee. "
        "A legitimate-looking result does not prove a website "
        "is safe. Do not enter passwords or personal information "
        "on websites based on this prediction."
    )


# ------------------------------------------
# 12. FOOTER
# ------------------------------------------
st.markdown("---")

st.markdown("""
<div style="text-align:center; padding:15px;">

    <div style="font-size:25px;">🛡️</div>

    <div style="color:#63d9ff; font-weight:800;">
        AI CYBERCRIME DETECTIVE
    </div>

    <div style="color:#8297b8; font-size:12px;">
        Built with Python • Machine Learning • Streamlit
    </div>

    <div style="color:#8297b8; font-size:12px; margin-top:8px;">
        THINK BEFORE YOU CLICK. STAY CYBER SAFE.
    </div>

</div>
""", unsafe_allow_html=True)


