
import streamlit as st
import pandas as pd
import joblib
import ipaddress
from urllib.parse import urlparse

# Load trained AI model
saved_data = joblib.load("cyber_detective_model.pkl")
model = saved_data["model"]
feature_names = saved_data["feature_names"]

# Feature extraction
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
    parse_input = url if "://" in url else "//" + url
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

    return {
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
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": subdomains,
        "has_https": int(lower_url.startswith("https://")),
        "has_http": int(lower_url.startswith("http://")),
        "has_ip_address": has_ip,
        "suspicious_word_count": suspicious_count,
        "uses_shortener": is_shortener,
        "has_fragment": int(bool(parsed.fragment))
    }

# Dashboard design
st.set_page_config(
    page_title="AI Cybercrime Detective",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ AI Cybercrime Detective")
st.subheader("AI-Powered Phishing URL Detection")

st.write(
    "Enter a URL below to estimate whether it may be a phishing link."
)

url = st.text_input("Enter URL")

if st.button("SCAN URL"):
    if not url.strip():
        st.warning("Please enter a URL.")
    else:
        features = extract_features(url)
        input_data = pd.DataFrame([features])[feature_names]

        prediction = model.predict(input_data)[0]
        probabilities = model.predict_proba(input_data)[0]

        phishing_probability = probabilities[
            list(model.classes_).index(1)
        ]

        if prediction == 1:
            st.error("⚠️ POSSIBLE PHISHING URL")
        else:
            st.success("✅ LIKELY LEGITIMATE URL")

        st.metric(
            "Model-estimated phishing probability",
            f"{phishing_probability * 100:.2f}%"
        )

st.caption(
    "Educational science exhibition prototype. "
    "This prediction is not a safety guarantee. "
    "The tool analyses URL text only and does not open websites."
)
