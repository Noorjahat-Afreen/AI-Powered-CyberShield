"""
AI-Powered CyberShield - Cybersecurity Platform
================================================
Real ML-powered phishing URL & message detection
B.Tech CSE Major Project

Run: streamlit run app.py
"""

import streamlit as st
import os
import sqlite3
import pandas as pd
import numpy as np
import joblib
import re
from datetime import datetime
import plotly.express as px

# ============================================
# Database Functions
# ============================================
DB_PATH = "cybershield.db"


def init_db():
    """Create database table if not exists"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_type TEXT,
                  input_content TEXT,
                  prediction TEXT,
                  confidence REAL,
                  risk_level TEXT,
                  details TEXT,
                  timestamp DATETIME)''')
    conn.commit()
    conn.close()


def save_scan(scan_type, input_content, prediction, confidence, risk_level, details):
    """Save a scan result to database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO scans 
                 (scan_type, input_content, prediction, confidence, risk_level, details, timestamp)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (scan_type, input_content, prediction, confidence, risk_level, details, datetime.now()))
    conn.commit()
    conn.close()


def get_all_scans():
    """Get all scans from database"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM scans ORDER BY timestamp DESC", conn)
    conn.close()
    return df


def clear_history():
    """Delete all scan history"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


# ============================================
# ML Model Loading
# ============================================
@st.cache_resource
def load_models():
    """Load trained ML models"""
    url_model = joblib.load("models/url_model.pkl") if os.path.exists("models/url_model.pkl") else None
    url_features = joblib.load("models/url_features.pkl") if os.path.exists("models/url_features.pkl") else None
    msg_model = joblib.load("models/message_model.pkl") if os.path.exists("models/message_model.pkl") else None
    msg_vectorizer = joblib.load("models/message_vectorizer.pkl") if os.path.exists("models/message_vectorizer.pkl") else None
    return url_model, url_features, msg_model, msg_vectorizer


init_db()
url_model, url_features, msg_model, msg_vectorizer = load_models()


# ============================================
# URL Analysis Functions
# ============================================
def extract_url_features(url):
    """Extract 20 features from a URL for ML classification"""
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at'] = 1 if '@' in url else 0
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_port'] = 1 if ':' in url.split('//')[-1].split('/')[0] else 0
    features['num_subdomains'] = url.split('//')[-1].split('/')[0].count('.') if '//' in url else url.count('.')
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club', '.work', '.click']
    features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'password', 'bank',
                        'free', 'winner', 'prize', 'gift', 'claim', 'urgent', 'suspended',
                        'limited', 'offer', 'bonus', 'discount', 'refund']
    features['num_suspicious_words'] = sum(1 for word in suspicious_words if word.lower() in url.lower())
    features['has_double_slash_redirect'] = 1 if url.count('//') > 1 else 0
    features['has_percent'] = 1 if '%' in url else 0
    features['has_equal_sign'] = 1 if '=' in url else 0
    features['has_question'] = 1 if '?' in url else 0
    return features


def analyze_url(url):
    """Analyze URL using ML model and return prediction with details"""
    if not url_model or not url_features:
        return None, 0, "Model not loaded", []

    features = extract_url_features(url)
    feature_values = [features[f] for f in url_features]

    # Use DataFrame with feature names to match training format
    feature_df = pd.DataFrame([feature_values], columns=url_features)
    prediction = url_model.predict(feature_df)[0]
    proba = url_model.predict_proba(feature_df)[0]
    confidence = max(proba) * 100

    # Build risk factor list for explanation
    risk_factors = []
    if features['has_ip']:
        risk_factors.append("URL contains IP address instead of a domain name")
    if features['has_at']:
        risk_factors.append("URL contains '@' symbol (often hides the real destination)")
    if features['suspicious_tld']:
        risk_factors.append("Uses a suspicious top-level domain (.tk, .ml, .ga, .cf)")
    if features['num_suspicious_words'] > 2:
        risk_factors.append(f"Contains {features['num_suspicious_words']} suspicious keywords")
    if features['url_length'] > 75:
        risk_factors.append(f"URL is unusually long ({features['url_length']} characters)")
    if features['num_dots'] > 4:
        risk_factors.append(f"Contains many dots ({features['num_dots']}) suggesting nested subdomains")
    if not features['has_https']:
        risk_factors.append("No HTTPS encryption (insecure connection)")
    if features['has_double_slash_redirect']:
        risk_factors.append("Contains redirect indicators (multiple //)")

    if prediction == 1:
        prediction_label = "Phishing/Malicious"
        risk_level = "Potentially Malicious" if confidence > 80 else "Suspicious"
    else:
        prediction_label = "Legitimate"
        risk_level = "Likely Safe" if confidence > 90 else "Low Risk"

    details = "; ".join(risk_factors) if risk_factors else "No obvious risk factors detected"
    return prediction_label, confidence, risk_level, risk_factors


# ============================================
# Message Analysis Functions
# ============================================
def analyze_message(text):
    """Analyze message text for phishing patterns using ML model"""
    if not msg_model or not msg_vectorizer:
        return None, 0, "Model not loaded", []

    vec = msg_vectorizer.transform([text])
    prediction = msg_model.predict(vec)[0]
    proba = msg_model.predict_proba(vec)[0]
    confidence = max(proba) * 100

    # Pattern-based analysis for explanations
    patterns = []
    urls_in_msg = re.findall(r'http[s]?://[^\s]+', text)
    if urls_in_msg:
        patterns.append(f"Contains {len(urls_in_msg)} URL(s) - verify destination carefully")

    urgency_words = ['urgent', 'immediately', 'now', 'limited', 'expires', 'deadline', 'today only', 'final']
    found_urgency = [w for w in urgency_words if w in text.lower()]
    if found_urgency:
        patterns.append(f"Urgency pressure language detected: {', '.join(found_urgency)}")

    credential_words = ['password', 'otp', 'pin', 'cvv', 'card number', 'account number']
    found_credentials = [w for w in credential_words if w in text.lower()]
    if found_credentials:
        patterns.append(f"Requests sensitive credentials: {', '.join(found_credentials)}")

    scam_words = ['winner', 'won', 'lottery', 'prize', 'free', 'gift', 'claim', 'bonus']
    found_scam = [w for w in scam_words if w in text.lower()]
    if found_scam:
        patterns.append(f"Too-good-to-be-true keywords: {', '.join(found_scam)}")

    threat_words = ['suspend', 'blocked', 'deactivate', 'closed', 'frozen', 'penalty', 'disconnection']
    found_threats = [w for w in threat_words if w in text.lower()]
    if found_threats:
        patterns.append(f"Account threat language: {', '.join(found_threats)}")

    financial_words = ['bank', 'refund', 'transfer', 'payment', 'money', 'invest']
    found_financial = [w for w in financial_words if w in text.lower()]
    if found_financial:
        patterns.append(f"Financial references: {', '.join(found_financial)}")

    if prediction == 1:
        prediction_label = "Phishing"
        risk_level = "Phishing Detected" if confidence > 75 else "Suspicious"
    else:
        prediction_label = "Legitimate"
        risk_level = "Likely Safe"

    details = "; ".join(patterns[:10]) if patterns else "No suspicious patterns detected"
    return prediction_label, confidence, risk_level, patterns


# ============================================
# Page Configuration
# ============================================
st.set_page_config(
    page_title="AI CyberShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# Dark Cyber Theme CSS
# ============================================
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1a2e 50%, #0f0f23 100%);
        color: #e0e6ed;
    }
    .css-1d391kg, section[data-testid="stSidebar"] {
        background: rgba(10, 14, 39, 0.98) !important;
        border-right: 1px solid rgba(0, 255, 136, 0.25);
    }
    .hero {
        background: linear-gradient(135deg, rgba(0, 255, 136, 0.12), rgba(0, 212, 255, 0.12));
        backdrop-filter: blur(15px);
        border: 1px solid rgba(0, 255, 136, 0.3);
        border-radius: 20px;
        padding: 50px 30px;
        text-align: center;
        margin-bottom: 30px;
    }
    .hero h1 {
        color: #00ff88 !important;
        font-size: 3em !important;
        font-weight: 800 !important;
        text-shadow: 0 0 25px rgba(0, 255, 136, 0.5);
        margin-bottom: 10px !important;
    }
    .hero p { color: #00d4ff !important; font-size: 1.25em !important; }
    .glass-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(15px);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 15px;
        padding: 25px;
        margin-bottom: 20px;
        transition: all 0.3s ease;
    }
    .glass-card:hover {
        border-color: rgba(0, 212, 255, 0.5);
        box-shadow: 0 0 25px rgba(0, 212, 255, 0.15);
    }
    .stat-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 12px;
        padding: 25px;
        text-align: center;
        transition: all 0.3s;
    }
    .stat-card:hover { transform: translateY(-5px); border-color: rgba(0, 255, 136, 0.5); }
    .stat-number {
        font-size: 2.8em;
        font-weight: 800;
        background: linear-gradient(135deg, #00ff88, #00d4ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        line-height: 1;
    }
    .stat-label { color: #a0b0c0; font-size: 0.9em; margin-top: 10px; }
    .badge-safe {
        background: rgba(0, 255, 136, 0.2); color: #00ff88; border: 1px solid #00ff88;
        padding: 8px 16px; border-radius: 25px; font-weight: 700; display: inline-block;
    }
    .badge-danger {
        background: rgba(255, 50, 50, 0.2); color: #ff3232; border: 1px solid #ff3232;
        padding: 8px 16px; border-radius: 25px; font-weight: 700; display: inline-block;
    }
    .badge-warning {
        background: rgba(255, 200, 0, 0.2); color: #ffc800; border: 1px solid #ffc800;
        padding: 8px 16px; border-radius: 25px; font-weight: 700; display: inline-block;
    }
    .section-title {
        color: #00d4ff;
        font-size: 1.8em;
        font-weight: 700;
        margin: 20px 0 15px 0;
        padding-bottom: 10px;
        border-bottom: 2px solid rgba(0, 212, 255, 0.3);
    }
    .risk-factor {
        background: rgba(255, 50, 50, 0.1);
        border-left: 3px solid #ff3232;
        padding: 10px 15px;
        margin: 8px 0;
        border-radius: 5px;
        color: #ffaaaa;
    }
    .safe-factor {
        background: rgba(0, 255, 136, 0.1);
        border-left: 3px solid #00ff88;
        padding: 10px 15px;
        margin: 8px 0;
        border-radius: 5px;
        color: #aaffcc;
    }
    .footer {
        text-align: center;
        padding: 30px;
        color: #6080a0;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        margin-top: 40px;
    }
    .stButton > button {
        background: linear-gradient(135deg, #00ff88, #00d4ff);
        color: #0a0e27;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: 700;
        transition: all 0.3s;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 20px rgba(0, 255, 136, 0.4);
    }
    h1, h2, h3 { color: #e0e6ed !important; }
</style>
""", unsafe_allow_html=True)


# ============================================
# Sidebar Navigation
# ============================================
st.sidebar.markdown("## 🛡️ CyberShield")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", [
    "🏠 Home",
    "📊 Dashboard",
    "🔗 URL Scanner",
    "💬 Message Detector",
    "📈 Threat Analytics",
    "📜 Scan History",
    "📋 Reports",
    "ℹ️ About"
])

st.sidebar.markdown("---")
st.sidebar.markdown("### System Status")
st.sidebar.markdown("✅ URL Scanner: Active" if url_model is not None else "❌ URL Scanner: Offline")
st.sidebar.markdown("✅ Message Detector: Active" if msg_model is not None else "❌ Message Detector: Offline")
st.sidebar.markdown("✅ Database: Connected")
st.sidebar.markdown("---")
st.sidebar.markdown("**AI-Powered CyberShield**")
st.sidebar.markdown("B.Tech CSE Major Project")


# ============================================
# Page: Home
# ============================================
if page == "🏠 Home":
    st.markdown("""
    <div class="hero">
        <h1>🛡️ AI-Powered CyberShield</h1>
        <p>Intelligent Cybersecurity Platform Powered by Machine Learning</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">🎯 What This Platform Does</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="glass-card">
        <p style="color:#e0e6ed;font-size:1.1em;line-height:1.8;">
            AI-Powered CyberShield is a cybersecurity platform that uses <strong style="color:#00ff88;">Machine Learning</strong>
            to detect phishing URLs, malicious websites, and suspicious messages. Our AI models analyze patterns
            and characteristics to identify potential cyber threats before they harm you. Every scan is stored
            securely in a database so you can track your security history over time.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">🔐 Key Features</div>', unsafe_allow_html=True)
    features = [
        ("🔗", "URL Scanner", "ML-powered phishing URL detection with detailed risk analysis"),
        ("💬", "Message Detector", "Identify phishing attempts in emails, SMS, and chat messages"),
        ("📊", "Dashboard", "Real-time threat analytics and scan statistics"),
        ("📜", "Scan History", "Complete history of all scans with timestamps"),
        ("📋", "Security Reports", "Detailed downloadable reports for each scan"),
        ("📈", "Threat Analytics", "Visual charts of detected threats over time"),
    ]
    cols = st.columns(3)
    for i, (icon, title, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(f"""
            <div class="glass-card" style="text-align:center;">
                <div style="font-size:3em;">{icon}</div>
                <h3 style="color:#00d4ff;">{title}</h3>
                <p style="color:#a0b0c0;">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">🤖 AI Models Used</div>', unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        <div class="glass-card">
            <h4 style="color:#00ff88;">1. URL Phishing Detection</h4>
            <p style="color:#a0b0c0;"><strong>Algorithm:</strong> Random Forest Classifier</p>
            <p style="color:#a0b0c0;"><strong>Features:</strong> URL length, IP address, suspicious TLDs, keywords</p>
            <p style="color:#a0b0c0;"><strong>Library:</strong> Scikit-learn</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="glass-card">
            <h4 style="color:#00ff88;">2. Message Phishing Detection</h4>
            <p style="color:#a0b0c0;"><strong>Algorithm:</strong> Multinomial Naive Bayes + TF-IDF</p>
            <p style="color:#a0b0c0;"><strong>Features:</strong> Word frequencies, n-grams</p>
            <p style="color:#a0b0c0;"><strong>Library:</strong> Scikit-learn</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="footer">
        <p>🛡️ <strong>AI-Powered CyberShield</strong> | B.Tech CSE Major Project</p>
        <p>Powered by Scikit-learn | Streamlit | SQLite | Plotly</p>
    </div>
    """, unsafe_allow_html=True)


# ============================================
# Page: Dashboard
# ============================================
elif page == "📊 Dashboard":
    st.markdown('<div class="section-title">📊 Security Dashboard</div>', unsafe_allow_html=True)

    scans_df = get_all_scans()
    total_scans = len(scans_df)
    if total_scans > 0:
        safe_scans = len(scans_df[scans_df['prediction'].str.contains('Legitimate|Safe', case=False, na=False)])
        phishing_scans = len(scans_df[scans_df['prediction'].str.contains('Phishing|Malicious', case=False, na=False)])
        suspicious_scans = len(scans_df[scans_df['prediction'].str.contains('Suspicious', case=False, na=False)])
    else:
        safe_scans, phishing_scans, suspicious_scans = 0, 0, 0

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="stat-card"><div class="stat-number">{total_scans}</div><div class="stat-label">Total Scans</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="stat-card"><div class="stat-number">{safe_scans}</div><div class="stat-label">Safe Detected</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="stat-card"><div class="stat-number">{suspicious_scans}</div><div class="stat-label">Suspicious</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="stat-card"><div class="stat-number">{phishing_scans}</div><div class="stat-label">Threats Blocked</div></div>', unsafe_allow_html=True)

    if total_scans > 0:
        st.markdown('<div class="section-title">📈 Scan Distribution</div>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            fig_pie = px.pie(
                values=[safe_scans, suspicious_scans, phishing_scans],
                names=['Safe', 'Suspicious', 'Threats'],
                color_discrete_map={'Safe': '#00ff88', 'Suspicious': '#ffc800', 'Threats': '#ff3232'},
                title="Threat Distribution"
            )
            fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#e0e6ed')
            st.plotly_chart(fig_pie, use_container_width=True)
        with col2:
            scan_types = scans_df['scan_type'].value_counts()
            fig_bar = px.bar(
                x=scan_types.index, y=scan_types.values,
                title="Scan Types", color=scan_types.values,
                color_continuous_scale=['#00d4ff', '#00ff88']
            )
            fig_bar.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#e0e6ed')
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown('<div class="section-title">📜 Recent Scans</div>', unsafe_allow_html=True)
        recent = scans_df.head(10)[['timestamp', 'scan_type', 'prediction', 'risk_level', 'confidence']].copy()
        recent['confidence'] = recent['confidence'].round(1)
        st.dataframe(recent, use_container_width=True)
    else:
        st.markdown("""
        <div class="glass-card" style="text-align:center;padding:40px;">
            <h3 style="color:#00d4ff;">No scans yet!</h3>
            <p style="color:#a0b0c0;">Start scanning URLs or messages to see analytics here.</p>
        </div>
        """, unsafe_allow_html=True)


# ============================================
# Page: URL Scanner
# ============================================
elif page == "🔗 URL Scanner":
    st.markdown('<div class="section-title">🔗 AI URL Scanner</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card">
        <p style="color:#a0b0c0;">Enter a URL below. The ML model analyzes 20 characteristics — length, IP address,
        suspicious TLDs, keywords, subdomains — to predict phishing risk.</p>
    </div>
    """, unsafe_allow_html=True)

    url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com")

    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        scan_btn = st.button("🔍 Scan URL", use_container_width=True)

    if scan_btn:
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL first!")
        elif not url_input.strip().startswith('http'):
            st.warning("⚠️ URL must start with http:// or https://")
        else:
            with st.spinner("🔍 Analyzing URL with AI model..."):
                import time
                time.sleep(1)

                prediction, confidence, risk_level, risk_factors = analyze_url(url_input.strip())

                if prediction is None:
                    st.error("❌ Model not loaded. Run train_models.py first!")
                else:
                    save_scan("URL", url_input.strip(), prediction, confidence, risk_level,
                              "; ".join(risk_factors) if risk_factors else "No risk factors")

                    is_danger = 'Phishing' in prediction or 'Malicious' in prediction
                    badge = 'badge-danger' if is_danger else ('badge-warning' if 'Suspicious' in risk_level else 'badge-safe')

                    st.markdown(f"""
                    <div class="glass-card">
                        <h3 style="color:#00d4ff;">Scan Result</h3>
                        <p><strong>URL:</strong> <span style="color:#00d4ff;">{url_input}</span></p>
                        <p><strong>Prediction:</strong> <span class="{badge}">{prediction}</span></p>
                        <p><strong>Risk Level:</strong> <span class="{badge}">{risk_level}</span></p>
                        <p><strong>Confidence:</strong> {confidence:.1f}%</p>
                    </div>
                    """, unsafe_allow_html=True)

                    if risk_factors:
                        st.markdown('<div class="section-title">⚠️ Risk Factors Detected</div>', unsafe_allow_html=True)
                        for factor in risk_factors:
                            st.markdown(f'<div class="risk-factor">⚠️ {factor}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="safe-factor">✅ No obvious risk factors detected.</div>', unsafe_allow_html=True)

                    st.info("⚠️ This is a machine learning prediction, not a guarantee. Always verify unknown URLs manually.")
                    st.success("✅ Scan saved to history!")

    # Sample test URLs
    st.markdown('<div class="section-title">🧪 Sample URLs to Test</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="glass-card">
        <p style="color:#00ff88;">✅ Try Safe: <code>https://www.google.com</code></p>
        <p style="color:#ff3232;">🚨 Try Phishing: <code>http://paypal-verify-account.tk/login</code></p>
        <p style="color:#ffc800;">⚠️ Try Suspicious: <code>http://free-gift-card-giveaway.ga/claim</code></p>
    </div>
    """, unsafe_allow_html=True)


# ============================================
# Page: Message Detector
# ============================================
elif page == "💬 Message Detector":
    st.markdown('<div class="section-title">💬 Phishing Message Detector</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card">
        <p style="color:#a0b0c0;">Paste a suspicious SMS, email, or chat message. The ML model (Naive Bayes + TF-IDF)
        classifies it and highlights suspicious patterns like urgency language, credential requests, and scam keywords.</p>
    </div>
    """, unsafe_allow_html=True)

    msg_input = st.text_area("Paste message here:", height=150,
                             placeholder="Dear customer, your account has been suspended...")

    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        analyze_btn = st.button("🔍 Analyze Message", use_container_width=True)

    if analyze_btn:
        if not msg_input.strip():
            st.warning("⚠️ Please paste a message first!")
        elif len(msg_input.strip()) < 10:
            st.warning("⚠️ Message too short (minimum 10 characters).")
        else:
            with st.spinner("🔍 Analyzing message with AI model..."):
                import time
                time.sleep(1)

                prediction, confidence, risk_level, patterns = analyze_message(msg_input.strip())

                if prediction is None:
                    st.error("❌ Model not loaded. Run train_models.py first!")
                else:
                    display_text = msg_input.strip()[:200] + ("..." if len(msg_input) > 200 else "")
                    save_scan("Message", display_text, prediction, confidence, risk_level,
                              "; ".join(patterns) if patterns else "No suspicious patterns")

                    is_phish = 'Phishing' in prediction
                    badge = 'badge-danger' if is_phish else ('badge-warning' if 'Suspicious' in risk_level else 'badge-safe')

                    st.markdown(f"""
                    <div class="glass-card">
                        <h3 style="color:#00d4ff;">Analysis Result</h3>
                        <p><strong>Prediction:</strong> <span class="{badge}">{prediction}</span></p>
                        <p><strong>Risk Level:</strong> <span class="{badge}">{risk_level}</span></p>
                        <p><strong>Confidence:</strong> {confidence:.1f}%</p>
                    </div>
                    """, unsafe_allow_html=True)

                    if patterns:
                        st.markdown('<div class="section-title">⚠️ Suspicious Patterns Detected</div>', unsafe_allow_html=True)
                        for pattern in patterns[:10]:
                            st.markdown(f'<div class="risk-factor">⚠️ {pattern}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="safe-factor">✅ No suspicious patterns detected.</div>', unsafe_allow_html=True)

                    st.info("⚠️ This is a machine learning prediction. Always be cautious with unknown senders.")
                    st.success("✅ Scan saved to history!")

    st.markdown('<div class="section-title">🧪 Sample Messages to Test</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="glass-card">
        <p style="color:#00ff88;">✅ Safe: <code>Hi, can we meet tomorrow at 3 PM for the project discussion?</code></p>
        <p style="color:#ff3232;">🚨 Phishing: <code>URGENT: Your bank account has been suspended. Click http://bank-update.tk to verify</code></p>
    </div>
    """, unsafe_allow_html=True)


# ============================================
# Page: Threat Analytics
# ============================================
elif page == "📈 Threat Analytics":
    st.markdown('<div class="section-title">📈 Threat Analytics</div>', unsafe_allow_html=True)

    scans_df = get_all_scans()

    if len(scans_df) == 0:
        st.markdown("""
        <div class="glass-card" style="text-align:center;padding:40px;">
            <h3 style="color:#00d4ff;">No data available</h3>
            <p style="color:#a0b0c0;">Perform some scans to see analytics here.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="section-title">📊 Confidence Distribution</div>', unsafe_allow_html=True)
        fig = px.histogram(scans_df, x='confidence', nbins=10,
                           title="Model Confidence Distribution",
                           color_discrete_sequence=['#00d4ff'])
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#e0e6ed')
        st.plotly_chart(fig, use_container_width=True)

        st.markdown('<div class="section-title">🎯 Risk Level Distribution</div>', unsafe_allow_html=True)
        risk_counts = scans_df['risk_level'].value_counts()
        fig2 = px.bar(x=risk_counts.index, y=risk_counts.values,
                      title="Risk Levels Detected", color=risk_counts.values,
                      color_continuous_scale=['#00ff88', '#ffc800', '#ff3232'])
        fig2.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#e0e6ed')
        st.plotly_chart(fig2, use_container_width=True)

        scans_df['timestamp'] = pd.to_datetime(scans_df['timestamp'])
        scans_df['date'] = scans_df['timestamp'].dt.date
        daily = scans_df.groupby('date').size().reset_index(name='count')

        st.markdown('<div class="section-title">📅 Daily Scan Activity</div>', unsafe_allow_html=True)
        fig3 = px.line(daily, x='date', y='count', title="Scans Over Time",
                       color_discrete_sequence=['#00ff88'])
        fig3.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#e0e6ed')
        st.plotly_chart(fig3, use_container_width=True)


# ============================================
# Page: Scan History
# ============================================
elif page == "📜 Scan History":
    st.markdown('<div class="section-title">📜 Scan History</div>', unsafe_allow_html=True)

    scans_df = get_all_scans()

    if len(scans_df) == 0:
        st.markdown("""
        <div class="glass-card" style="text-align:center;padding:40px;">
            <h3 style="color:#00d4ff;">No scans yet</h3>
            <p style="color:#a0b0c0;">Your scan history will appear here after you perform scans.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        col1, col2 = st.columns(2)
        with col1:
            scan_type_filter = st.selectbox("Filter by Type", ["All", "URL", "Message"])
        with col2:
            result_filter = st.selectbox("Filter by Result", ["All", "Safe", "Phishing", "Suspicious"])

        filtered = scans_df.copy()
        if scan_type_filter != "All":
            filtered = filtered[filtered['scan_type'] == scan_type_filter]
        if result_filter != "All":
            filtered = filtered[filtered['prediction'].str.contains(result_filter, case=False, na=False)]

        st.markdown(f"**Showing {len(filtered)} of {len(scans_df)} scans**")

        for _, row in filtered.iterrows():
            badge = 'badge-danger' if 'Phishing' in row['prediction'] else ('badge-warning' if 'Suspicious' in row['risk_level'] else 'badge-safe')
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex;justify-content:space-between;">
                    <div><strong style="color:#00d4ff;">[{row['scan_type']}]</strong> <span style="color:#a0b0c0;">{row['timestamp']}</span></div>
                    <span class="{badge}">{row['prediction']}</span>
                </div>
                <p style="color:#e0e6ed;margin:10px 0;"><strong>Input:</strong> {row['input_content'][:120]}</p>
                <p style="color:#a0b0c0;font-size:0.9em;"><strong>Confidence:</strong> {row['confidence']:.1f}% | <strong>Risk:</strong> {row['risk_level']}</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        if st.button("🗑️ Clear All History"):
            clear_history()
            st.success("History cleared!")
            st.rerun()


# ============================================
# Page: Reports
# ============================================
elif page == "📋 Reports":
    st.markdown('<div class="section-title">📋 Security Reports</div>', unsafe_allow_html=True)

    scans_df = get_all_scans()

    if len(scans_df) == 0:
        st.markdown("""
        <div class="glass-card" style="text-align:center;padding:40px;">
            <h3 style="color:#00d4ff;">No reports available</h3>
            <p style="color:#a0b0c0;">Perform scans to generate security reports.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"**{len(scans_df)} reports available for download**")

        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="📥 Download All Reports (CSV)",
                data=scans_df.to_csv(index=False),
                file_name=f"cybershield_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        with col2:
            safe_n = len(scans_df[scans_df['prediction'].str.contains('Legitimate|Safe', case=False, na=False)])
            phish_n = len(scans_df[scans_df['prediction'].str.contains('Phishing|Malicious', case=False, na=False)])
            susp_n = len(scans_df[scans_df['prediction'].str.contains('Suspicious', case=False, na=False)])
            summary = f"""AI-POWERED CYBERSHIELD - SECURITY REPORT
===========================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

TOTAL SCANS: {len(scans_df)}
- URL Scans: {len(scans_df[scans_df['scan_type'] == 'URL'])}
- Message Scans: {len(scans_df[scans_df['scan_type'] == 'Message'])}

THREAT STATISTICS:
- Safe: {safe_n}
- Suspicious: {susp_n}
- Phishing/Malicious: {phish_n}

AVERAGE CONFIDENCE: {scans_df['confidence'].mean():.1f}%

===========================================
AI-Powered CyberShield | B.Tech CSE Project
"""
            st.download_button(
                label="📄 Download Summary Report (TXT)",
                data=summary,
                file_name=f"cybershield_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )

        st.markdown('<div class="section-title">📋 Individual Scan Reports</div>', unsafe_allow_html=True)
        for _, row in scans_df.head(20).iterrows():
            with st.expander(f"Report #{row['id']} — {row['scan_type']} — {row['timestamp']}"):
                st.markdown(f"**Scan Type:** {row['scan_type']}")
                st.markdown(f"**Date & Time:** {row['timestamp']}")
                st.markdown(f"**Input:** {row['input_content']}")
                st.markdown(f"**Prediction:** {row['prediction']}")
                st.markdown(f"**Confidence:** {row['confidence']:.1f}%")
                st.markdown(f"**Risk Level:** {row['risk_level']}")
                st.markdown(f"**Details:** {row['details']}")

                report_text = f"""CYBERSHIELD SCAN REPORT
========================
Scan ID: {row['id']}
Date: {row['timestamp']}
Scan Type: {row['scan_type']}

INPUT:
{row['input_content']}

PREDICTION: {row['prediction']}
CONFIDENCE: {row['confidence']:.1f}%
RISK LEVEL: {row['risk_level']}

DETAILS:
{row['details']}

---
AI-Powered CyberShield | B.Tech CSE Project
"""
                st.download_button(
                    label=f"📥 Download Report #{row['id']}",
                    data=report_text,
                    file_name=f"scan_report_{row['id']}.txt",
                    mime="text/plain"
                )


# ============================================
# Page: About
# ============================================
elif page == "ℹ️ About":
    st.markdown('<div class="section-title">ℹ️ About This Project</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card">
        <h2 style="color:#00ff88;">AI-Powered CyberShield</h2>
        <p style="color:#a0b0c0;font-size:1.1em;">An intelligent cybersecurity platform powered by Machine Learning</p>
    </div>

    <div class="glass-card">
        <h3 style="color:#00d4ff;">📖 Project Description</h3>
        <p style="color:#e0e6ed;line-height:1.8;">
            AI-Powered CyberShield is a B.Tech CSE final-year major project demonstrating the practical
            application of Machine Learning in cybersecurity. The platform uses trained ML models to detect
            phishing URLs and suspicious messages, helping users identify potential cyber threats. All scans
            are stored in a SQLite database and can be exported as security reports.
        </p>
    </div>

    <div class="glass-card">
        <h3 style="color:#00d4ff;">🛠️ Technology Stack</h3>
        <ul style="color:#e0e6ed;line-height:2;">
            <li><strong style="color:#00ff88;">Frontend:</strong> Streamlit (Python web framework)</li>
            <li><strong style="color:#00ff88;">Machine Learning:</strong> Scikit-learn (Random Forest, Naive Bayes)</li>
            <li><strong style="color:#00ff88;">Feature Engineering:</strong> TF-IDF Vectorizer, 20 custom URL features</li>
            <li><strong style="color:#00ff88;">Database:</strong> SQLite</li>
            <li><strong style="color:#00ff88;">Visualization:</strong> Plotly</li>
            <li><strong style="color:#00ff88;">Language:</strong> Python 3</li>
        </ul>
    </div>

    <div class="glass-card">
        <h3 style="color:#00d4ff;">🤖 ML Models</h3>
        <p style="color:#e0e6ed;"><strong>1. URL Phishing Detection:</strong></p>
        <ul style="color:#a0b0c0;">
            <li>Algorithm: Random Forest Classifier (100 trees, depth 10)</li>
            <li>Features: 20 URL characteristics (length, IP, TLD, keywords, etc.)</li>
            <li>Training data: 100 URLs (legitimate + phishing patterns)</li>
        </ul>
        <p style="color:#e0e6ed;"><strong>2. Message Phishing Detection:</strong></p>
        <ul style="color:#a0b0c0;">
            <li>Algorithm: Multinomial Naive Bayes</li>
            <li>Features: TF-IDF vectors (1000 features, 1-2 grams)</li>
            <li>Training data: 100 messages (legitimate + phishing)</li>
        </ul>
    </div>

    <div class="glass-card">
        <h3 style="color:#00d4ff;">📁 Project Structure</h3>
        <pre style="color:#a0b0c0;background:rgba(0,0,0,0.3);padding:15px;border-radius:8px;">
cybershield/
├── app.py                  # Main Streamlit application
├── train_models.py         # ML model training script
├── requirements.txt        # Python dependencies
├── README.md               # Documentation
├── models/
│   ├── url_model.pkl       # Trained Random Forest
│   ├── url_features.pkl    # Feature column names
│   ├── message_model.pkl   # Trained Naive Bayes
│   └── message_vectorizer.pkl  # TF-IDF vectorizer
├── data/
│   ├── urls_dataset.csv    # URL training data
│   └── messages_dataset.csv # Message training data
└── cybershield.db          # SQLite database (auto-created)
        </pre>
    </div>

    <div class="glass-card">
        <h3 style="color:#00d4ff;">⚠️ Limitations & Disclaimer</h3>
        <p style="color:#e0e6ed;line-height:1.8;">
            <strong>Important:</strong> This is an educational project. The ML models are trained on
            limited sample data and may not detect all phishing attempts. Predictions are ML-based
            estimates, not guaranteed security verdicts. Always use multiple security layers and
            exercise caution with unknown URLs and messages.
        </p>
        <p style="color:#ffc800;">
            The models use real ML predictions (not hardcoded results), but training data is limited
            in scope. For production use, models should be trained on larger datasets such as
            PhishTank or UCI Phishing Dataset.
        </p>
    </div>

    <div class="glass-card">
        <h3 style="color:#00d4ff;">🎓 Academic Information</h3>
        <p style="color:#e0e6ed;"><strong>Project Type:</strong> B.Tech CSE Major Project</p>
        <p style="color:#e0e6ed;"><strong>Domain:</strong> Artificial Intelligence + Cybersecurity</p>
        <p style="color:#e0e6ed;"><strong>Key Concepts:</strong> Machine Learning, Phishing Detection, Feature Engineering, NLP, Web Security</p>
    </div>

    <div class="footer">
        <p>🛡️ <strong>AI-Powered CyberShield</strong></p>
        <p>B.Tech CSE Major Project | Built with Streamlit + Scikit-learn</p>
    </div>
    """, unsafe_allow_html=True)
