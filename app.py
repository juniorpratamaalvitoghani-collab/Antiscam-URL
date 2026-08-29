import pandas as pd
import joblib
import os
import sys
import tldextract
import streamlit as st
import time

st.set_page_config(page_title="AntiScam - Phishing Detector", page_icon="🛡️", layout="centered")
st.markdown("""
<style>
    /* 1. Sembunyikan Header bawaan */
    header {visibility: hidden !important;}
    #MainMenu {visibility: hidden !important;}
    .stAppDeployButton {display: none !important;}
    div[data-testid="stDecoration"] {display: none !important;}
    div[data-testid="stStatusWidget"] {display: none !important;}
    
    /* 2. Kustomisasi Footer */
    footer {
        visibility: visible !important;
        font-size: 0px !important;
        text-align: center;
        padding: 10px;
    }
    
    footer::after {
        content: "🛡️ Anti-Scam | Powered by Machine Learning";
        visibility: visible !important;
        display: block;
        font-size: 14px !important;
        color: #9ca3af;
        font-weight: 500;
    }

    /* 3. Background Animasi Cyber */
    .stApp {
        background: linear-gradient(-45deg, #0a0e17, #111827, #1e1b4b, #0f172a) !important;
        background-size: 400% 400% !important;
        animation: gradientBG 12s ease infinite !important;
    }

    @keyframes gradientBG {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
</style>
""", unsafe_allow_html=True)

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from src.feature_extractor import URLLexicalFeatureExtractor

st.title("🛡️ Anti-Scam URL Phishing")

# -------------------------------------------------------------
# 1. LOAD TRANCO TOP DOMAINS (AUTO-WHITELIST)
# -------------------------------------------------------------
TRANCO_CSV_PATH = os.path.join('dataset', 'tranco_top1m.csv')
EXTRA_SAFE_TLDS = {'go.id', 'ac.id', 'gov', 'edu', 'mil'}

@st.cache_resource
def load_tranco_whitelist(file_path: str, max_rank: int = 250000) -> set:
    if not os.path.exists(file_path):
        st.warning(f"⚠️ File Tranco `{file_path}` tidak ditemukan! Pastikan file dinamai `tranco_top1m.csv` di folder `dataset/`.")
        return set()
    
    try:
        df = pd.read_csv(file_path, header=None, names=['rank', 'domain'], nrows=max_rank)
        domains_set = set(df['domain'].astype(str).str.lower().str.strip())
        return domains_set
    except Exception as e:
        st.error(f"Gagal membaca file Tranco List: {e}")
        return set()

tranco_domains = load_tranco_whitelist(TRANCO_CSV_PATH, max_rank=250000)

def is_whitelisted(url: str) -> tuple[bool, str]:
    try:
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower()
        
        if registered_domain in tranco_domains:
            return True, registered_domain
            
        if ext.suffix.lower() in EXTRA_SAFE_TLDS:
            return True, f".{ext.suffix}"
    except Exception:
        pass
    return False, ""

# -------------------------------------------------------------
# 2. LOAD ARTIFACTS MODEL ML
# -------------------------------------------------------------
@st.cache_resource
def load_artifacts():
    model_path = os.path.join('model', 'phishing_model.pkl')
    features_path = os.path.join('model', 'feature_names.pkl')
    
    if not os.path.exists(model_path) or not os.path.exists(features_path):
        st.error("⚠️ File model/feature_names tidak ditemukan di folder `model/`!")
        st.stop()
        
    model = joblib.load(model_path)
    feature_names = joblib.load(features_path)
    return model, feature_names

model, feature_names = load_artifacts()
extractor = URLLexicalFeatureExtractor()

# -------------------------------------------------------------
# 3. USER INTERFACE & DETEKSI
# -------------------------------------------------------------
input_url = st.text_input("Masukkan URL yang ingin diperiksa:", placeholder="Contoh: https://www.google.com")

if st.button("Analisis URL", type="primary"):
    if not input_url.strip():
        st.warning("Masukkan URL!")
    else:
        with st.spinner("Menganalisis keamanan URL..."):
            time.sleep(1)
            
        st.divider()
        
        # LAPIS 1: Auto-Whitelist Tranco
        is_white, matched_domain = is_whitelisted(input_url)
        
        if is_white:
            st.markdown("**Skor Risiko Kerentanan:** :green[**0.00%**]")
            st.success("✅ **STATUS: AMAN / TERVERIFIKASI**")
        else:
            # LAPIS 2: Predict ML XGBoost (Jika domain tidak ada di Tranco)
            raw_features = extractor.extract_features(input_url)
            df_features = pd.DataFrame([raw_features])[feature_names]

            probabilities = model.predict_proba(df_features)[0]
            phishing_prob = float(probabilities[1])

            # LAPIS 3: Heuristic Smoothing & Rule Intervention
            ext = tldextract.extract(input_url)
            is_common_tld = ext.suffix.lower() in ['com', 'org', 'net', 'id', 'co.id', 'io']
            has_no_bad_words = raw_features.get('suspicious_keyword_count', 0) == 0
            is_https = raw_features.get('is_https', 0) == 1
            has_no_ip = raw_features.get('has_ip', 0) == 0

            # --- ATURAN HEURISTIC SMOOTHING & INTERVENSI ---

            # A. Keringanan untuk HTTPS & TLD umum yang bersih
            if is_https and has_no_ip and is_common_tld and has_no_bad_words:
                phishing_prob -= 0.15  

            # B. Kalibrasi untuk IP Address tanpa kata kunci sensitif
            elif not has_no_ip and has_no_bad_words:
                phishing_prob = 0.55

            # C. Intervensi jika ML memberikan skor terlalu rendah (< 0.35) tapi ada anomali ringan
            elif phishing_prob < 0.35:
                if not has_no_bad_words or raw_features.get('url_length', 0) > 75:
                    phishing_prob = 0.45 

            # Pastikan skor tetap berada pada rentang [0.0, 1.0]
            phishing_prob = max(0.0, min(1.0, phishing_prob))

            # Pengecekan status akhir
            if phishing_prob >= 0.70:
                st.markdown(f"**Skor Risiko Kerentanan:** {phishing_prob:.2%}")
                st.error("🚨 **STATUS: SANGAT BERBAHAYA (PHISHING)**")
            elif phishing_prob >= 0.35:
                st.markdown(f"**Skor Risiko Kerentanan:** {phishing_prob:.2%}")
                st.warning("⚠️ **STATUS: MENCURIGAKAN (POTENSI ANCAMAN)**")
            else:
                st.markdown(f"**Skor Risiko Kerentanan:** {phishing_prob:.2%}")
                st.success("✅ **STATUS: AMAN / BENIGN**")