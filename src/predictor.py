import sys
import os
import joblib
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.feature_extractor import URLLexicalFeatureExtractor

WHITELIST = ['google.com', 'wikipedia.org', 'github.com', 'go.id', 'ac.id', 'amazon.com']

class PhishingPredictor:
    def __init__(self, model_path='model/phishing_model.pkl', features_path='model/feature_names.pkl'):
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(features_path)
        self.extractor = URLLexicalFeatureExtractor()

    def predict(self, url: str) -> dict:
        url_lower = url.lower().strip()
        
        # Cek Whitelist
        if any(domain in url_lower for domain in WHITELIST):
            return {'status': 'SAFE', 'phishing_probability': 0.0, 'is_whitelisted': True}

        # Ekstraksi & Prediksi
        feat_dict = self.extractor.extract_features(url_lower)
        df_feat = pd.DataFrame([feat_dict])[self.feature_names]
        
        prob = self.model.predict_proba(df_feat)[0][1] # Probabilitas kelas 1 (Phishing)
        status = 'PHISHING' if prob >= 0.5 else 'SAFE'

        return {
            'status': status,
            'phishing_probability': float(prob),
            'is_whitelisted': False,
            'features': feat_dict
        }