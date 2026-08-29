import sys
import os
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.feature_extractor import URLLexicalFeatureExtractor

def train():
    print("🔄 1. Membaca dataset/raw_data.csv...")
    df = pd.read_csv('dataset/raw_data.csv')
    
    df.columns = [col.lower() for col in df.columns]
    
    url_col = next((col for col in df.columns if col in ['url', 'urls', 'domain', 'link']), None)
    target_col = next((col for col in df.columns if col in ['label', 'type', 'class', 'target', 'result']), None)

    if not url_col or not target_col:
        raise ValueError("Kolom URL atau Label tidak ditemukan di dataset!")

    print(f"ℹ️ Menggunakan kolom '{url_col}' sebagai URL dan '{target_col}' sebagai Label.")

    df[target_col] = df[target_col].astype(str).str.lower()
    label_mapping = {
        'bad': 1, 'phishing': 1, 'malicious': 1, '1': 1,
        'good': 0, 'benign': 0, 'safe': 0, '0': 0
    }
    
    df['target'] = df[target_col].map(label_mapping)
    df = df.dropna(subset=['target'])
    df['target'] = df['target'].astype(int)

    print(f"🔄 2. Mengekstraksi fitur leksikal dari {len(df)} URL...")
    extractor = URLLexicalFeatureExtractor()
    features_list = [extractor.extract_features(url) for url in df[url_col]]
    X = pd.DataFrame(features_list)
    y = df['target']

    print("🔄 3. Melatih XGBoost Classifier...")
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', XGBClassifier(
            n_estimators=150,
            learning_rate=0.08,
            max_depth=8,
            random_state=42,
            eval_metric='logloss'
        ))
    ])
    
    pipeline.fit(X, y)
    
    output_dir = 'models'
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"💾 4. Menyimpan artefak model ke folder {output_dir}/...")
    joblib.dump(pipeline, os.path.join(output_dir, 'phishing_model.pkl'))
    joblib.dump(list(X.columns), os.path.join(output_dir, 'feature_names.pkl'))
    
    print("✅ Pelatihan Selesai! Model XGBoost berhasil diperbarui.")

if __name__ == '__main__':
    train()