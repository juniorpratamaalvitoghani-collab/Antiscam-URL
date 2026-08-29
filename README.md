# 🛡️ AntiScam - Phishing Detector

Aplikasi deteksi URL Phishing berbasis **Machine Learning (XGBoost)** dan **Auto-Whitelist (Tranco Top Domains)** yang dibangun menggunakan **Streamlit**.

---

## 🚀 Fitur Utama
* **Lapis 1 (Auto-Whitelist):** Pengecekan otomatis ke *Tranco Top 250k Domains* & TLD Instansi Resmi (`go.id`, `ac.id`, dll) untuk menjamin 0% risiko pada situs resmi.
* **Lapis 2 (ML XGBoost):** Prediksi berbasis *Lexical URL Features* menggunakan model XGBoost.
* **Lapis 3 (Hard-Rules Calibration):** Deteksi khusus untuk *Typosquatting* (peniruan merek seperti `paypa1`, `g00gle`), IP Direct Address, serta penyesuaian skor ekstrem (0% vs ≥90%).

---

## 🛠️ Teknologi yang Digunakan
* **Python 3.10+**
* **Streamlit** (User Interface)
* **XGBoost & Scikit-Learn** (Machine Learning Engine)
* **Pandas & Joblib** (Data Processing & Model Loading)
* **TLDExtract** (Domain Parsing)

---

## 📂 Struktur Folder

```text
├── dataset/
│   └── tranco_top1m.csv
├── model/
│   ├── phishing_model.pkl
│   └── feature_names.pkl
├── src/
│   └── feature_extractor.py
├── app.py
├── requirements.txt
└── README.md

Cara Menjalankan di Lokal
1.Clone Repositori:
    git clone [https://github.com/username/Antiscam-URL.git](https://github.com/username/Antiscam-URL.git)
    cd Antiscam-URL
2.Buat & Aktifkan Virtual Environment (Opsional):
    python -m venv venv
    # Windows:
    venv\Scripts\activate
3.Install Dependencies:
    pip install -r requirements.txt
4.Jalankan Aplikasi:
    streamlit run app.py

