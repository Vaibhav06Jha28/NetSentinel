# train_model.py

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

# === Config ===
DATA_PATH = "data/normal_traffic.csv"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_model.pkl")

# === Step 1: Load Data ===
try:
    df = pd.read_csv(DATA_PATH, header=None, names=["src", "dst", "proto", "length"])
    print(f"✅ Loaded {len(df)} records from {DATA_PATH}")
except FileNotFoundError:
    print(f"❌ File not found: {DATA_PATH}")
    exit(1)

# === Step 2: Preprocessing ===
try:
    df = df[["proto", "length"]]  # Drop IPs for ML
    df["proto"] = df["proto"].astype("category").cat.codes  # Encode protocol
except Exception as e:
    print(f"❌ Data preprocessing failed: {e}")
    exit(1)

# === Step 3: Train Isolation Forest Model ===
try:
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(df)
    print("✅ Isolation Forest model trained.")
except Exception as e:
    print(f"❌ Model training failed: {e}")
    exit(1)

# === Step 4: Save the Model ===
try:
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"✅ Model saved to {MODEL_PATH}")
except Exception as e:
    print(f"❌ Model saving failed: {e}")

