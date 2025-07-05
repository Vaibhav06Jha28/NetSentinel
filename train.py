# train_model.py
from sklearn.ensemble import IsolationForest
from joblib import dump
import os

# Sample training data: [protocol_code, packet_length]
X_train = [
    [0, 400], [0, 420], [0, 380],   # Normal TCP
    [1, 60],  [1, 65],  [1, 62],    # Normal UDP
    [2, 100], [2, 110]              # Normal ICMP
]

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)

os.makedirs("models", exist_ok=True)
dump(model, "models/isolation_model.pkl")
print("✅ Model saved at models/isolation_model.pkl")
