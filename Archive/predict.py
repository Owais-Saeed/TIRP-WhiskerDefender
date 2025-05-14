# predict.py

import pandas as pd
import joblib

# === Load model and scaler ===
model = joblib.load("stacked_model.pkl")
scaler = joblib.load("scaler.pkl")

# === Load input data ===
input_file = "sample_input_for_prediction.csv"
df = pd.read_csv(input_file)

# === Scale input ===
X_scaled = scaler.transform(df)

# === Predict ===
predictions = model.predict(X_scaled)
probs = model.predict_proba(X_scaled)

# === Confidence level categorization function ===
def confidence_label(score):
    if score >= 0.9:
        return "High Confidence"
    elif score >= 0.7:
        return "Medium Confidence"
    else:
        return "Low Confidence"

# === Stylized Output ===
for i, (row, pred, prob) in enumerate(zip(df.iterrows(), predictions, probs)):
    sample_id = f"sample_row_{i+1}"
    is_malware = pred == 1
    confidence_pct = prob[1 if is_malware else 0] * 100
    confidence_level = confidence_label(confidence_pct / 100)

    print(f"\n🔍 Processing sample: {sample_id}")
    print(f"{'✅' if is_malware else '🟩'} Malware Detection: {'MALWARE' if is_malware else 'BENIGN'}")
    print(f"🛡️ Confidence: {confidence_pct:.1f}% ({confidence_level})")
