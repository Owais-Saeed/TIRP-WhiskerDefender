# predict.py

import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
# from sklearn.ensemble import RandomForestClassifier # Not needed directly if loading joblib
# from sklearn.preprocessing import StandardScaler # Not needed directly if loading joblib
import joblib
import os

# === Load Artifacts ===
print("🔍 Loading models, scaler, and thresholds...")
MODEL_DIR = "models"
try:
    autoencoder = load_model(os.path.join(MODEL_DIR, "autoencoder_model.h5"), compile=False) # compile=False speeds up loading if not retraining
    rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    expected_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))
    mse_threshold = joblib.load(os.path.join(MODEL_DIR, "ae_mse_threshold.pkl"))
    # rf_classes = joblib.load(os.path.join(MODEL_DIR, "rf_classes.pkl")) # For verifying RF output classes if needed
    print("✅ Models, scaler, feature columns, and AE threshold loaded successfully.")
except FileNotFoundError as e:
    print(f"❌ Error loading artifacts: {e}. Please ensure 'hybrid_training.py' was run successfully and all files are in the '{MODEL_DIR}' directory.")
    exit()
except Exception as e:
    print(f"❌ An unexpected error occurred while loading artifacts: {e}")
    exit()


# === Load and Preprocess Input Sample ===
# This script expects a CSV file named "sample_input_for_prediction.csv" in the same directory
# This CSV should contain ONLY THE FEATURES, with column names matching those used during training.
# It should NOT contain target labels like 'Class' or 'Category'.
INPUT_CSV_PATH = "Ransomeware.csv" 
print(f"📄 Loading input data from '{INPUT_CSV_PATH}'...")
if not os.path.exists(INPUT_CSV_PATH):
    print(f"❌ Input file not found: {INPUT_CSV_PATH}")
    print("Please create this file with one or more samples (rows) and feature columns matching the training data.")
    # Example: Create a dummy sample_input_for_prediction.csv if it doesn't exist
    if expected_columns:
        dummy_data = {col: [np.random.rand()] for col in expected_columns}
        pd.DataFrame(dummy_data).to_csv(INPUT_CSV_PATH, index=False)
        print(f"Created a dummy '{INPUT_CSV_PATH}' with random data for demonstration.")
    else:
        exit()

try:
    input_df = pd.read_csv(INPUT_CSV_PATH)
    print(f"Loaded {input_df.shape[0]} sample(s) with {input_df.shape[1]} columns.")
except Exception as e:
    print(f"❌ Error reading input CSV '{INPUT_CSV_PATH}': {e}")
    exit()

# Validate and reorder columns to match training
print("Validating and aligning feature columns...")
try:
    # Check for missing columns
    missing_cols = [col for col in expected_columns if col not in input_df.columns]
    if missing_cols:
        print(f"❌ Missing expected columns in '{INPUT_CSV_PATH}': {missing_cols}")
        print(f"   Make sure the input CSV contains all of these {len(expected_columns)} feature columns.")
        exit()
    
    # Select and reorder columns
    input_df_reordered = input_df[expected_columns]
except Exception as e:
    print(f"❌ Error aligning columns: {e}")
    exit()

# Scale features
print("Scaling features...")
try:
    X_scaled = scaler.transform(input_df_reordered)
except ValueError as e:
    print(f"❌ Error during scaling: {e}")
    print("   This can happen if the input data has a different number of features than expected by the scaler,")
    print(f"   or if data types are incompatible. Expected {len(expected_columns)} features.")
    exit()


# === AutoEncoder Anomaly Detection ===
print("🧠 Running AutoEncoder for anomaly detection...")
X_reconstructed = autoencoder.predict(X_scaled)
reconstruction_error = np.mean(np.square(X_scaled - X_reconstructed), axis=1)

# === Random Forest Classification ===
print("🌲 Running Random Forest for type classification...")
rf_probs = rf_model.predict_proba(X_scaled)
rf_preds = rf_model.predict(X_scaled) # These are the malware types or "Benign"

# === Interpret and Display Results ===
print("\n--- Prediction Results ---")
for i in range(len(X_scaled)):
    is_anomaly_ae = reconstruction_error[i] > mse_threshold
    predicted_type_rf = rf_preds[i]
    confidence_rf = np.max(rf_probs[i]) * 100

    print(f"\n🔎 Sample {i+1} (from '{INPUT_CSV_PATH}')")
    print(f"  AE Reconstruction Error: {reconstruction_error[i]:.6f} (Threshold: {mse_threshold:.6f})")
    print(f"  AE Verdict: {'MALWARE (Anomaly)' if is_anomaly_ae else 'BENIGN'}")
    print(f"  RF Predicted Type: {predicted_type_rf} (Confidence: {confidence_rf:.2f}%)")

    # Final Hybrid Verdict
    if is_anomaly_ae:
        # If AE detects an anomaly, the final verdict is MALWARE, and its type is from RF.
        # Note: RF might predict "Benign" even if AE flags it. This is a point for refinement.
        # If RF predicts "Benign" for an AE-flagged anomaly, it might indicate an unknown malware type
        # or a misclassification by RF. For now, we trust RF's type if AE flags.
        final_verdict = "MALWARE"
        final_type = predicted_type_rf 
        if final_type == "Benign" : # If AE says malware but RF says benign
            final_type = "Unknown Malware (AE anomaly, RF benign)" # Or handle as per your strategy
        print(f"🔴 Hybrid Final Verdict: {final_verdict}")
        print(f"   → Predicted Type: {final_type}")
    else:
        # If AE does not detect an anomaly, the final verdict is BENIGN.
        final_verdict = "BENIGN"
        print(f"🟢 Hybrid Final Verdict: {final_verdict}")

print("\nPrediction process complete.")
