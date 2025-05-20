# backend_app.py (Conceptual Flask Example)
from flask import Flask, request, jsonify
import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import os
import tempfile
# import pefile # For static PE feature extraction

app = Flask(__name__)

# --- Load Models and Artifacts (Ideally once at startup) ---
MODEL_DIR = "models"
try:
    autoencoder = load_model(os.path.join(MODEL_DIR, "autoencoder_model.h5"), compile=False)
    rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    expected_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))
    mse_threshold = joblib.load(os.path.join(MODEL_DIR, "ae_mse_threshold.pkl"))
    rf_classes = joblib.load(os.path.join(MODEL_DIR, "rf_classes.pkl")) # Classes RF was trained on
    print("✅ Models and artifacts loaded successfully.")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    # Handle error appropriately, maybe exit or disable the endpoint
    autoencoder = None # Prevent use if loading failed

# --- Placeholder for Feature Extraction ---
def extract_features_from_exe(exe_file_path, expected_feature_list):
    """
    Placeholder for your actual feature extraction logic.
    This function needs to take an EXE file path and return a Pandas DataFrame
    with a single row, containing features in the order of expected_feature_list.
    """
    print(f"Attempting to extract features from: {exe_file_path}")
    # Example: using pefile for some basic static features
    # This is NOT a complete feature extractor matching your original dataset.
    # You MUST develop this part based on the features your model was trained on.
    
    # Initialize a dictionary to hold features
    features = {col: 0 for col in expected_feature_list} # Default all to 0 or NaN

    # try:
    #     pe = pefile.PE(exe_file_path)
    #     if 'number_of_sections' in features: # Example feature name
    #         features['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
    #     if 'size_of_code' in features: # Example feature name
    #         features['size_of_code'] = pe.OPTIONAL_HEADER.SizeOfCode
    #     # ... extract other PE features and map them to `expected_feature_list` names
    #     # This requires knowing what your `expected_feature_list` columns represent.
    # except Exception as e:
    #     print(f"Error during pefile processing: {e}")
    #     # Return features with defaults, or handle error
    
    # For demonstration, returning dummy data. Replace with actual extraction.
    # This dummy data assumes all expected columns are numerical.
    if not features: # If pefile part is commented out
         print("WARNING: Returning DUMMY features. Implement actual feature extraction.")
         for i, col_name in enumerate(expected_feature_list):
              features[col_name] = np.random.rand() # Dummy value

    feature_df = pd.DataFrame([features])
    feature_df = feature_df[expected_feature_list] # Ensure correct column order
    return feature_df

@app.route('/api/scan-exe', methods=['POST'])
def scan_executable():
    if autoencoder is None: # Check if models loaded
        return jsonify({"error": "Models not loaded, service unavailable"}), 500

    if 'executable' not in request.files:
        return jsonify({"error": "No executable file part"}), 400
    
    file = request.files['executable']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file: # Basic check, add more validation (e.g., file type, size)
        # Securely save the file to a temporary location
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, file.filename)
        
        try:
            file.save(temp_file_path)
            print(f"File saved temporarily to {temp_file_path}")

            # ** 1. Feature Extraction **
            # This is the critical step you need to implement thoroughly.
            # The extracted features must match what your model was trained on.
            extracted_features_df = extract_features_from_exe(temp_file_path, expected_columns)

            if extracted_features_df is None or extracted_features_df.empty:
                return jsonify({"error": "Feature extraction failed"}), 500
            
            # ** 2. Scaling **
            X_scaled = scaler.transform(extracted_features_df)

            # ** 3. Prediction (using logic similar to your predict.py) **
            # AutoEncoder Anomaly Detection
            X_reconstructed = autoencoder.predict(X_scaled)
            reconstruction_error = np.mean(np.square(X_scaled - X_reconstructed), axis=1)[0] # Get single value

            # Random Forest Classification
            rf_probs_sample = rf_model.predict_proba(X_scaled)[0] # Probs for the first (only) sample
            rf_pred_sample = rf_model.predict(X_scaled)[0]      # Prediction for the first sample

            is_anomaly_ae = reconstruction_error > mse_threshold
            predicted_type_rf = rf_pred_sample
            confidence_rf = np.max(rf_probs_sample) * 100
            
            final_verdict_label = ""
            final_type_label = ""
            risk_level = "Low" # Default

            if is_anomaly_ae:
                final_verdict_label = "MALWARE"
                final_type_label = predicted_type_rf
                if final_type_label == "Benign":
                    final_type_label = "Unknown Malware (AE anomaly, RF benign)"
                
                # Determine risk level based on type (example)
                if "Ransomware" in final_type_label: risk_level = "Critical"
                elif "Trojan" in final_type_label: risk_level = "High"
                elif "Spyware" in final_type_label: risk_level = "Medium"
                else: risk_level = "High" # For other AE-flagged anomalies
            else:
                final_verdict_label = "BENIGN"
                final_type_label = "Benign" # Or could be RF's prediction if you want to show it
                risk_level = "Low"

            # Prepare results for ScanResultPopup.vue
            scan_result_data = {
                "fileName": file.filename,
                "scanTime": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                "fileImage": ".EXE", # Placeholder
                "malwareDetected": is_anomaly_ae,
                "riskLevel": risk_level, 
                "aeReconstructionError": float(reconstruction_error),
                "aeThreshold": float(mse_threshold),
                "rfPredictedType": str(predicted_type_rf),
                "rfConfidence": float(confidence_rf),
                "finalVerdict": final_verdict_label,
                "threatDetails": None # Populate if malware detected
            }

            if is_anomaly_ae:
                scan_result_data["threatDetails"] = {
                    "signature": final_type_label, # Or more specific signature if available
                    "behavior": "Anomalous reconstruction by AE. Classified by RF.", # Placeholder
                    "severity": risk_level 
                }
            
            return jsonify(scan_result_data)

        except Exception as e:
            print(f"Error during processing: {e}")
            return jsonify({"error": f"Server processing error: {str(e)}"}), 500
        finally:
            # Clean up: remove temporary file and directory
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
            print(f"Cleaned up temporary file and directory: {temp_dir}")
            
    return jsonify({"error": "Invalid file"}), 400

if __name__ == '__main__':
    # Important: For development only. Use a proper WSGI server (like Gunicorn) for production.
    app.run(debug=True, port=5000) 