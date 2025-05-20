# app.py (Flask backend)

from flask import Flask, request, jsonify
from flask_cors import CORS # Import CORS
import os
import tempfile
from werkzeug.utils import secure_filename
import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import logging # For better logging

# --- Custom Feature Extraction ---
from extract_features import extract_static_features

app = Flask(__name__)
CORS(app) # Enable CORS for all routes, allowing requests from your Vue dev server

# --- Configuration ---
# Use an absolute path for UPLOAD_FOLDER in production or a more robust relative path
UPLOAD_FOLDER = tempfile.gettempdir() 
ALLOWED_EXTENSIONS = {'exe'}
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models") # Assumes 'models' is in the same dir as app.py

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Load Models and Artifacts (Once at Startup) ---
MODELS_LOADED = False
scaler, rf_model, mse_threshold, expected_feature_names, autoencoder, rf_classes = [None] * 6

try:
    logger.info("Loading machine learning artifacts...")
    logger.info(f"Model directory: {MODEL_DIR}")
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
    mse_threshold = joblib.load(os.path.join(MODEL_DIR, "ae_mse_threshold.pkl"))
    expected_feature_names = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))
    autoencoder = load_model(os.path.join(MODEL_DIR, "autoencoder_model.h5"), compile=False)
    rf_classes = joblib.load(os.path.join(MODEL_DIR, "rf_classes.pkl")) # Load RF classes
    logger.info("✅ Artifacts loaded successfully.")
    MODELS_LOADED = True
except Exception as e:
    logger.critical(f"❌ CRITICAL ERROR: Failed to load one or more model artifacts: {e}", exc_info=True)
    # The application might still run, but the scan endpoint will fail.

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/scan', methods=['POST']) # Changed endpoint to /scan to match Vue's fetch
def scan_exe_file_route():
    if not MODELS_LOADED:
        logger.error("Scan attempt failed: Models not loaded.")
        return jsonify({'status': 'error', 'message': 'Service unavailable: Essential models are not loaded.'}), 503

    # Your Vue code sends the file with the key 'file' in FormData
    if 'file' not in request.files:
        logger.warning("Bad request: 'file' part missing from request.")
        return jsonify({'status': 'error', 'message': 'No file part in the request. Ensure the form field name is "file".'}), 400

    file = request.files['file']

    if file.filename == '':
        logger.warning("Bad request: Empty filename.")
        return jsonify({'status': 'error', 'message': 'No selected file (empty filename)'}), 400

    if not file or not allowed_file(file.filename):
        logger.warning(f"Bad request: File type not allowed for '{file.filename}'.")
        return jsonify({'status': 'error', 'message': f'File type not allowed. Only {ALLOWED_EXTENSIONS} are supported.'}), 400

    filename = secure_filename(file.filename)
    # Create a unique subdirectory within UPLOAD_FOLDER for this request to avoid filename collisions
    request_temp_dir = tempfile.mkdtemp(dir=UPLOAD_FOLDER)
    temp_file_path = os.path.join(request_temp_dir, filename)
    
    try:
        file.save(temp_file_path)
        logger.info(f"File '{filename}' temporarily saved to: {temp_file_path}")

        # --- 1. Extract Features ---
        raw_features_dict = extract_static_features(temp_file_path, expected_feature_names)

        if raw_features_dict is None:
            logger.error(f"Feature extraction returned None for '{filename}'. Possibly corrupted PE.")
            return jsonify({'status': 'error', 'message': 'Failed to extract features (file might be corrupted or not a valid PE).'}), 500

        # --- 2. Prepare DataFrame for Model ---
        try:
            input_df = pd.DataFrame([raw_features_dict])
            # Ensure columns are in the exact order model expects, and only those columns
            input_df = input_df[expected_feature_names] 
        except KeyError as e:
            logger.error(f"KeyError during DataFrame creation for '{filename}': {e}. Mismatch between extracted and expected features.", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Feature mismatch error: A required feature ({str(e)}) was not found after extraction.'}), 500
        except Exception as e:
            logger.error(f"Error creating DataFrame from features for '{filename}': {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Internal error preparing features: {str(e)}'}), 500

        # --- 3. Scale Features ---
        try:
            X_scaled = scaler.transform(input_df)
        except Exception as e:
            logger.error(f"Error during feature scaling for '{filename}': {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Feature scaling error: {str(e)}'}), 500
            
        # --- 4. Make Predictions ---
        ae_is_malware = False
        rf_prediction_label = "Error"
        confidence = 0.0
        final_verdict_label = "Error"
        risk_level = "Undetermined"
        mse = -1.0

        try:
            reconstructed = autoencoder.predict(X_scaled)
            mse = np.mean(np.square(X_scaled - reconstructed), axis=1)[0]
            ae_is_malware = bool(mse > mse_threshold) # Ensure boolean

            rf_prediction_idx = rf_model.predict(X_scaled)[0] # This might be an index if classes are numerical
            # Ensure rf_prediction_label is the actual class name (string)
            # If rf_model.classes_ was saved and loaded, you can map index to label
            if rf_classes is not None and isinstance(rf_prediction_idx, (int, np.integer)):
                 rf_prediction_label = rf_classes[rf_prediction_idx]
            else: # Assume predict directly gives labels
                 rf_prediction_label = str(rf_prediction_idx)


            rf_proba_vector = rf_model.predict_proba(X_scaled)[0]
            confidence = float(np.max(rf_proba_vector)) * 100

            if ae_is_malware:
                final_verdict_label = "MALWARE"
                final_type_label = rf_prediction_label # Use the string label
                if final_type_label == "Benign":
                    final_type_label = "Unknown/Anomaly" # More generic if AE flags but RF says benign
                
                # Determine risk level based on type
                if "Ransomware" in final_type_label: risk_level = "Critical"
                elif "Trojan" in final_type_label: risk_level = "High"
                elif "Spyware" in final_type_label: risk_level = "Medium"
                elif final_type_label == "Unknown/Anomaly": risk_level = "High" # AE flagged it
                else: risk_level = "Medium" # Other RF malware types
            else:
                final_verdict_label = "BENIGN"
                final_type_label = "Benign" # If AE says benign, override RF
                risk_level = "Low"
        except Exception as e:
            logger.error(f"Error during model prediction for '{filename}': {e}", exc_info=True)
            # Keep default error labels for result

        # --- 5. Prepare and Send Response (Matches ScanResultPopup.vue structure) ---
        scan_result_data = {
            "fileName": filename,
            "isMalware": bool(ae_is_malware), # Directly use the AE verdict for overall malware status
            "malwareType": str(final_type_label) if ae_is_malware else "Benign", # Use final_type_label if malware
            "confidenceScore": round(float(confidence), 2) if ae_is_malware else 100.0, # RF confidence if malware, or a default for benign
            # Optional: include scanTime if you still want it
            "scanTime": pd.Timestamp.now().strftime('%Y-%m-%d %I:%M:%S %p'),
            # Optional: for debugging or slightly more info if desired later
            "aeVerdict": "Anomaly" if ae_is_malware else "Normal",
            "rfRawPrediction": str(rf_prediction_label) # RF's own direct prediction
        }

        # if ae_is_malware:
        #     scan_result_data["threatDetails"] = {
        #         "signature": str(final_type_label), # e.g., "Trojan", "Unknown/Anomaly"
        #         "behavior": "Static analysis. Anomalous reconstruction by AE. Classified by RF.", # Generic
        #         "severity": risk_level 
        #     }
        
        logger.info(f"Scan result for '{filename}': {scan_result_data}")
        return jsonify({'status': 'ok', 'result': scan_result_data})

    except Exception as e:
        logger.error(f"Unhandled exception processing file '{filename}': {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'An unexpected server error occurred.'}), 500
    finally:
        # --- 6. Cleanup Temporary File and Directory ---
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logger.info(f"Temporary file {temp_file_path} removed.")
            except Exception as e:
                logger.error(f"Error removing temporary file {temp_file_path}: {e}", exc_info=True)
        if os.path.exists(request_temp_dir): # remove the unique temp directory for this request
            try:
                os.rmdir(request_temp_dir)
                logger.info(f"Temporary directory {request_temp_dir} removed.")
            except Exception as e:
                logger.error(f"Error removing temporary directory {request_temp_dir}: {e}", exc_info=True)

if __name__ == '__main__':
    logger.info(f"Flask app starting. Expected model directory: {MODEL_DIR}")
    if not MODELS_LOADED:
        logger.warning("Flask app started, but one or more ML models FAILED to load. The /scan endpoint will be impaired.")
    # For development: app.run(debug=True). For production: use a proper WSGI server like Gunicorn.
    # Host 0.0.0.0 makes it accessible on your network, not just localhost.
    app.run(host='0.0.0.0', port=5000, debug=True)
