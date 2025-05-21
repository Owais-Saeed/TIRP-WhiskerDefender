# app.py (Flask backend)

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
from werkzeug.utils import secure_filename
import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import logging
import datetime 
import random 
import shutil # For more robust directory removal

# --- Custom Feature Extraction (for .exe files) ---
from extract_features import extract_static_features

app = Flask(__name__)
CORS(app)

# --- Configuration ---
UPLOAD_FOLDER = tempfile.gettempdir() 
ALLOWED_EXTENSIONS = {'exe', 'csv'}
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

# --- Logging Setup ---
# Ensure the root logger is configured to see logs from other modules if they use logging.
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # Logger for this specific app.py module

# --- Firebase Initialization (COMMENTED OUT FOR DUMMY DATA) ---
db = None 
logger.info("Running in DUMMY DATA mode. Firestore is disabled.")

# --- Load Models and Artifacts (Once at Startup) ---
MODELS_LOADED = False
scaler, rf_model, mse_threshold, expected_feature_names, autoencoder, rf_classes = [None] * 6

try:
    logger.info(f"Attempting to load machine learning artifacts from: {MODEL_DIR}")
    if not os.path.isdir(MODEL_DIR):
        logger.critical(f"CRITICAL ERROR: Models directory not found at {MODEL_DIR}")
        raise FileNotFoundError(f"Models directory not found: {MODEL_DIR}")

    scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
    rf_model_path = os.path.join(MODEL_DIR, "rf_model.pkl")
    mse_threshold_path = os.path.join(MODEL_DIR, "ae_mse_threshold.pkl")
    expected_feature_names_path = os.path.join(MODEL_DIR, "feature_columns.pkl")
    autoencoder_path = os.path.join(MODEL_DIR, "autoencoder_model.h5")
    rf_classes_path = os.path.join(MODEL_DIR, "rf_classes.pkl")

    required_files = [scaler_path, rf_model_path, mse_threshold_path, expected_feature_names_path, autoencoder_path, rf_classes_path]
    for f_path in required_files:
        if not os.path.exists(f_path):
            logger.critical(f"CRITICAL ERROR: Required model file not found: {f_path}")
            raise FileNotFoundError(f"Required model file not found: {f_path}")

    scaler = joblib.load(scaler_path)
    rf_model = joblib.load(rf_model_path)
    mse_threshold = joblib.load(mse_threshold_path)
    expected_feature_names = joblib.load(expected_feature_names_path)
    autoencoder = load_model(autoencoder_path, compile=False)
    rf_classes = joblib.load(rf_classes_path)
    
    logger.info("✅ All machine learning artifacts loaded successfully.")
    MODELS_LOADED = True
except Exception as e:
    logger.critical(f"❌ CRITICAL ERROR: Failed to load one or more model artifacts: {e}", exc_info=True)


def get_file_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else None

def allowed_file(filename):
    return get_file_extension(filename) in ALLOWED_EXTENSIONS

@app.route('/scan', methods=['POST'])
def scan_file_route():
    if not MODELS_LOADED:
        logger.error("Scan attempt failed: Models not loaded. Service unavailable.")
        return jsonify({'status': 'error', 'message': 'Service unavailable: Essential models are not loaded.'}), 503

    if 'file' not in request.files:
        logger.warning("Bad request: 'file' part missing from request.")
        return jsonify({'status': 'error', 'message': 'No file part in the request. Ensure the form field name is "file".'}), 400

    file = request.files['file']
    if file.filename == '':
        logger.warning("Bad request: Empty filename provided.")
        return jsonify({'status': 'error', 'message': 'No selected file (empty filename)'}), 400

    filename = secure_filename(file.filename)
    file_ext = get_file_extension(filename)

    if not file_ext or not allowed_file(filename):
        logger.warning(f"Bad request: File type '{file_ext}' not allowed for '{filename}'.")
        return jsonify({'status': 'error', 'message': f'File type not allowed. Only {", ".join(ALLOWED_EXTENSIONS)} are supported.'}), 400

    request_temp_dir = None 
    temp_file_path = None   

    try:
        request_temp_dir = tempfile.mkdtemp(dir=UPLOAD_FOLDER)
        temp_file_path = os.path.join(request_temp_dir, filename)
        file.save(temp_file_path)
        logger.info(f"File '{filename}' (type: {file_ext}) temporarily saved to: {temp_file_path}")

        input_df = None
        if file_ext == 'exe':
            logger.info(f"Processing .exe file: {filename}")
            raw_features_dict = extract_static_features(temp_file_path, expected_feature_names)
            logger.debug(f"Raw features extracted from EXE '{filename}': {raw_features_dict}") # ADDED LOG
            if raw_features_dict is None: 
                logger.error(f"Static feature extraction returned None for .exe: '{filename}'.")
                return jsonify({'status': 'error', 'message': 'Failed to extract features from .exe (file might be corrupted or not a valid PE).'}), 500
            input_df = pd.DataFrame([raw_features_dict])
        elif file_ext == 'csv':
            logger.info(f"Processing .csv file: {filename}")
            try:
                df_from_csv = pd.read_csv(temp_file_path)
                if df_from_csv.empty:
                    logger.error(f"Uploaded CSV '{filename}' is empty.")
                    return jsonify({'status': 'error', 'message': 'Uploaded CSV file is empty.'}), 400
                df_row_to_process = df_from_csv.head(1)
                if list(df_row_to_process.columns) == expected_feature_names:
                    logger.info(f"CSV '{filename}' matches expected feature format directly.")
                    input_df = df_row_to_process
                elif len(df_row_to_process.columns) == len(expected_feature_names) + 2:
                    logger.info(f"CSV '{filename}' appears to be in original training data format. Extracting middle columns for features.")
                    feature_values_from_original_format = df_row_to_process.iloc[:, 1:-1]
                    if len(feature_values_from_original_format.columns) == len(expected_feature_names):
                        feature_values_from_original_format.columns = expected_feature_names
                        input_df = feature_values_from_original_format
                    else:
                        logger.error(f"CSV '{filename}' (original format) did not yield correct number of feature columns.")
                        return jsonify({'status': 'error', 'message': 'CSV format (original type) error: Incorrect number of features after processing.'}), 400
                else:
                    logger.error(f"CSV '{filename}' column structure does not match expected formats. Columns found: {list(df_row_to_process.columns)}")
                    return jsonify({'status': 'error', 'message': 'CSV column structure mismatch.'}), 400
            except Exception as e:
                logger.error(f"Error reading or processing CSV '{filename}': {e}", exc_info=True)
                return jsonify({'status': 'error', 'message': f'Could not read or process CSV file: {str(e)}'}), 400
        
        if input_df is None:
             logger.critical(f"Internal error: input_df not populated for {filename}.")
             return jsonify({'status': 'error', 'message': 'Internal server error processing file input.'}), 500
        
        logger.debug(f"Input DataFrame for '{filename}' before column alignment (head): \n{input_df.head()}") # ADDED LOG

        try:
            missing_input_cols = [col for col in expected_feature_names if col not in input_df.columns]
            if missing_input_cols:
                logger.error(f"Input DataFrame for '{filename}' is missing expected columns: {missing_input_cols}")
                return jsonify({'status': 'error', 'message': f'Processed input is missing required feature columns: {", ".join(missing_input_cols)}.'}), 400
            input_df = input_df[expected_feature_names] 
            logger.debug(f"Input DataFrame for '{filename}' after column alignment (dtypes): \n{input_df.dtypes}") # ADDED LOG
            logger.debug(f"Input DataFrame for '{filename}' NaN check: {input_df.isnull().sum().sum()} NaNs") # ADDED LOG

        except KeyError as e:
            logger.error(f"KeyError during DataFrame column alignment for '{filename}': {e}.", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Feature mismatch error: An expected feature ({str(e)}) was not found.'}), 500
        except Exception as e:
            logger.error(f"Error aligning DataFrame columns for '{filename}': {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Internal error preparing features for model: {str(e)}'}), 500

        try:
            X_scaled = scaler.transform(input_df)
            logger.debug(f"X_scaled for '{filename}' (sample): {X_scaled[0, :10] if X_scaled.shape[1] > 10 else X_scaled}") # ADDED LOG (sample)
        except Exception as e:
            logger.error(f"Error during feature scaling for '{filename}': {e}", exc_info=True)
            logger.error(f"Data causing scaling error (first 5 rows, all columns): \n{input_df.head()}") # Log data before scaling
            return jsonify({'status': 'error', 'message': f'Feature scaling error: {str(e)}'}), 500
            
        ae_is_malware = False
        rf_prediction_label_from_model = "Error"
        confidence_to_display = 0.0
        final_type_label = "Error" 
        risk_level = "Undetermined"
        mse = -1.0

        try:
            reconstructed = autoencoder.predict(X_scaled)
            mse = np.mean(np.square(X_scaled - reconstructed), axis=1)[0]
            ae_is_malware = bool(mse > mse_threshold)
            logger.info(f"AE for '{filename}': MSE={mse:.6f}, Threshold={mse_threshold:.6f}, AE_is_Malware={ae_is_malware}") # ADDED LOG

            rf_pred_raw_idx_or_label = rf_model.predict(X_scaled)[0]
            rf_proba_vector = rf_model.predict_proba(X_scaled)[0]
            logger.debug(f"RF for '{filename}': Raw prediction={rf_pred_raw_idx_or_label}, Proba vector (first 5): {rf_proba_vector[:5]}") # ADDED LOG

            if rf_classes is not None:
                try:
                    if isinstance(rf_pred_raw_idx_or_label, (int, np.integer)) and 0 <= rf_pred_raw_idx_or_label < len(rf_classes):
                        rf_prediction_label_from_model = rf_classes[rf_pred_raw_idx_or_label]
                        rf_top_class_confidence = float(rf_proba_vector[rf_pred_raw_idx_or_label]) * 100
                    else: 
                        rf_prediction_label_from_model = str(rf_pred_raw_idx_or_label)
                        class_idx_for_confidence = list(rf_classes).index(rf_prediction_label_from_model)
                        rf_top_class_confidence = float(rf_proba_vector[class_idx_for_confidence]) * 100
                except (IndexError, ValueError) as map_err:
                    logger.warning(f"Could not reliably map RF prediction '{rf_pred_raw_idx_or_label}' to class name or get its direct probability: {map_err}. Using max probability as fallback.")
                    rf_prediction_label_from_model = str(rf_pred_raw_idx_or_label) 
                    rf_top_class_confidence = float(np.max(rf_proba_vector)) * 100
            else: 
                rf_prediction_label_from_model = str(rf_pred_raw_idx_or_label)
                rf_top_class_confidence = float(np.max(rf_proba_vector)) * 100
            
            logger.info(f"RF for '{filename}': Predicted Label='{rf_prediction_label_from_model}', Top Confidence={rf_top_class_confidence:.2f}%") # ADDED LOG

            if ae_is_malware: 
                final_type_label = rf_prediction_label_from_model 
                confidence_to_display = rf_top_class_confidence 
                # if final_type_label == "Benign":
                #     final_type_label = "Unknown/Anomaly"
                
                if "Ransomware" in final_type_label: risk_level = "Critical"
                elif "Trojan" in final_type_label: risk_level = "High"
                elif "Spyware" in final_type_label: risk_level = "Medium"
                # elif final_type_label == "Unknown/Anomaly": risk_level = "High"
                else: risk_level = "Medium" 
            else: 
                final_type_label = "Benign" 
                risk_level = "Low"
                if rf_classes is not None and "Benign" in rf_classes:
                    try:
                        benign_class_idx = list(rf_classes).index("Benign")
                        confidence_to_display = float(rf_proba_vector[benign_class_idx]) * 100
                    except (ValueError, IndexError):
                        confidence_to_display = 99.0 
                else: 
                    confidence_to_display = 99.0
            logger.info(f"Hybrid Verdict for '{filename}': Final Type='{final_type_label}', Confidence Displayed={confidence_to_display:.2f}%, Risk='{risk_level}'") # ADDED LOG
        except Exception as e:
            logger.error(f"Error during model prediction for '{filename}': {e}", exc_info=True)

        current_timestamp_obj = datetime.datetime.utcnow()
        scan_result_data = {
            "fileName": filename,
            "scanTime": current_timestamp_obj.strftime('%Y-%m-%d %I:%M:%S %p UTC'),
            "isMalware": ae_is_malware,
            "malwareType": final_type_label,
            "confidenceScore": round(confidence_to_display, 2),
            "riskLevel": risk_level,
            "aeVerdictOnExe": "Anomaly" if ae_is_malware else "Normal",
            "rfRawPrediction": rf_prediction_label_from_model,
            "aeReconstructionError": round(float(mse), 6),
            "aeThreshold": round(float(mse_threshold), 6)
        }
        
        logger.info(f"Dummy mode: Scan result for '{filename}' not saved to DB (Firestore disabled).")
        logger.info(f"Final scan result for '{filename}': {scan_result_data}")
        return jsonify(scan_result_data)

    except Exception as e:
        logger.error(f"Unhandled exception processing file '{filename}': {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'An unexpected server error occurred during scan.'}), 500
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logger.debug(f"Temporary file {temp_file_path} removed.")
            except Exception as e_rem_file:
                logger.error(f"Error removing temporary file {temp_file_path}: {e_rem_file}", exc_info=True)
        
        if request_temp_dir and os.path.exists(request_temp_dir):
            try:
                shutil.rmtree(request_temp_dir)
                logger.debug(f"Temporary directory {request_temp_dir} and its contents removed.")
            except Exception as e_rem_dir:
                logger.error(f"Error removing temporary directory {request_temp_dir}: {e_rem_dir}", exc_info=True)

# --- Admin API Endpoint (Serves DUMMY DATA) ---
@app.route('/api/admin/top-scans', methods=['GET'])
def get_top_scans():
    logger.info("Admin request for top scans received (serving dummy data).")
    if not MODELS_LOADED: 
        return jsonify({"error": "Service not fully available (models not loaded)"}), 503
    
    dummy_scans = []
    malware_types = ["Trojan", "Ransomware", "Spyware"]
    risk_levels = ["High", "Critical", "Medium"]
    
    for i in range(random.randint(5, 20)): 
        days_ago = random.randint(0, 6)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        
        scan_time = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        
        dummy_scan = {
            "id": f"dummy_scan_{i+1}",
            "timestamp": scan_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "filename": f"malware_sample_{i+1}.exe",
            "isMalware": True, 
            "malwareType": random.choice(malware_types),
            "confidenceScore": round(random.uniform(70.0, 99.9), 2),
            "riskLevel": random.choice(risk_levels)
        }
        dummy_scans.append(dummy_scan)
        
    dummy_scans_sorted = sorted(dummy_scans, key=lambda x: x.get('confidenceScore', 0), reverse=True)
    return jsonify(dummy_scans_sorted)

if __name__ == '__main__':
    logger.info(f"Flask app starting. Current working directory: {os.getcwd()}")
    logger.info(f"Expected model directory (resolved): {os.path.abspath(MODEL_DIR)}")
    if not MODELS_LOADED:
        logger.warning("Flask app is starting, but one or more ML models FAILED to load. The /scan endpoint will be impaired.")
    app.run(host='0.0.0.0', port=5000, debug=True)
