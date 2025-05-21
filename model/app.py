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
import datetime # For timestamp and date calculations
import random # For dummy data generation

# --- Firebase Firestore Integration (COMMENTED OUT FOR DUMMY DATA) ---
# from firebase_admin import credentials, firestore, initialize_app as initialize_firebase_app, get_app as get_firebase_app
# from google.cloud.firestore_v1.base_query import FieldFilter

# --- Custom Feature Extraction (for .exe files) ---
from extract_features import extract_static_features

app = Flask(__name__)
CORS(app)

# --- Configuration ---
UPLOAD_FOLDER = tempfile.gettempdir() 
ALLOWED_EXTENSIONS = {'exe', 'csv'}
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Firebase Initialization (COMMENTED OUT FOR DUMMY DATA) ---
db = None # No database client for dummy data mode
# app_id_str = 'dummy-app-id-local' # Define a dummy app_id if any logic still references it
# try:
#     app_id_str = os.environ.get('__APP_ID', 'default-flask-app-id')
#     try:
#         firebase_app = get_firebase_app()
#         logger.info("Firebase app already initialized.")
#     except ValueError:
#         if os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'):
#              initialize_firebase_app()
#              logger.info("Firebase app initialized with application default credentials.")
#              firebase_app = get_firebase_app() # Get the app instance
#         else:
#             try:
#                 initialize_firebase_app() 
#                 logger.info("Firebase app initialized (basic).")
#                 firebase_app = get_firebase_app() 
#             except Exception as fb_init_e:
#                 logger.warning(f"Could not initialize Firebase Admin SDK (basic init failed: {fb_init_e}). Firestore features will be disabled.")
#                 firebase_app = None
#     if firebase_app:
#         db = firestore.client()
#         logger.info("Firestore client obtained.")
#     else:
#         db = None
#         logger.warning("Firestore client NOT obtained. Scan history will not be saved.")
# except Exception as e:
#     logger.error(f"Error during Firebase initialization: {e}", exc_info=True)
#     db = None
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

    # ... (rest of your file upload and initial validation logic from previous app.py) ...
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

    request_temp_dir = tempfile.mkdtemp(dir=UPLOAD_FOLDER)
    temp_file_path = os.path.join(request_temp_dir, filename)
    
    input_df = None

    try:
        file.save(temp_file_path)
        logger.info(f"File '{filename}' (type: {file_ext}) temporarily saved to: {temp_file_path}")

        # --- 1. Feature Extraction or Loading ---
        # ... (Your existing logic for handling .exe and .csv files to populate input_df) ...
        if file_ext == 'exe':
            logger.info(f"Processing .exe file: {filename}")
            raw_features_dict = extract_static_features(temp_file_path, expected_feature_names)
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
                    logger.error(f"CSV '{filename}' column structure does not match expected formats.")
                    return jsonify({'status': 'error', 'message': 'CSV column structure mismatch.'}), 400
            except Exception as e:
                logger.error(f"Error reading or processing CSV '{filename}': {e}", exc_info=True)
                return jsonify({'status': 'error', 'message': f'Could not read or process CSV file: {str(e)}'}), 400
        
        if input_df is None:
             logger.critical(f"Internal error: input_df not populated for {filename}.")
             return jsonify({'status': 'error', 'message': 'Internal server error processing file input.'}), 500

        # --- 2. Prepare DataFrame for Model ---
        # ... (Your existing logic for validating and ordering input_df columns) ...
        try:
            missing_input_cols = [col for col in expected_feature_names if col not in input_df.columns]
            if missing_input_cols:
                logger.error(f"Input DataFrame for '{filename}' is missing expected columns: {missing_input_cols}")
                return jsonify({'status': 'error', 'message': f'Processed input is missing required feature columns: {", ".join(missing_input_cols)}.'}), 400
            input_df = input_df[expected_feature_names] 
        except KeyError as e:
            logger.error(f"KeyError during DataFrame column alignment for '{filename}': {e}.", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Feature mismatch error: An expected feature ({str(e)}) was not found.'}), 500
        except Exception as e:
            logger.error(f"Error aligning DataFrame columns for '{filename}': {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Internal error preparing features for model: {str(e)}'}), 500

        # --- 3. Scale Features ---
        # ... (Your existing scaling logic) ...
        try:
            X_scaled = scaler.transform(input_df)
        except Exception as e:
            logger.error(f"Error during feature scaling for '{filename}': {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Feature scaling error: {str(e)}'}), 500
            
        # --- 4. Make Predictions ---
        # ... (Your existing prediction logic to determine ae_is_malware, final_type_label, confidence_to_display, risk_level, mse) ...
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

            rf_pred_raw_idx_or_label = rf_model.predict(X_scaled)[0]
            rf_proba_vector = rf_model.predict_proba(X_scaled)[0]
            
            if rf_classes is not None:
                try:
                    if isinstance(rf_pred_raw_idx_or_label, (int, np.integer)) and 0 <= rf_pred_raw_idx_or_label < len(rf_classes):
                        rf_prediction_label_from_model = rf_classes[rf_pred_raw_idx_or_label]
                        rf_top_class_confidence = float(rf_proba_vector[rf_pred_raw_idx_or_label]) * 100
                    else: 
                        rf_prediction_label_from_model = str(rf_pred_raw_idx_or_label)
                        class_idx_for_confidence = list(rf_classes).index(rf_prediction_label_from_model)
                        rf_top_class_confidence = float(rf_proba_vector[class_idx_for_confidence]) * 100
                except (IndexError, ValueError):
                    logger.warning(f"Could not reliably map RF prediction '{rf_pred_raw_idx_or_label}' to class name or get its direct probability. Using max probability as fallback.")
                    rf_prediction_label_from_model = str(rf_pred_raw_idx_or_label) 
                    rf_top_class_confidence = float(np.max(rf_proba_vector)) * 100
            else: 
                rf_prediction_label_from_model = str(rf_pred_raw_idx_or_label)
                rf_top_class_confidence = float(np.max(rf_proba_vector)) * 100

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
        except Exception as e:
            logger.error(f"Error during model prediction for '{filename}': {e}", exc_info=True)

        # --- 5. Prepare Scan Result Data ---
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
        
        # --- 6. Save to Firestore (COMMENTED OUT FOR DUMMY DATA) ---
        # if db:
        #     try:
        #         current_app_id = app_id_str if 'app_id_str' in globals() and app_id_str else 'unknown_app'
        #         scan_log_data_for_db = {
        #             "filename": filename,
        #             "timestamp": current_timestamp_obj, # Firestore Timestamp object
        #             "isMalware": ae_is_malware,
        #             "malwareType": final_type_label,
        #             "confidenceScore": round(confidence_to_display, 2),
        #             "riskLevel": risk_level,
        #             "fileExtension": file_ext
        #         }
        #         scan_history_ref = db.collection('scan_history_public') 
        #         doc_ref = scan_history_ref.add(scan_log_data_for_db)
        #         logger.info(f"Scan result for '{filename}' would be saved to Firestore with ID: {doc_ref[1].id}")
        #     except Exception as e_fs:
        #         logger.error(f"Error saving scan result to Firestore for '{filename}': {e_fs}", exc_info=True)
        # else:
        #     logger.info(f"Dummy mode: Scan result for '{filename}' not saved to DB.")
        logger.info(f"Dummy mode: Scan result for '{filename}' not saved to DB (Firestore disabled).")


        logger.info(f"Final scan result for '{filename}': {scan_result_data}")
        return jsonify(scan_result_data)

    except Exception as e:
        logger.error(f"Unhandled exception processing file '{filename}': {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'An unexpected server error occurred during scan.'}), 500
    finally:
        # --- Cleanup Temporary File and Directory ---
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logger.debug(f"Temporary file {temp_file_path} removed.")
            except Exception as e_rem_file:
                logger.error(f"Error removing temporary file {temp_file_path}: {e_rem_file}", exc_info=True)
        if 'request_temp_dir' in locals() and os.path.exists(request_temp_dir):
            try:
                os.rmdir(request_temp_dir)
                logger.debug(f"Temporary directory {request_temp_dir} removed.")
            except Exception as e_rem_dir:
                logger.error(f"Error removing temporary directory {request_temp_dir}: {e_rem_dir}", exc_info=True)

# --- New Admin API Endpoint (Serves DUMMY DATA) ---
@app.route('/api/admin/top-scans', methods=['GET'])
def get_top_scans():
    logger.info("Admin request for top scans received (serving dummy data).")
    if not MODELS_LOADED: 
        return jsonify({"error": "Service not fully available (models not loaded)"}), 503
    
    # --- DUMMY DATA GENERATION ---
    dummy_scans = []
    malware_types = ["Trojan", "Ransomware", "Spyware"]
    risk_levels = ["High", "Critical", "Medium"]
    
    for i in range(random.randint(5, 20)): # Generate a random number of dummy scans
        days_ago = random.randint(0, 6)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        
        scan_time = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        
        dummy_scan = {
            "id": f"dummy_scan_{i+1}",
            "timestamp": scan_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "filename": f"malware_sample_{i+1}.exe",
            "isMalware": True, # All dummy scans are malware for this example
            "malwareType": random.choice(malware_types),
            "confidenceScore": round(random.uniform(70.0, 99.9), 2),
            "riskLevel": random.choice(risk_levels)
        }
        dummy_scans.append(dummy_scan)
        
    # Sort dummy scans by confidence score (descending)
    dummy_scans_sorted = sorted(dummy_scans, key=lambda x: x.get('confidenceScore', 0), reverse=True)
    
    return jsonify(dummy_scans_sorted)

    # --- ORIGINAL FIRESTORE LOGIC (COMMENTED OUT) ---
    # if not db:
    #     return jsonify({"error": "Database service not available (dummy mode)"}), 503
    # try:
    #     seven_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    #     query_ref = db.collection('scan_history_public')
    #     query = query_ref.where(filter=FieldFilter("isMalware", "==", True)) \
    #                      .where(filter=FieldFilter("timestamp", ">=", seven_days_ago)) \
    #                      .order_by("timestamp", direction=firestore.Query.DESCENDING) 
    #     results = query.limit(50).stream()
    #     top_scans = []
    #     for doc in results:
    #         scan_data = doc.to_dict()
    #         scan_data['id'] = doc.id
    #         if isinstance(scan_data.get('timestamp'), datetime.datetime):
    #             scan_data['timestamp'] = scan_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')
    #         top_scans.append(scan_data)
    #     top_scans_sorted = sorted(top_scans, key=lambda x: x.get('confidenceScore', 0), reverse=True)
    #     return jsonify(top_scans_sorted[:20])
    # except Exception as e:
    #     logger.error(f"Error fetching top scans: {e}", exc_info=True)
    #     return jsonify({"error": "Failed to retrieve top scans", "details": str(e)}), 500


if __name__ == '__main__':
    logger.info(f"Flask app starting. Current working directory: {os.getcwd()}")
    logger.info(f"Expected model directory (resolved): {os.path.abspath(MODEL_DIR)}")
    if not MODELS_LOADED:
        logger.warning("Flask app is starting, but one or more ML models FAILED to load. The /scan endpoint will be impaired.")
    app.run(host='0.0.0.0', port=5000, debug=True)
