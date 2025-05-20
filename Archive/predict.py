import pandas as pd
import joblib
import numpy as np # Added for np.max and np.zeros if needed

# Load model and scaler
print("Loading model, scaler, and model classes...")
try:
    feature_columns_train = joblib.load("feature_columns.pkl")
    print("✅ Loaded feature columns from training.")
except FileNotFoundError:
    print("Error: feature_columns.pkl not found. Ensure full_training.py was run successfully.")
    exit()
except Exception as e:
    print(f"Error loading feature columns: {e}")
    exit()

# === Load data for prediction ===
try:
    df_full = pd.read_csv("Obfuscated-MalMem2022.csv")
    print(f"Loaded prediction data shape: {df_full.shape}")
except FileNotFoundError:
    print("Error: Obfuscated-MalMem2022.csv not found for prediction input.")
    exit()
except Exception as e:
    print(f"Error reading Obfuscated-MalMem2022.csv: {e}")
    exit()


# === Apply the same preprocessing as in training ===
# It's crucial that the preprocessing steps are identical.

# 1. Store original 'Category' and 'Class' if they exist, for reference, then drop
#    The 'Category' column from input data is not used for features, but can be used for comparing actual vs predicted.
original_category_raw = None
if 'Category' in df_full.columns:
    original_category_raw = df_full['Category'].copy() 
    # We don't need to clean original_category_raw here for prediction features,
    # but if you want to compare with cleaned labels, you'd apply the same cleaning function.
    df_predict_features = df_full.drop(columns=["Category"])
else:
    df_predict_features = df_full.copy()

if 'Class' in df_predict_features.columns:
    df_predict_features = df_predict_features.drop(columns=["Class"])


# 2. Drop constant columns
#    Ideally, load the list of constant_cols from training.
#    joblib.dump(constant_cols, "constant_cols.pkl") in training
#    constant_cols_to_drop = joblib.load("constant_cols.pkl") in prediction
#    For this example, re-identifying on the loaded data (less robust if data differs significantly):
temp_df_for_constant_check = df_predict_features.copy() # Use a copy to avoid modifying df_predict_features yet
constant_cols_predict = temp_df_for_constant_check.columns[temp_df_for_constant_check.nunique() == 1].tolist()
if constant_cols_predict:
    df_predict_features = df_predict_features.drop(columns=constant_cols_predict, errors='ignore')
    print(f"Dropped constant columns for prediction: {constant_cols_predict}")


# 3. Drop leaky features (must be the same list as in training)
leaky_features = [
    'pslist.nppid', 'handles.ndirectory', 'pslist.avg_handlers',
    'ldrmodules.not_in_mem_avg', 'ldrmodules.not_in_load_avg',
    'handles.nhandles', 'handles.ndesktop', 'svcscan.nservices',
    'svcscan.nactive', 'handles.nkey', 'svcscan.shared_process_services',
    'ldrmodules.not_in_init', 'svcscan.process_services',
    'handles.nsemaphore', 'handles.ntimer', 'ldrmodules.not_in_mem',
    'ldrmodules.not_in_load', 'pslist.avg_threads', 'handles.nsection',
    'dlllist.ndlls', 'handles.nmutant', 'handles.nthread', 'handles.nevent',
    'dlllist.avg_dlls_per_proc'
]
columns_to_drop_predict = [col for col in leaky_features if col in df_predict_features.columns]
if columns_to_drop_predict:
    df_predict_features = df_predict_features.drop(columns=columns_to_drop_predict, errors='ignore')
    print(f"Dropped leaky features for prediction: {columns_to_drop_predict}")


# Select a sample (or use the whole df_predict_features if you want to predict on all)
if df_predict_features.empty:
    print("Error: No data left for prediction after preprocessing.")
    exit()

# Take a sample from df_predict_features (which has Category and Class columns removed)
sample_features = df_predict_features.sample(n=1, random_state=42) 
sample_index = sample_features.index # Keep track of the original index for the sample

print(f"\nSample features selected for prediction (shape {sample_features.shape}):")
print(sample_features)

# Save the input sample that will be fed to the model
sample_features.to_csv("sample_input_for_prediction.csv", index=False)
print("Saved the raw sample features to sample_input_for_prediction.csv")


# 4. Scale the features
#    Ensure column order matches training. Best practice: save X_train.columns during training and reorder here.
#    feature_columns_train = joblib.load("feature_columns.pkl")
#    sample_features = sample_features[feature_columns_train]
try:
    if hasattr(scaler, 'feature_names_in_'):
        feature_columns_from_scaler = scaler.feature_names_in_
        sample_features_reordered = sample_features[feature_columns_from_scaler]
        X_scaled = scaler.transform(sample_features_reordered)
        print("Scaled sample using feature names from scaler.")
    else:
        print("Warning: Scaler does not have 'feature_names_in_'. Assuming column order is correct. For robust deployment, save and load column order from training.")
        X_scaled = scaler.transform(sample_features) # Assumes sample_features has correct order

except ValueError as e:
    print(f"Error during scaling: {e}")
    print("This often happens if the columns in the prediction data do not match (name, order, or count) the data used to fit the scaler.")
    print(f"Columns in current sample: {sample_features.columns.tolist()}")
    if hasattr(scaler, 'feature_names_in_'):
         print(f"Columns expected by scaler: {list(scaler.feature_names_in_)}")
    exit()
except Exception as e:
    print(f"An unexpected error occurred during scaling: {e}")
    exit()


# Predict
print("\nMaking predictions...")
predictions = model.predict(X_scaled)
try:
    probs = model.predict_proba(X_scaled)
except AttributeError: 
    probs = np.zeros((len(predictions), len(model_classes))) 
    print("Warning: model.predict_proba() not available. Confidence scores will be placeholder.")


# Confidence helper
def confidence_label(score_percent):
    score = score_percent / 100
    if score >= 0.9:
        return "High Confidence"
    elif score >= 0.7:
        return "Medium Confidence"
    else:
        return "Low Confidence"

# Function to clean category labels (same as in training) - for comparing actual vs predicted
def clean_malware_category_for_comparison(category_str):
    if pd.isna(category_str): return "N/A"
    category_str = str(category_str).lower()
    if category_str.startswith("ransomware"): return "Ransomware"
    elif category_str.startswith("trojan"): return "Trojan"
    elif category_str.startswith("spyware"): return "Spyware"
    # elif category_str.startswith("adware"): return "Adware"
    # elif category_str.startswith("downloader"): return "Downloader"
    else: return "Other"


# Show result
print("\n=== Prediction Results ===")
for i, (pred_label, prob_vector) in enumerate(zip(predictions, probs)):
    actual_raw_label = "N/A"
    actual_cleaned_label = "N/A"

    current_sample_original_index = sample_index[i]
    if original_category_raw is not None and not original_category_raw.empty:
        if current_sample_original_index in original_category_raw.index:
            actual_raw_label = original_category_raw.loc[current_sample_original_index]
            actual_cleaned_label = clean_malware_category_for_comparison(actual_raw_label)
        
    print(f"\n🔍 Sample (Original Index: {current_sample_original_index})")
    if actual_raw_label != "N/A":
        print(f"   Actual Raw Label (from input file): {actual_raw_label}")
        print(f"   Actual Cleaned Label (expected type): {actual_cleaned_label}")
    print(f"🧬 Predicted Class: {pred_label}")

    if probs.any() and hasattr(model, 'predict_proba'): 
        confidence_pct = np.max(prob_vector) * 100
        level = confidence_label(confidence_pct)
        print(f"🛡️ Confidence: {confidence_pct:.2f}% ({level})")
        
        print("   Class Probabilities:")
        for class_idx, class_prob in enumerate(prob_vector):
            class_name = model_classes[class_idx] # Use loaded model_classes
            print(f"     - {class_name}: {class_prob*100:.2f}%")
    else:
        print("🛡️ Confidence: Not available or predict_proba failed.")

