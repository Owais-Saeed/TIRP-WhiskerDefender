# hybrid_training.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os

# === Configuration ===
# Define the percentile for AE threshold (e.g., 95th percentile of benign reconstruction errors)
AE_THRESHOLD_PERCENTILE = 95 
# Define the main malware categories you are interested in
MALWARE_CATEGORIES = ['Ransomware', 'Trojan', 'Spyware']


# === Step 1: Load and preprocess dataset ===
print("Loading dataset...")
df = pd.read_csv("Obfuscated-MalMem2022.csv")
print(f"Initial dataset shape: {df.shape}")

# Clean missing data - consider more sophisticated imputation if appropriate
df = df.dropna()
print(f"Shape after dropping NaNs: {df.shape}")

# Create binary label for AE
if 'Class' not in df.columns:
    raise ValueError("Column 'Class' not found in CSV. This column is required for 'is_malware' label.")
if df['Class'].dtype == 'object':
    df['is_malware'] = df['Class'].apply(lambda x: 1 if str(x).lower() == 'malware' else 0)
else:
    df['is_malware'] = df['Class'].astype(int) # Ensure it's integer

# Create cleaned multi-class labels
if 'Category' not in df.columns:
    raise ValueError("Column 'Category' not found in CSV. This column is required for 'malware_type' label.")

# Dynamically create the regex pattern based on MALWARE_CATEGORIES
category_pattern = r'^(' + '|'.join(MALWARE_CATEGORIES) + r')'
df['malware_type'] = df['Category'].str.extract(category_pattern, expand=False).fillna("Benign")

print("\nValue counts for 'is_malware':")
print(df['is_malware'].value_counts())
print("\nValue counts for 'malware_type':")
print(df['malware_type'].value_counts())

# Drop non-feature columns
# Ensure 'Class' and 'Category' are dropped if they were not already part of X
# and that 'malware_type' and 'is_malware' are the source for y_multi and y_binary
X = df.drop(columns=["Class", "Category", "malware_type", "is_malware"], errors='ignore')
y_binary = df["is_malware"]
y_multi = df["malware_type"]

print(f"\nFeature shape (X): {X.shape}")
print(f"Binary target unique values (y_binary): {y_binary.unique()}")
print(f"Multi-class target unique values (y_multi): {y_multi.unique()}")

if X.empty:
    raise ValueError("Feature set X is empty. Check column drop logic and CSV content.")

# Save the feature names
os.makedirs("models", exist_ok=True) # Ensure models directory exists
feature_names = X.columns.tolist()
joblib.dump(feature_names, "models/feature_columns.pkl")
print(f"✅ Saved {len(feature_names)} feature names to 'models/feature_columns.pkl'")

# === Step 2: Scale features ===
print("\nScaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# === Step 3: Train/test split ===
print("Splitting data into train and test sets...")
# Stratify by y_multi if it's more representative of the final task,
# or y_binary if AE performance is primary. Let's use y_multi for better multi-class representation.
# Ensure y_multi has enough samples per class for stratification.
if df['malware_type'].value_counts().min() < 2 and len(df['malware_type'].unique()) > 1 :
    print(f"Warning: Some classes in 'malware_type' have less than 2 samples. Stratification might fail or be ineffective. Using stratify=y_binary instead.")
    stratify_target = y_binary
else:
    stratify_target = y_multi

X_train, X_test, y_bin_train, y_bin_test, y_multi_train, y_multi_test = train_test_split(
    X_scaled, y_binary, y_multi, test_size=0.2, stratify=stratify_target, random_state=42
)
print(f"X_train shape: {X_train.shape}, X_test shape: {X_test.shape}")
print(f"y_multi_train distribution:\n{y_multi_train.value_counts()}")
print(f"y_multi_test distribution:\n{y_multi_test.value_counts()}")


# === Step 4: Train AutoEncoder on benign training data ===
X_train_benign = X_train[y_bin_train == 0]
input_dim = X_train.shape[1]

if X_train_benign.shape[0] == 0:
    raise ValueError("No benign samples in the training set (X_train_benign is empty). Cannot train AutoEncoder.")

print(f"\nTraining AutoEncoder on {X_train_benign.shape[0]} benign samples...")
input_layer = Input(shape=(input_dim,))
# Consider making the AE deeper or wider if performance is low
encoded = Dense(max(32, input_dim // 4), activation='relu')(input_layer) # Example: 32 units or 1/4 of input_dim
encoded = Dense(max(16, input_dim // 8), activation='relu')(encoded)    # Example: 16 units or 1/8 of input_dim
decoded = Dense(max(32, input_dim // 4), activation='relu')(encoded)
output_layer = Dense(input_dim, activation='linear')(decoded) # Linear for reconstruction of scaled continuous values

autoencoder = Model(input_layer, output_layer)
autoencoder.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001), loss='mse') # Adam is a good default
autoencoder.fit(X_train_benign, X_train_benign, epochs=30, batch_size=64, validation_split=0.2, shuffle=True, verbose=1,
                callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)])
print("AutoEncoder training complete.")

# Determine MSE threshold from reconstruction errors on benign training data
print("Determining MSE threshold for AutoEncoder...")
train_benign_reconstructions = autoencoder.predict(X_train_benign)
train_benign_mse = np.mean(np.square(X_train_benign - train_benign_reconstructions), axis=1)
mse_threshold = np.percentile(train_benign_mse, AE_THRESHOLD_PERCENTILE)
print(f"MSE Threshold at {AE_THRESHOLD_PERCENTILE}th percentile of benign train errors: {mse_threshold:.6f}")
joblib.dump(mse_threshold, "models/ae_mse_threshold.pkl")
print("✅ Saved AE MSE threshold.")

# === Step 5: Train Random Forest ===
# The RF is trained on all training data (benign and malware) to predict malware_type
print("\nTraining Random Forest classifier...")
rf = RandomForestClassifier(n_estimators=150, random_state=42, class_weight='balanced_subsample', min_samples_split=5, min_samples_leaf=3)
rf.fit(X_train, y_multi_train) # Train on all X_train, predict malware_type
print("Random Forest training complete.")
# Save the classes RF was trained on
joblib.dump(rf.classes_, "models/rf_classes.pkl")
print("✅ Saved RF classes.")


# === Step 6: Save models ===
# Models directory already created
joblib.dump(rf, "models/rf_model.pkl")
joblib.dump(scaler, "models/scaler.pkl")
autoencoder.save("models/autoencoder_model.h5")
print("✅ All models and scaler saved to 'models/' folder.")

# === Step 7: Evaluate Models on Test Set ===
print("\n--- Evaluating AutoEncoder (Anomaly Detection) on Test Set ---")
test_reconstructions = autoencoder.predict(X_test)
test_mse = np.mean(np.square(X_test - test_reconstructions), axis=1)
ae_predictions_binary = (test_mse > mse_threshold).astype(int) # 1 for malware (anomaly), 0 for benign

print(f"AE Accuracy (Benign vs Malware): {accuracy_score(y_bin_test, ae_predictions_binary):.4f}")
print("AE Classification Report (Benign vs Malware):")
print(classification_report(y_bin_test, ae_predictions_binary, target_names=['Benign (0)', 'Malware (1)'], zero_division=0))
print("AE Confusion Matrix (Benign vs Malware):")
print(confusion_matrix(y_bin_test, ae_predictions_binary))

print("\n--- Evaluating Random Forest (Multi-class Classification) on Test Set ---")
rf_predictions_multi = rf.predict(X_test)
# Evaluate RF against y_multi_test. These are the direct multi-class predictions from RF.
# y_multi_test contains "Benign" for benign samples and specific types for malware.
rf_accuracy_multi = accuracy_score(y_multi_test, rf_predictions_multi)
print(f"RF Multi-class Accuracy: {rf_accuracy_multi:.4f}")
print("RF Multi-class Classification Report:")
# Ensure labels for report match unique values in y_multi_test and rf_predictions_multi
multi_class_labels = sorted(y_multi_test.unique())
print(classification_report(y_multi_test, rf_predictions_multi, labels=multi_class_labels, zero_division=0))
print("RF Multi-class Confusion Matrix:")
print(confusion_matrix(y_multi_test, rf_predictions_multi, labels=multi_class_labels))


print("\n--- Evaluating Hybrid Model on Test Set ---")
# Hybrid logic: If AE says benign, it's Benign. If AE says malware, use RF's prediction.
hybrid_final_predictions = []
for i in range(len(X_test)):
    if ae_predictions_binary[i] == 0: # AE predicts Benign
        hybrid_final_predictions.append("Benign")
    else: # AE predicts Malware, use RF's prediction for type
        hybrid_final_predictions.append(rf_predictions_multi[i])
hybrid_final_predictions = np.array(hybrid_final_predictions)

# y_multi_test already serves as the true labels for the hybrid model
# It contains "Benign" for true benign samples and the specific malware type for true malware samples.
hybrid_accuracy = accuracy_score(y_multi_test, hybrid_final_predictions)
print(f"Hybrid Model Accuracy: {hybrid_accuracy:.4f}")
print("Hybrid Model Classification Report:")
print(classification_report(y_multi_test, hybrid_final_predictions, labels=multi_class_labels, zero_division=0))
print("Hybrid Model Confusion Matrix:")
print(confusion_matrix(y_multi_test, hybrid_final_predictions, labels=multi_class_labels))

print("\n--- Example Predictions (first 5 test samples) ---")
for i in range(min(5, len(X_test))):
    print(f"\n🔍 Test Sample {i+1}")
    print(f"  True Binary Label: {'Malware' if y_bin_test.iloc[i] == 1 else 'Benign'}")
    print(f"  True Malware Type: {y_multi_test.iloc[i]}")
    print(f"  AE Prediction: {'Malware (Anomaly)' if ae_predictions_binary[i] == 1 else 'Benign'} (MSE: {test_mse[i]:.6f})")
    print(f"  RF Predicted Type: {rf_predictions_multi[i]}")
    print(f"  Hybrid Final Verdict: {hybrid_final_predictions[i]}")

print("\nTraining and evaluation complete.")