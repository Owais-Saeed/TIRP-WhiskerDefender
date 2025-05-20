# === Required packages ===
# pip install pandas numpy scikit-learn lightgbm joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import warnings

# Suppress specific LightGBM warnings if they are too noisy after fixing the main issue
# warnings.filterwarnings("ignore", category=UserWarning, module="lightgbm")

# === Step 1: Load and Prepare Data ===
print("Loading data...")
df = pd.read_csv("Obfuscated-MalMem2022.csv")

# We'll use 'Category' as the target (multi-class)
print(f"Initial dataframe shape: {df.shape}")
df = df[df['Category'].notna()]  # remove any NaNs in target
df = df.drop(columns=["Class"], errors='ignore')  # Drop binary label if it exists
print(f"Shape after dropping NaNs in 'Category' and 'Class' column: {df.shape}")

# === Step 1.5: Clean Target Labels in 'Category' Column ===
print("\nCleaning target labels in 'Category' column...")
def clean_malware_category(category_str):
    """
    Extracts the primary malware type (Ransomware, Trojan, Spyware)
    from the detailed category string.
    """
    if pd.isna(category_str):
        return None # Handle potential NaNs if any slip through

    category_str = str(category_str).lower() # Convert to lowercase for robust matching

    if category_str.startswith("ransomware"):
        return "Ransomware"
    elif category_str.startswith("trojan"):
        return "Trojan"
    elif category_str.startswith("spyware"):
        return "Spyware"
    elif category_str == "benign":
        return "Benign"
    # Add other primary types if they exist and you want to classify them
    # elif category_str.startswith("adware"):
    #     return "Adware"
    # elif category_str.startswith("downloader"):
    #     return "Downloader"
    else:
        # If it's not one of the specified primary types,
        # you can choose to label it as 'Other' or try to extract the first part.
        # For now, let's label unrecognized ones as 'Other'.
        # print(f"Warning: Unrecognized category format: {category_str}. Will be treated as 'Other'.")
        return "Other" # Or return category_str.split('-')[0].capitalize() if you want the first part

# Apply the cleaning function
df['Category'] = df['Category'].apply(clean_malware_category)

# Optional: Remove rows where category became None or 'Other' if you only want specific types
# df = df[df['Category'].notna()]
# df = df[df['Category'] != 'Other'] # Uncomment if you want to exclude 'Other'

print("\nCategory counts after cleaning:")
print(df['Category'].value_counts(dropna=False)) # dropna=False to see if any NaNs were produced

# Remove rows if 'Category' became None after cleaning
df = df[df['Category'].notna()]
print(f"Shape after removing any NaN categories post-cleaning: {df.shape}")


# === Step 2: Drop Constant Columns ===
print("\nDropping constant columns...")
constant_cols = df.columns[df.nunique() == 1].tolist()
if constant_cols:
    df = df.drop(columns=constant_cols)
    print(f"Dropped constant columns: {constant_cols}")
else:
    print("No constant columns found.")
print(f"Shape after dropping constant columns: {df.shape}")

# === Step 3: Drop Highly Correlated (Leaky) Features ===
print("\nDropping leaky features...")
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
# Ensure only existing columns are dropped
columns_to_drop = [col for col in leaky_features if col in df.columns]
if columns_to_drop:
    df = df.drop(columns=columns_to_drop)
    print(f"Dropped leaky features: {columns_to_drop}")
else:
    print("No specified leaky features found in the dataframe.")
print(f"Shape after dropping leaky features: {df.shape}")

# === Step 4: Define Features and Target ===
if "Category" not in df.columns:
    raise ValueError("'Category' column not found. This column is needed as the target variable.")
    
X = df.drop("Category", axis=1)
y = df["Category"] # Now 'y' will have "Ransomware", "Trojan", "Spyware", "Other"
print(f"\nFeatures shape (X): {X.shape}")
print(f"Target shape (y): {y.shape}")

# Save the list of feature names
feature_columns = X.columns.tolist()
joblib.dump(feature_columns, "feature_columns.pkl")
print("\n✅ Saved feature columns.")

# === Step 5: Filter Classes and Train-Test Split ===
print("\nCategory counts before filtering for CV:")
print(y.value_counts())

CV_FOLDS_IN_STACKING = 5  # This should match cv in StackingClassifier
class_counts = y.value_counts()
# Keep classes that have at least CV_FOLDS_IN_STACKING samples
valid_classes = class_counts[class_counts >= CV_FOLDS_IN_STACKING].index

if len(valid_classes) < len(class_counts.index):
    print(f"\nFiltering classes: Keeping only those with at least {CV_FOLDS_IN_STACKING} samples for CV.")
    X = X[y.isin(valid_classes)]
    y = y[y.isin(valid_classes)]
    print("Filtered category counts (for CV):")
    print(y.value_counts())
else:
    print(f"\nAll classes have at least {CV_FOLDS_IN_STACKING} samples. No CV-based filtering needed.")

if X.empty or y.empty:
    raise ValueError(f"No data left after filtering classes with less than {CV_FOLDS_IN_STACKING} samples. Check your dataset or CV_FOLDS_IN_STACKING value.")
if len(y.unique()) < 2: # Stacking and classification require at least 2 classes
    raise ValueError(f"Less than 2 classes remain after filtering (found {len(y.unique())}: {y.unique()}). Stacking requires multiple classes.")

print(f"\nShape of X after class filtering for CV: {X.shape}")
print(f"Shape of y after class filtering for CV: {y.shape}")

print("\nSplitting data into training and testing sets...")
# Stratify by y to ensure class proportions are maintained in train/test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print(f"X_train shape: {X_train.shape}, y_train shape: {y_train.shape}")
print(f"X_test shape: {X_test.shape}, y_test shape: {y_test.shape}")

print("\nCategory counts in y_train (this will be used for StackingClassifier CV):")
y_train_counts = pd.Series(y_train).value_counts()
print(y_train_counts)
# Check if any class in y_train now has less than CV_FOLDS_IN_STACKING
if (y_train_counts < CV_FOLDS_IN_STACKING).any():
    problematic_classes = y_train_counts[y_train_counts < CV_FOLDS_IN_STACKING].index.tolist()
    print(f"\n[CRITICAL WARNING] Some classes in y_train have fewer than {CV_FOLDS_IN_STACKING} samples after train-test split: {problematic_classes}.")
    print("This WILL LIKELY cause issues with StackingClassifier's CV (e.g., errors or LightGBM warnings).")
    print("Consider: ")
    print("  1. Increasing the initial number of samples per class before filtering (if possible).")
    print("  2. Using a smaller `CV_FOLDS_IN_STACKING` value (e.g., 3), but this reduces CV robustness.")
    print("  3. Removing these very small classes from y_train and corresponding X_train (though this means the model won't learn them).")
    print("  4. Ensuring your initial data cleaning and filtering (Step 1.5 and Step 5) leaves enough samples post-split.")
    # Example of how to remove them if absolutely necessary, though it's better to fix upstream:
    # valid_train_indices = y_train[y_train.isin(y_train_counts[y_train_counts >= CV_FOLDS_IN_STACKING].index)].index
    # X_train = X_train.loc[valid_train_indices]
    # y_train = y_train.loc[valid_train_indices]
    # print("\nCategory counts in y_train after attempting to fix critical warning:")
    # print(pd.Series(y_train).value_counts())
    # if len(y_train.unique()) < 2:
    #    raise ValueError("Not enough classes left in y_train after attempting to fix critical warning.")


# === Step 6: Feature Scaling (Important for SVM) ===
print("\nScaling features...")
scaler = StandardScaler()
# Ensure X_train is not empty before fitting scaler
if X_train.empty:
    raise ValueError("X_train is empty. Cannot fit scaler. Check data preprocessing and filtering steps.")
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test) # Use the same scaler fitted on training data
print("Feature scaling complete.")

# === Step 7: Define Base Learners ===
print("\nDefining base learners...")
base_learners = [
    ("lgbm", LGBMClassifier(
        random_state=42,
        min_child_samples=5, 
        n_estimators=100,
        # verbosity=-1 # Suppress LightGBM's own messages
    )),
    ("svm", SVC(probability=True, random_state=42, C=1.0))
]

# Meta-learner
meta_learner = LogisticRegression(max_iter=1000, random_state=42)
print("Base learners and meta-learner defined.")

# === Step 8: Build Stacking Ensemble ===
print("\nBuilding Stacking Ensemble model...")
# Ensure y_train has enough classes for stacking
if len(pd.Series(y_train).unique()) < 2:
    raise ValueError(f"y_train has less than 2 unique classes ({pd.Series(y_train).unique()}), cannot build StackingClassifier.")

stacked_model = StackingClassifier(
    estimators=base_learners,
    final_estimator=meta_learner,
    cv=CV_FOLDS_IN_STACKING,
    n_jobs=-1,
    # passthrough=False
)

print("Fitting the stacked model (this may take some time)...")
stacked_model.fit(X_train_scaled, y_train)
print("Model fitting complete.")

# === Step 9: Evaluate ===
print("\nEvaluating the model...")
y_pred = stacked_model.predict(X_test_scaled)

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

print("\n=== Classification Report ===")
try:
    unique_labels = sorted(pd.Series(y_test).unique()) 
    print(classification_report(y_test, y_pred, target_names=[str(label) for label in unique_labels], zero_division=0))
except Exception as e:
    print(f"Could not generate classification report with target names: {e}")
    print(classification_report(y_test, y_pred, zero_division=0))


print("\n=== Confusion Matrix ===")
try:
    cm = confusion_matrix(y_test, y_pred, labels=unique_labels)
    cm_df = pd.DataFrame(cm, index=[f"Actual: {label}" for label in unique_labels], columns=[f"Predicted: {label}" for label in unique_labels])
    print(cm_df)
except Exception as e:
    print(f"Could not generate confusion matrix with labels: {e}")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)


# === Step 10: Save Model and Scaler ===
print("\nSaving model and scaler...")
joblib.dump(stacked_model, "stacked_model.pkl")
joblib.dump(scaler, "scaler.pkl")
# Save the cleaned classes the model was trained on
joblib.dump(stacked_model.classes_, "model_classes.pkl") 
print("✅ Model, scaler, and model classes saved.")