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

# === Step 1: Load and Prepare Data ===
df = pd.read_csv("Obfuscated-MalMem2022.csv")
df['Class'] = df['Class'].apply(lambda x: 1 if x.lower() == 'malware' else 0)
df = df.drop(columns=["Category"])

# === Step 2: Drop Constant Columns ===
constant_cols = df.columns[df.nunique() == 1].tolist()
df = df.drop(columns=constant_cols)

# === Step 3: Drop Highly Correlated (Leaky) Features ===
leaky_features = [
    'pslist.nppid',
    'handles.ndirectory',
    'pslist.avg_handlers',
    'ldrmodules.not_in_mem_avg',
    'ldrmodules.not_in_load_avg',
    'handles.nhandles',
    'handles.ndesktop',
    'svcscan.nservices',
    'svcscan.nactive',
    'handles.nkey',
    'svcscan.shared_process_services',
    'ldrmodules.not_in_init',
    'svcscan.process_services',
    'handles.nsemaphore',
    'handles.ntimer',
    'ldrmodules.not_in_mem',
    'ldrmodules.not_in_load',
    'pslist.avg_threads',
    'handles.nsection',
    'dlllist.ndlls',
    'handles.nmutant',
    'handles.nthread',
    'handles.nevent',
    'dlllist.avg_dlls_per_proc'
]
df = df.drop(columns=[col for col in leaky_features if col in df.columns])

# === Step 4: Define Features and Target ===
X = df.drop("Class", axis=1)
y = df["Class"]

# === Step 5: Train-Test Split ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# === Step 6: Feature Scaling (Important for SVM) ===
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# === Step 7: Define Base Learners ===
base_learners = [
    ("lgbm", LGBMClassifier(random_state=42)),
    ("svm", SVC(probability=True, random_state=42))
]

meta_learner = LogisticRegression()

# === Step 8: Build Stacking Ensemble ===
stacked_model = StackingClassifier(
    estimators=base_learners,
    final_estimator=meta_learner,
    cv=5,
    n_jobs=-1
)

stacked_model.fit(X_train_scaled, y_train)

# === Step 9: Evaluate ===
y_pred = stacked_model.predict(X_test_scaled)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))
print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

# === Step 10: Save Model and Scaler ===
joblib.dump(stacked_model, "stacked_model.pkl")
joblib.dump(scaler, "scaler.pkl")
print("✅ Model and scaler saved.")
