import joblib
expected_cols = joblib.load("models/feature_columns.pkl")
print(expected_cols)