import pandas as pd
import joblib
import os

def predict_traffic(input_data_path, model_path):
    # 1. Load the model and label encoder
    if not os.path.exists(model_path):
        print(f"Error: Model file not found at {model_path}")
        return

    model = joblib.load(model_path)
    print("Model loaded successfully.")
    
    models_dir = os.path.dirname(model_path)
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    le = None
    if os.path.exists(encoder_path):
        le = joblib.load(encoder_path)
        print("Label encoder loaded successfully.")

    # 2. Load the input data
    data = pd.read_csv(input_data_path)
    
    # 3. Prepare features exactly as the model expects
    cols_to_drop = ['Label', 'Label_Encoded']
    X_new = data.drop(columns=[c for c in cols_to_drop if c in data.columns])
    
    try:
        X_new = X_new[model.feature_names_in_]
    except AttributeError:
        print("Error: The model is incompatible. Please retrain your model with the latest scikit-learn.")
        return

    # 4. Predict
    print(f"Predicting on {len(X_new)} records...")
    predictions = model.predict(X_new)
    
    # 5. Decode predictions
    if le is not None:
        predictions = le.inverse_transform(predictions)
    
    return predictions

if __name__ == "__main__":
    model_file = "models/ids_model.joblib"
    test_data = "dataset/processed/final_encoded_data.csv"
    
    if os.path.exists(test_data):
        results = predict_traffic(test_data, model_file)
        if results is not None:
            print(f"Predictions (first 10): {results[:10]}")
    else:
        print(f"Error: {test_data} not found.")