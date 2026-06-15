import pandas as pd
from sklearn.preprocessing import LabelEncoder
import os
import joblib

def clean_label(val):
    val_str = str(val).strip()
    if 'BENIGN' in val_str:
        return 'Benign'
    elif 'DDoS' in val_str or 'DoS' in val_str:
        return 'DDoS Attack'
    elif 'PortScan' in val_str or 'Port Scan' in val_str:
        return 'Port Scan'
    elif 'Bot' in val_str:
        return 'Botnet'
    elif 'Patator' in val_str:
        return 'Brute Force'
    elif 'Web Attack' in val_str or 'Infiltration' in val_str or 'Heartbleed' in val_str:
        return 'Web Attack'
    return 'Benign'

def encode_labels(input_file, output_file):
    # 1. Load the cleaned data
    print("Loading data for encoding...")
    df = pd.read_csv(input_file)
    
    # 2. Check if 'Label' exists
    if 'Label' not in df.columns:
        print("Error: 'Label' column not found in dataset!")
        return

    # 3. Map labels to target categories and encode
    print("Mapping labels to target categories...")
    df['Label'] = df['Label'].apply(clean_label)

    print("Encoding labels...")
    le = LabelEncoder()
    df['Label_Encoded'] = le.fit_transform(df['Label'])
    
    # Print the mapping for documentation
    mapping = dict(zip(le.classes_, le.transform(le.classes_)))
    print(f"Label Mapping: {mapping}")
    
    # Save the label encoder
    models_dir = "models"
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    joblib.dump(le, encoder_path)
    print(f"Saved LabelEncoder to: {encoder_path}")
    
    # 4. Save the processed data
    df.to_csv(output_file, index=False)
    print(f"Successfully saved encoded data to: {output_file}")


if __name__ == "__main__":
    # Define paths
    input_path = "dataset/processed/cleaned_ids_data.csv"
    output_path = "dataset/processed/final_encoded_data.csv"
    
    # Run the function
    if os.path.exists(input_path):
        encode_labels(input_path, output_path)
    else:
        print(f"File not found: {input_path}. Please run data_preprocessing.py first.")