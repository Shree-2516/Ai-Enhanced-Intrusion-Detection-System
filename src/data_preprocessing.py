import pandas as pd
import numpy as np
import os
import glob

def preprocess_data(raw_data_path, output_path):
    # 1. Get all CSV files in the directory
    all_files = glob.glob(os.path.join(raw_data_path, "*.csv"))
    
    df_list = []
    print(f"Found {len(all_files)} files. Starting to load...")

    for file in all_files:
        print(f"Processing: {os.path.basename(file)}")
        df = pd.read_csv(file)
        
        # Clean column names (remove leading/trailing spaces)
        df.columns = df.columns.str.strip()
        df_list.append(df)

    # 2. Merge all dataframes
    full_df = pd.concat(df_list, axis=0, ignore_index=True)
    print(f"Merged dataset shape: {full_df.shape}")

    # 3. Data Cleaning
    # Replace Infinity values with NaN
    full_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Drop rows with NaN values
    initial_count = len(full_df)
    full_df.dropna(inplace=True)
    print(f"Dropped {initial_count - len(full_df)} rows containing NaN/Inf values.")

    # 4. Save to processed folder
    if not os.path.exists(output_path):
        os.makedirs(output_path)
        
    output_file = os.path.join(output_path, "cleaned_ids_data.csv")
    full_df.to_csv(output_file, index=False)
    print(f"Successfully saved cleaned data to: {output_file}")

if __name__ == "__main__":
    # Point to your folders based on your structure
    raw_dir = "dataset/raw/CIC-IDS2017"
    proc_dir = "dataset/processed"
    
    preprocess_data(raw_dir, proc_dir)