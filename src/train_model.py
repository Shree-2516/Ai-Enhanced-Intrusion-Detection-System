import pandas as pd
import joblib
import os
import json
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support

def save_metrics_to_db(accuracy: float, precision: float, recall: float, f1: float):
    """
    Saves model performance metrics to the database model_metrics table.
    Ensures path resolutions work when run directly as a script.
    """
    try:
        import sys
        # Resolve root path of the project to import db
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if root_dir not in sys.path:
            sys.path.append(root_dir)

        from db.database import SessionLocal
        from db.models import ModelMetric

        db = SessionLocal()
        try:
            metric_record = ModelMetric(
                accuracy=accuracy,
                precision_score=precision,
                recall_score=recall,
                f1_score=f1
            )
            db.add(metric_record)
            db.commit()
            print("Successfully saved training metrics to the database 'model_metrics' table.")
        except Exception as db_err:
            db.rollback()
            print(f"Database error saving metrics: {db_err}")
        finally:
            db.close()
    except Exception as e:
        print(f"Could not save metrics to database: {e}")


def train_ids_model(input_file, model_output_path):
    # 1. Load the encoded data
    print("Loading encoded data...")
    df = pd.read_csv(input_file)
    
    # 2. Downsample to keep training fast, balanced, and model size compact
    print("Downsampling dataset for balanced and fast training...")
    
    # Target sample sizes
    benign_target = 100000
    ddos_target = 100000
    port_target = 50000
    
    df_benign = df[df['Label'] == 'Benign']
    df_ddos = df[df['Label'] == 'DDoS Attack']
    df_port = df[df['Label'] == 'Port Scan']
    df_others = df[~df['Label'].isin(['Benign', 'DDoS Attack', 'Port Scan'])]
    
    # Safely sample if we have enough records, otherwise take all
    df_benign_sampled = df_benign.sample(n=min(benign_target, len(df_benign)), random_state=42)
    df_ddos_sampled = df_ddos.sample(n=min(ddos_target, len(df_ddos)), random_state=42)
    df_port_sampled = df_port.sample(n=min(port_target, len(df_port)), random_state=42)
    
    sampled_df = pd.concat([df_benign_sampled, df_ddos_sampled, df_port_sampled, df_others], ignore_index=True)
    print(f"Sampled dataset shape: {sampled_df.shape}")
    print("Class distribution in training set:")
    print(sampled_df['Label'].value_counts())
    
    # 3. Prepare Features (X) and Target (y)
    X = sampled_df.drop(['Label', 'Label_Encoded'], axis=1)
    y = sampled_df['Label_Encoded']
    
    # 4. Split into Train and Test sets (80% training, 20% testing)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 5. Initialize and Train the model
    # n_estimators=50 and max_depth=15 provides excellent accuracy and speed
    print("Training Random Forest model (this should take less than 10 seconds)...")
    model = RandomForestClassifier(n_estimators=50, max_depth=15, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)
    
    # 6. Evaluate Performance
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Training Complete.")
    print(f"Accuracy on Test Set: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    report_str = classification_report(y_test, y_pred)
    print(report_str)
    
    # Load label encoder classes to map metrics
    models_dir = os.path.dirname(model_output_path)
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    if os.path.exists(encoder_path):
        le = joblib.load(encoder_path)
        class_names = list(le.classes_)
    else:
        class_names = [str(c) for c in sorted(y.unique())]
        
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average=None)
    
    metrics = {
        "accuracy": float(accuracy),
        "class_metrics": {
            name: {
                "precision": float(p),
                "recall": float(r),
                "f1_score": float(f)
            }
            for name, p, r, f in zip(class_names, precision, recall, f1)
        }
    }
    
    metrics_path = os.path.join(models_dir, "model_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)
    print(f"Saved evaluation metrics to: {metrics_path}")

    # Save metrics to the database table model_metrics
    precision_avg, recall_avg, f1_avg, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    save_metrics_to_db(float(accuracy), float(precision_avg), float(recall_avg), float(f1_avg))
    
    # 7. Save the model
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
        
    joblib.dump(model, model_output_path)
    print(f"\nModel saved to: {model_output_path}")

if __name__ == "__main__":
    # Ensure this path matches the output from feature_engineering.py
    data_path = "dataset/processed/final_encoded_data.csv"
    model_path = "models/ids_model.joblib"
    
    if os.path.exists(data_path):
        train_ids_model(data_path, model_path)
    else:
        print(f"Error: {data_path} not found. Run feature_engineering.py first.")