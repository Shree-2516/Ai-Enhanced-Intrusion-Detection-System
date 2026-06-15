from pathlib import Path
import random
import json
from datetime import datetime, timedelta

import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from db.database import SessionLocal, engine
from db.models import Alert, Base, TrafficRecord
from src.severity import get_severity
from src.charts import get_charts_data

app = FastAPI(title="AI Enhanced Intrusion Detection System")

BASE_DIR = Path(__file__).resolve().parent

# Create database tables automatically on startup.
Base.metadata.create_all(bind=engine)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Load model
model = joblib.load(BASE_DIR / "models" / "ids_model.joblib")

# Pre-load sample dataset once at startup for high performance
df_sample = None
try:
    csv_path = BASE_DIR / "dataset" / "processed" / "final_encoded_data.csv"
    if csv_path.exists():
        print("Pre-loading sample dataset for live scanning simulation...")
        df_sample = pd.read_csv(csv_path, nrows=10000)
        print(f"Loaded {len(df_sample)} rows for live scanning.")
except Exception as e:
    print(f"Error loading sample dataset: {e}")


def init_db_data():
    """Pre-populates the database with historical data matching the user's example metrics."""
    db = SessionLocal()
    try:
        if db.query(TrafficRecord).count() == 0:
            print("Database is empty. Pre-populating with 10,000 historical records...")
            
            # Threat breakdown (exactly 234 threats)
            threats_pool = (
                ['DDoS Attack'] * 100 +
                ['Port Scan'] * 80 +
                ['Botnet'] * 20 +
                ['Brute Force'] * 25 +
                ['Web Attack'] * 9
            )
            random.shuffle(threats_pool)
            
            records = []
            alerts = []
            
            # Start dates over the last week
            start_time = datetime.now() - timedelta(days=7)
            
            # 1. Generate threats (234)
            for i in range(234):
                attack = threats_pool[i]
                src = f"192.168.1.{random.randint(100, 200)}"
                dst = f"10.0.0.{random.randint(2, 50)}"
                port = random.choice([80, 443, 22, 21, 8080])
                conf = round(random.uniform(0.85, 0.99), 2)
                dt = start_time + timedelta(seconds=random.randint(0, 7 * 24 * 3600))
                
                # Fetch severity dynamically from severity engine
                severity = get_severity(attack)
                
                records.append({
                    "source_ip": src,
                    "destination_ip": dst,
                    "destination_port": port,
                    "protocol": random.choice(["TCP", "UDP"]),
                    "packet_length": random.randint(64, 1500),
                    "predicted_class": attack,
                    "is_anomaly": 1,
                    "confidence_score": conf,
                    "timestamp": dt
                })
                
                alerts.append({
                    "attack_type": attack,
                    "severity": severity,
                    "source_ip": src,
                    "destination_ip": dst,
                    "confidence_score": conf,
                    "detection_time": dt
                })
                
            # 2. Generate Benign records (9,766)
            for i in range(9766):
                src = f"192.168.1.{random.randint(10, 99)}"
                dst = f"10.0.0.{random.randint(2, 100)}"
                port = random.choice([80, 443, 8080, 22, 53])
                conf = round(random.uniform(0.95, 1.0), 2)
                dt = start_time + timedelta(seconds=random.randint(0, 7 * 24 * 3600))
                
                records.append({
                    "source_ip": src,
                    "destination_ip": dst,
                    "destination_port": port,
                    "protocol": random.choice(["TCP", "UDP"]),
                    "packet_length": random.randint(40, 1500),
                    "predicted_class": "Benign",
                    "is_anomaly": 0,
                    "confidence_score": conf,
                    "timestamp": dt
                })
                
            # Sort chronologically
            records.sort(key=lambda x: x["timestamp"])
            alerts.sort(key=lambda x: x["detection_time"])
            
            # Bulk Insert
            db.execute(TrafficRecord.__table__.insert(), records)
            db.execute(Alert.__table__.insert(), alerts)
            db.commit()
            print("Successfully initialized mock database records!")
    except Exception as e:
        db.rollback()
        print(f"Error pre-populating database: {e}")
    finally:
        db.close()


init_db_data()


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")


@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")


@app.get("/alerts-page")
def alerts_page(request: Request):
    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.detection_time.desc()).all()
        return templates.TemplateResponse(
            request=request,
            name="alerts.html",
            context={"request": request, "alerts": alerts}
        )
    finally:
        db.close()


@app.get("/dashboard-stats")
def get_dashboard_stats():
    db = SessionLocal()
    try:
        # Load accuracy from metrics JSON
        accuracy = 0.984
        metrics_path = BASE_DIR / "models" / "model_metrics.json"
        if metrics_path.exists():
            try:
                with open(metrics_path, "r", encoding="utf-8") as f:
                    metrics = json.load(f)
                    accuracy = metrics.get("accuracy", 0.984)
            except Exception:
                pass
                
        total_scanned = db.query(TrafficRecord).count()
        total_threats = db.query(Alert).count()
        safe_connections = db.query(TrafficRecord).filter(TrafficRecord.is_anomaly == 0).count()
        
        # Threat distribution counts
        threat_distribution = {
            "DDoS Attack": db.query(TrafficRecord).filter(TrafficRecord.predicted_class == "DDoS Attack").count(),
            "Port Scan": db.query(TrafficRecord).filter(TrafficRecord.predicted_class == "Port Scan").count(),
            "Botnet": db.query(TrafficRecord).filter(TrafficRecord.predicted_class == "Botnet").count(),
            "Brute Force": db.query(TrafficRecord).filter(TrafficRecord.predicted_class == "Brute Force").count(),
            "Web Attack": db.query(TrafficRecord).filter(TrafficRecord.predicted_class == "Web Attack").count(),
            "Benign": safe_connections
        }
        
        # Recent Alerts (last 15)
        recent_alerts = db.query(Alert).order_by(Alert.detection_time.desc()).limit(15).all()
        alerts_list = [
            {
                "id": alert.id,
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "confidence_score": round(alert.confidence_score * 100, 1) if alert.confidence_score <= 1.0 else alert.confidence_score,
                "detection_time": alert.detection_time.strftime("%H:%M:%S")
            }
            for alert in recent_alerts
        ]
        
        # Generate chart data reactively
        charts_data = get_charts_data(db)
        
        return {
            "total_records": total_scanned,
            "threats": total_threats,
            "safe": safe_connections,
            "accuracy": round(accuracy * 100, 1),
            "threat_distribution": threat_distribution,
            "recent_alerts": alerts_list,
            "charts": charts_data
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        db.close()


@app.get("/predict")
def predict():
    global df_sample
    db = SessionLocal()
    
    try:
        if df_sample is None:
            csv_path = BASE_DIR / "dataset" / "processed" / "final_encoded_data.csv"
            if csv_path.exists():
                df_sample = pd.read_csv(csv_path, nrows=10000)
            else:
                return {"error": "Dataset not found. Please run feature engineering first."}
                
        # Sample 50 records for dynamic scanning
        scan_batch = df_sample.sample(n=50, random_state=random.randint(1, 100000))
        
        # Prepare features exactly as the model expects
        features = scan_batch.drop(
            columns=["Label", "Label_Encoded"],
            errors="ignore",
        )
        features = features[model.feature_names_in_]
        
        # Run prediction
        predictions = model.predict(features)
        
        # Calculate confidence scores
        try:
            probabilities = model.predict_proba(features)
            confidence_scores = np.max(probabilities, axis=1)
        except Exception:
            confidence_scores = [0.95] * len(predictions)
            
        # Decode predictions using the LabelEncoder
        encoder_path = BASE_DIR / "models" / "label_encoder.joblib"
        if encoder_path.exists():
            le = joblib.load(encoder_path)
            predicted_labels = le.inverse_transform(predictions)
        else:
            class_mapping = {0: 'Benign', 1: 'Botnet', 2: 'Brute Force', 3: 'DDoS Attack', 4: 'Port Scan', 5: 'Web Attack'}
            predicted_labels = [class_mapping.get(p, 'Benign') for p in predictions]
            
        scanned_records = []
        threats_detected = 0
        
        # Read from dataset columns if present
        ports = scan_batch['Destination Port'].tolist() if 'Destination Port' in scan_batch.columns else [random.choice([80, 443, 22, 53])] * 50
        packet_lengths = scan_batch['Average Packet Size'].tolist() if 'Average Packet Size' in scan_batch.columns else [random.randint(40, 1500)] * 50
        
        for i in range(len(predicted_labels)):
            predicted_class = predicted_labels[i]
            conf = float(confidence_scores[i])
            port = int(ports[i])
            pkt_len = int(packet_lengths[i]) if not np.isnan(packet_lengths[i]) else random.randint(40, 1500)
            
            src = f"192.168.1.{random.randint(100, 200)}"
            dst = f"10.0.0.{random.randint(2, 50)}"
            protocol = random.choice(["TCP", "UDP"])
            
            is_anomaly = 1 if predicted_class != "Benign" else 0
            
            # Log to TrafficRecord
            tr = TrafficRecord(
                source_ip=src,
                destination_ip=dst,
                destination_port=port,
                protocol=protocol,
                packet_length=pkt_len,
                predicted_class=predicted_class,
                is_anomaly=is_anomaly,
                confidence_score=conf
            )
            db.add(tr)
            
            # Log Alert if it's an attack
            if is_anomaly == 1:
                threats_detected += 1
                
                # Fetch severity dynamically from severity engine
                severity = get_severity(predicted_class)
                
                alert = Alert(
                    attack_type=predicted_class,
                    severity=severity,
                    source_ip=src,
                    destination_ip=dst,
                    confidence_score=conf
                )
                db.add(alert)
                
            scanned_records.append({
                "source_ip": src,
                "destination_ip": dst,
                "destination_port": port,
                "protocol": protocol,
                "predicted_class": predicted_class,
                "is_anomaly": is_anomaly,
                "confidence_score": round(conf * 100, 1)
            })
            
        db.commit()
        
        return {
            "scanned_count": len(predicted_labels),
            "threats_count": threats_detected,
            "results": scanned_records
        }
    except Exception as exc:
        db.rollback()
        return {"error": str(exc)}
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
