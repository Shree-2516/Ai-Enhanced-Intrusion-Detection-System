# AI-Enhanced Intrusion Detection System (IDS)

An advanced, machine learning-driven network traffic classification and intrusion detection system. The application features a clean FastAPI web interface, a robust MySQL data pipeline for real-time alerting, dynamic plotting using Plotly, and a Random Forest Classifier trained on the CIC-IDS2017 dataset to identify malicious traffic patterns with **99.83% accuracy**.

---

## 🌟 Key Features

- **Real-Time Traffic Scanning**: Simulate and classify live network traffic batches using an optimized Random Forest machine learning model.
- **Interactive Security Dashboard**: Visual insights including live network threat distribution, network throughput, anomaly ratios, and system health status.
- **Dynamic Threat Alerting**: Centralized alert management system categorizing threats (DDoS, Botnet, Brute Force, Port Scan, Web Attacks) and prioritizing severity.
- **Relational Data Pipeline**: Structured SQLite/MySQL logging utilizing SQLAlchemy ORM to track `TrafficRecord`, `TrafficLog`, `Alert`, and `ModelMetric` histories.
- **End-to-End ML Pipeline**: Out-of-the-box scripts for raw data preprocessing, balanced feature engineering, downsampling, classifier training, and performance tracking.

---

## 📊 Model Evaluation & Metrics

The system uses a Random Forest Classifier trained on downsampled and balanced traffic patterns from the **CIC-IDS2017 dataset**. The performance evaluation demonstrates excellent precision, recall, and F1-score across all classes:

| Traffic Class | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: |
| **Benign** | 99.73% | 99.84% | 99.79% | Safe ✅ |
| **Botnet** | 96.92% | 94.25% | 95.56% | Threat 🚨 |
| **Brute Force** | 100.00% | 99.86% | 99.93% | Threat 🚨 |
| **DDoS Attack** | 99.92% | 99.94% | 99.93% | Threat 🚨 |
| **Port Scan** | 99.90% | 99.93% | 99.92% | Threat 🚨 |
| **Web Attack** | 99.75% | 96.67% | 98.19% | Threat 🚨 |
| **Overall Accuracy** | \- | \- | **99.83%** | **Optimal** |

---

## 📂 Project Architecture

```directory
├── dataset/
│   ├── raw/                  # Raw CIC-IDS2017 CSV source files
│   └── processed/            # Cleaned and feature-engineered datasets
├── db/
│   ├── database.py           # SQLAlchemy database connection and session creation
│   └── models.py             # Database schemas (TrafficRecord, TrafficLog, Alert, ModelMetric)
├── models/
│   ├── ids_model.joblib      # Trained Random Forest classifier binary
│   ├── label_encoder.joblib  # Trained LabelEncoder for target classifications
│   └── model_metrics.json    # Exported evaluation metrics JSON
├── src/
│   ├── alert_system.py       # Logic for filtering anomalies and creating alerts
│   ├── charts.py             # Dynamic Plotly/Matplotlib data generation for UI charts
│   ├── data_preprocessing.py # Merging and cleaning raw network CSVs
│   ├── feature_engineering.py# Target label cleanup and category mapping
│   ├── severity.py           # Severity assignment engine based on attack types
│   └── train_model.py        # Model training script and database metrics logger
├── static/
│   ├── css/                  # Front-end styling rules
│   ├── js/                   # Dashboard charts loader and update scripts
│   └── images/               # Media files and dashboard graphics
├── templates/
│   ├── dashboard.html        # Main interactive admin panel
│   ├── alerts.html           # Historical threat logs view
│   └── index.html            # Landing / Root template
├── .env                      # Local environment variable configs
├── .gitignore                # Target directories and files to exclude from Git
├── app.py                    # Main FastAPI gateway and endpoints
└── requirements.txt          # Package dependencies
```

---

## 🛠️ Getting Started

### Prerequisites

- **Python 3.10+** installed.
- **MySQL Server** (or local MySQL instance) running.
- (Optional) Git installed.

### 1. Clone & Setup Workspace

```bash
# Clone the repository (if applicable)
git clone https://github.com/your-username/Ai-Enhanced-Intrusion-Detection-System.git
cd "Ai-Enhanced Intrusion Detection System"

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Windows (Command Prompt)
.venv\Scripts\activate
# On Windows (PowerShell)
.venv\Scripts\Activate.ps1
# On macOS/Linux
source .venv/bin/activate

# Install the dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create a `.env` file in the root directory and populate it with your database and app credentials:

```ini
DB_HOST=localhost
DB_PORT=3306
DB_NAME=intrusion_detection_db
DB_USER=root
DB_PASSWORD=your_root_password

SECRET_KEY=your_super_secure_app_secret_key
```

Make sure to create the database in MySQL before running the application:
```sql
CREATE DATABASE intrusion_detection_db;
```

---

## 🔄 Running the Machine Learning Pipeline

If you want to preprocess raw data, perform feature engineering, and train/evaluate the classifier from scratch, run the scripts in order:

### Step A: Data Preprocessing
Consolidates raw traffic files (CSVs) inside `dataset/raw/CIC-IDS2017/` into a single cleaned CSV.
```bash
python src/data_preprocessing.py
```

### Step B: Feature Engineering
Cleans up classes, maps anomalies, fits labels, and saves the `label_encoder.joblib` artifact.
```bash
python src/feature_engineering.py
```

### Step C: Train Model
Downsamples data, splits sets, trains the Random Forest classifier, evaluates it, saves `ids_model.joblib`, and pushes evaluation metrics to both `model_metrics.json` and the database dashboard database.
```bash
python src/train_model.py
```

*Note: Pre-trained files (`ids_model.joblib` and `label_encoder.joblib`) are already included inside the `models/` directory for out-of-the-box operation.*

---

## 🚀 Running the Web Application

To spin up the web dashboard and API service locally:

```bash
python app.py
```

The app automatically handles:
1. Connecting to your database.
2. Generating the schemas and tables if they don't exist.
3. Seeding mock traffic log templates to populate dashboard histories.
4. Serving the dashboard at: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 🔍 API Documentation Reference

FastAPI generates interactive, self-documenting API structures accessible directly:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Core Enpoints

- `GET /` or `/dashboard`: Render and return the UI console template.
- `GET /alerts-page`: Render and return the historical threat alerts view.
- `GET /dashboard-stats`: Retrieves overall logs count, anomaly breakdown percentages, live metrics, and coordinates for charts.
- `GET /predict`: Simulates a live scan batch of 50 records from the processed validation dataset, running predictions, generating live alert triggers, and recording telemetry.

## Author 
Shreeyash Paraj