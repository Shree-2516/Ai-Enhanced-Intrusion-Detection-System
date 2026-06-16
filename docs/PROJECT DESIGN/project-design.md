## PROJECT DESIGN
### 1 Data Flow Diagrams & User Stories

# Data Flow Diagram (Level 0)
+------------------+
| Security Analyst |
+--------+---------+
         |
         | Scan Request
         v
+---------------------------+
| AI-Enhanced IDS System    |
+------------+-------------+
             |
             | Detection Results
             v
+---------------------------+
| Threat Alerts & Reports   |
+---------------------------+


# Data Flow Diagram (Level 1)
                     +----------------+
                     | Security Admin |
                     +--------+-------+
                              |
                              | Request Scan
                              v
+--------------------------------------------------+
|         AI-Enhanced Intrusion Detection          |
+--------------------------------------------------+
|                                                  |
| 1. Network Traffic Data Collection               |
|                 |                                |
|                 v                                |
| 2. Data Preprocessing                            |
|                 |                                |
|                 v                                |
| 3. Feature Engineering                           |
|                 |                                |
|                 v                                |
| 4. Random Forest Model Prediction                |
|                 |                                |
|         +-------+--------+                       |
|         |                |                       |
|         v                v                       |
| 5. Traffic Logs      6. Alert System            |
|         |                |                       |
|         +-------+--------+                       |
|                 |                                |
|                 v                                |
|          MySQL Database                          |
+----------------+---------------------------------+
                 |
                 v
      Dashboard / Reports / Charts


## User Stories
## User Story ID	      Description
US-01	              As a Security Analyst, I want to scan network traffic    so that suspicious activities can be detected automatically.

US-02	              As a Security Analyst, I want to view attack classifications so that I can understand the nature of threats.

US-03	              As an Administrator, I want all alerts stored in a database so that historical incidents can be audited.

US-04	               As a Security Analyst, I want to see dashboard analytics and charts so that I can monitor network health. 

US-05	                As an Administrator, I want model performance metrics so that I can evaluate detection accuracy.

US-06	                As a Security Analyst, I want severity-based alerts so that critical threats can be prioritized.


###  Solution Architecture
Solution Architecture Description

The AI-Enhanced Intrusion Detection System follows a three-layer architecture:

Presentation Layer
Dashboard UI
Alerts Page
Plotly Charts
Traffic Inspector
Application Layer
FastAPI Backend
Alert Engine
Prediction Engine
Severity Classification Engine
Data Layer
MySQL Database
Trained ML Model
Processed Dataset


## Solution Architecture Diagram
┌─────────────────────────────────────┐
│         PRESENTATION LAYER          │
├─────────────────────────────────────┤
│ Dashboard.html                      │
│ Alerts.html                         │
│ Plotly Charts                       │
│ Traffic Inspector                   │
└─────────────────┬───────────────────┘
                  │ HTTP Requests
                  ▼
┌─────────────────────────────────────┐
│         APPLICATION LAYER           │
├─────────────────────────────────────┤
│ FastAPI Server (app.py)             │
│                                     │
│ Prediction Engine                   │
│ Alert System                        │
│ Severity Classification             │
│ Charts Module                       │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│            DATA LAYER               │
├─────────────────────────────────────┤
│ MySQL Database                      │
│                                     │
│ alerts table                        │
│ traffic_logs table                  │
│ model_metrics table                 │
│                                     │
│ Random Forest Model                 │
│ ids_model.joblib                    │
│                                     │
│ Processed Dataset                   │
└─────────────────────────────────────┘