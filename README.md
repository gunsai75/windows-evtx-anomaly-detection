# Windows EVTX Anomaly Detection

> Anomaly detection pipeline for Windows event logs using Isolation Forest, DBSCAN, and Random Forest — with an interactive Plotly Dash dashboard.

**Team:** B. Murali Krishna · Bhuvan Kasam · Maayank Singh · Nihanth Varma R. · M. Sai Ganesha  
**Mentor:** Dr. Rajkumar Kalimuthu, Associate Professor, SOT

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Dataset Setup](#dataset-setup)
- [Installation](#installation)
- [Running the Pipeline](#running-the-pipeline)
- [Results](#results)
- [Project Structure](#project-structure)

---

## Overview

This project automates the process of digital forensic investigation by applying Machine Learning to Windows event logs. It ingests raw `.evtx` files, parses them using Hayabusa, runs a three-stage ML pipeline to detect and classify anomalies, and visualizes the results on an interactive dashboard.

The system reduces the volume of events requiring manual review by automatically surfacing the most suspicious activity, ranked by severity.

---

## Architecture

```
Raw .evtx Files
      ↓
Hayabusa CLI (forensics timeline generator)
      ↓
Merged CSV Dataset (13,962 events)
      ↓
┌─────────────────────────────────────┐
│           pipeline.py               │
│                                     │
│  Stage 1: Isolation Forest          │
│           (anomaly detection)       │
│                ↓                    │
│  Stage 2: DBSCAN                    │
│           (cluster anomalies)       │
│                ↓                    │
│  Stage 3: Random Forest             │
│           (severity classification) │
│                ↓                    │
│  Stage 4: SHAP                      │
│           (explainability)          │
└─────────────────────────────────────┘
      ↓
FastAPI Backend (port 8000)
      ↓
Plotly Dash Dashboard (port 8050)
```

---

## Tech Stack

| Component | Tool |
|-----------|------|
| Event log parsing | Hayabusa CLI |
| Data processing | pandas, numpy |
| Anomaly detection | Isolation Forest (scikit-learn) |
| Clustering | DBSCAN (scikit-learn) |
| Severity classification | Random Forest (scikit-learn) |
| Explainability | SHAP |
| Backend API | FastAPI + Uvicorn |
| Dashboard | Plotly Dash + dash-bootstrap-components |

---

## Prerequisites

- Python 3.10+
- Hayabusa binary ([download here](https://github.com/Yamato-Security/hayabusa/releases))
- Git

---

## Dataset Setup

This project uses three open-source Windows attack simulation datasets. Clone all three:

```bash
# Dataset 1 - EVTX Attack Samples
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

# Dataset 2 - EVTX to MITRE ATT&CK
git clone https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack

# Dataset 3 - Yamato Security samples
# Included in the hayabusa-sample-evtx repo
git clone https://github.com/Yamato-Security/hayabusa-sample-evtx
```

Place the Hayabusa binary in the project root directory.

---

## Installation

```bash
# Clone this repository
git clone 
cd 

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

**requirements.txt:**
```
pandas
numpy
scikit-learn
shap
matplotlib
fastapi
uvicorn
dash
dash-bootstrap-components
plotly
requests
pydantic
```

---

## Running the Pipeline

Run each step in order. Each step produces output files consumed by the next.

### Step 1 — Parse EVTX files with Hayabusa

```bash
# Run Hayabusa on each dataset
python hayabusa_runner.py --evtx ./EVTX-ATTACK-SAMPLES/ --hayabusa ./hayabusa --output ./output/evtx_attack_samples.csv
python hayabusa_runner.py --evtx ./EVTX-to-MITRE-Attack/ --hayabusa ./hayabusa --output ./output/evtx_mitre.csv
python hayabusa_runner.py --evtx ./hayabusa-sample-evtx/YamatoSecurity/ --hayabusa ./hayabusa --output ./output/yamato.csv
```

**Output:** Three CSV files in `./output/`

---

### Step 2 — Merge datasets

```bash
python merger.py
```

**Output:** `./output/final_dataset.csv` (13,962 events)

---

### Step 3 — Run ML pipeline

```bash
python pipeline.py
```

This runs all four ML stages:
- Isolation Forest anomaly detection
- DBSCAN clustering
- Random Forest severity classification  
- SHAP explainability

**Output:**
- `./output/enriched_dataset.csv`
- `./output/anomalies_only.csv`
- `./output/shap_summary.png`

---

### Step 4 — Start FastAPI backend

```bash
python main.py
```

Backend runs at `http://localhost:8000`  
Interactive API docs at `http://localhost:8000/docs`

---

### Step 5 — Launch dashboard

Open a new terminal:

```bash
python dashboard.py
```

Dashboard runs at `http://localhost:8050`

---

## Results

| Metric | Value |
|--------|-------|
| Total events analyzed | 13,962 |
| Anomalies detected | 4,825 |
| Anomaly rate | 34.6% |
| DBSCAN clusters found | 119 |
| Classifier accuracy | 76.9% |
| contamination parameter | 0.38 |

**Level distribution in dataset:**

| Level | Count |
|-------|-------|
| info (normal) | 8,627 |
| low | 1,781 |
| high | 1,778 |
| med | 1,735 |
| crit | 41 |

---

## Project Structure

```
project/
├── hayabusa_runner.py      # Hayabusa CLI wrapper
├── merger.py               # CSV merging script
├── pipeline.py             # Full ML pipeline (IF + DBSCAN + RF + SHAP)
├── main.py                 # FastAPI backend
├── dashboard.py            # Plotly Dash frontend
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── output/
    ├── evtx_attack_samples.csv   # Hayabusa output 1
    ├── evtx_mitre.csv            # Hayabusa output 2
    ├── yamato.csv                # Hayabusa output 3
    ├── final_dataset.csv         # Merged dataset
    ├── enriched_dataset.csv      # ML pipeline output
    ├── anomalies_only.csv        # Flagged anomalies only
    └── shap_summary.png          # SHAP feature importance plot
```
