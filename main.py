import math
import os
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any

import pandas as pd
import numpy as np
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
import uvicorn

# Global in-memory storage for DataFrames
class DataStore:
    df_all: pd.DataFrame = None
    df_anomalies: pd.DataFrame = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the datasets at startup
    print("Loading datasets into memory...")
    try:
        DataStore.df_all = pd.read_csv("./output/enriched_dataset.csv")
        # Ensure we handle nan values properly for JSON
        DataStore.df_all.replace({np.nan: None}, inplace=True)
        
        DataStore.df_anomalies = pd.read_csv("./output/anomalies_only.csv")
        DataStore.df_anomalies.replace({np.nan: None}, inplace=True)
        
        print(f"Loaded {len(DataStore.df_all)} total events and {len(DataStore.df_anomalies)} anomalies.")
    except Exception as e:
        print(f"Error loading datasets: {e}")
        # Not exiting right away so endpoints can still return empty but informative shapes if needed
    yield
    # Clean up at shutdown
    DataStore.df_all = None
    DataStore.df_anomalies = None

app = FastAPI(title="Automated Digital Forensics ML Dashboard API", lifespan=lifespan)

# Add CORS middleware to allow the Dash frontend (or any frontend) on localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# Pydantic v2 Models
# =====================================================================

class PaginationModel(BaseModel):
    page: int
    page_size: int
    total_count: int
    total_pages: int

class SummaryResponse(BaseModel):
    total_events: int
    total_anomalies: int
    anomaly_rate: float
    cluster_count: int
    classifier_accuracy: float
    severity_breakdown: Dict[str, int]
    level_distribution: Dict[str, int]

class PaginatedEventsResponse(BaseModel):
    data: List[Dict[str, Any]]
    pagination: PaginationModel
    
    model_config = ConfigDict(protected_namespaces=())

class TimelineEntry(BaseModel):
    hour: str
    all_count: int
    anomaly_count: int

class ClusterSummary(BaseModel):
    cluster_id: int
    size: int
    dominant_severity: Optional[str]
    top_channels: List[str]
    top_event_ids: List[int]
    sample_rules: List[str]

class ComputerSummary(BaseModel):
    computer: str
    anomaly_count: int
    top_severity: Optional[str]


# =====================================================================
# Helper Functions
# =====================================================================

def paginate_dataframe(df: pd.DataFrame, page: int, page_size: int):
    total_count = len(df)
    total_pages = math.ceil(total_count / page_size) if page_size > 0 else 0
    
    if page < 1:
        page = 1
        
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    paginated_data = df.iloc[start_idx:end_idx].to_dict(orient="records")
    
    pagination = PaginationModel(
        page=page,
        page_size=page_size,
        total_count=total_count,
        total_pages=total_pages
    )
    return paginated_data, pagination


# =====================================================================
# Endpoints
# =====================================================================

@app.get("/summary", response_model=SummaryResponse)
def get_summary():
    if DataStore.df_all is None or DataStore.df_anomalies is None:
        raise HTTPException(status_code=500, detail="Data not loaded")

    df_all = DataStore.df_all
    df_ano = DataStore.df_anomalies

    total_events = len(df_all)
    total_anomalies = len(df_ano)
    anomaly_rate = (total_anomalies / total_events * 100) if total_events > 0 else 0.0
    
    # Calculate unique clusters excluding -1 (noise)
    if 'cluster' in df_all.columns:
        valid_clusters = [c for c in df_all['cluster'].unique() if c is not None and c != -1]
        cluster_count = len(valid_clusters)
    else:
        cluster_count = 0

    # Severity breakdown among anomalies
    if 'predicted_severity' in df_ano.columns:
        sev_counts = df_ano['predicted_severity'].value_counts().to_dict()
        severity_breakdown = {k: int(v) for k, v in sev_counts.items() if k is not None}
    else:
        severity_breakdown = {}

    # Level distribution across all events
    if 'Level' in df_all.columns:
        level_counts = df_all['Level'].value_counts().to_dict()
        level_distribution = {k: int(v) for k, v in level_counts.items() if k is not None}
    else:
        level_distribution = {}

    return SummaryResponse(
        total_events=total_events,
        total_anomalies=total_anomalies,
        anomaly_rate=round(anomaly_rate, 2),
        cluster_count=cluster_count,
        classifier_accuracy=0.7694,  # Hardcoded per instructions
        severity_breakdown=severity_breakdown,
        level_distribution=level_distribution
    )


@app.get("/events", response_model=PaginatedEventsResponse)
def get_events(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=1000)):
    if DataStore.df_all is None:
        raise HTTPException(status_code=500, detail="Data not loaded")
    
    data, pagination = paginate_dataframe(DataStore.df_all, page, page_size)
    return PaginatedEventsResponse(data=data, pagination=pagination)


@app.get("/anomalies", response_model=PaginatedEventsResponse)
def get_anomalies(
    page: int = Query(1, ge=1), 
    page_size: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = None,
    cluster: Optional[int] = None
):
    if DataStore.df_anomalies is None:
        raise HTTPException(status_code=500, detail="Data not loaded")
    
    df = DataStore.df_anomalies.copy()
    
    # Apply filters
    if severity:
        if 'predicted_severity' in df.columns:
            df = df[df['predicted_severity'].str.lower() == severity.lower()]
    if cluster is not None:
        if 'cluster' in df.columns:
            df = df[df['cluster'] == cluster]
            
    # Sort by anomaly_score descending
    if 'anomaly_score' in df.columns:
        df = df.sort_values(by='anomaly_score', ascending=False)
        
    data, pagination = paginate_dataframe(df, page, page_size)
    return PaginatedEventsResponse(data=data, pagination=pagination)


@app.get("/timeline", response_model=List[TimelineEntry])
def get_timeline():
    if DataStore.df_all is None or DataStore.df_anomalies is None:
        raise HTTPException(status_code=500, detail="Data not loaded")
        
    df_all = DataStore.df_all.copy()
    df_ano = DataStore.df_anomalies.copy()
    
    if 'Timestamp' not in df_all.columns:
        return []
        
    df_all['Timestamp'] = pd.to_datetime(df_all['Timestamp'])
    df_all['hour_floor'] = df_all['Timestamp'].dt.floor('h')
    
    all_counts = df_all.groupby('hour_floor').size().reset_index(name='all_count')
    
    if len(df_ano) > 0 and 'Timestamp' in df_ano.columns:
        df_ano['Timestamp'] = pd.to_datetime(df_ano['Timestamp'])
        df_ano['hour_floor'] = df_ano['Timestamp'].dt.floor('h')
        ano_counts = df_ano.groupby('hour_floor').size().reset_index(name='anomaly_count')
    else:
        ano_counts = pd.DataFrame(columns=['hour_floor', 'anomaly_count'])
        
    merged = pd.merge(all_counts, ano_counts, on='hour_floor', how='left').fillna(0)
    merged['hour_floor'] = merged['hour_floor'].dt.strftime('%Y-%m-%d %H:00')
    
    result = []
    for _, row in merged.iterrows():
        result.append(TimelineEntry(
            hour=row['hour_floor'],
            all_count=int(row['all_count']),
            anomaly_count=int(row['anomaly_count'])
        ))
    
    return result


@app.get("/clusters", response_model=List[ClusterSummary])
def get_clusters():
    if DataStore.df_anomalies is None:
        raise HTTPException(status_code=500, detail="Data not loaded")
        
    df = DataStore.df_anomalies
    if 'cluster' not in df.columns:
        return []
        
    clusters = []
    unique_clusters = [c for c in df['cluster'].unique() if pd.notna(c) and c != -1]
    
    for c_id in sorted(unique_clusters):
        c_df = df[df['cluster'] == c_id]
        size = len(c_df)
        
        dominant_severity = None
        if 'predicted_severity' in c_df.columns:
            sev_counts = c_df['predicted_severity'].value_counts()
            if not sev_counts.empty:
                dominant_severity = sev_counts.idxmax()
                
        top_channels = []
        if 'Channel' in c_df.columns:
            top_channels = c_df['Channel'].value_counts().head(3).index.tolist()
            top_channels = [str(x) for x in top_channels]
            
        top_event_ids = []
        if 'EventID' in c_df.columns:
            top_event_ids = c_df['EventID'].value_counts().head(3).index.tolist()
            top_event_ids = [int(x) for x in top_event_ids]
            
        sample_rules = []
        if 'RuleTitle' in c_df.columns:
            sample_rules = c_df['RuleTitle'].dropna().unique()[:3].tolist()
            sample_rules = [str(x) for x in sample_rules]
            
        clusters.append(ClusterSummary(
            cluster_id=int(c_id),
            size=size,
            dominant_severity=dominant_severity,
            top_channels=top_channels,
            top_event_ids=top_event_ids,
            sample_rules=sample_rules
        ))
        
    return clusters


@app.get("/shap")
def get_shap():
    file_path = "./output/shap_summary.png"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="SHAP plot not found")
    return FileResponse(file_path, media_type="image/png")


@app.get("/computers", response_model=List[ComputerSummary])
def get_computers():
    if DataStore.df_all is None:
        raise HTTPException(status_code=500, detail="Data not loaded")
        
    df_all = DataStore.df_all
    if 'Computer' not in df_all.columns:
        return []
        
    computers = []
    for comp in df_all['Computer'].dropna().unique():
        c_df = df_all[df_all['Computer'] == comp]
        
        anomaly_count = 0
        if 'is_anomaly' in c_df.columns:
            anomaly_count = int(c_df['is_anomaly'].sum())
            
        top_severity = None
        if anomaly_count > 0 and 'predicted_severity' in c_df.columns:
            ano_c_df = c_df[c_df['is_anomaly'] == True]
            if not ano_c_df['predicted_severity'].dropna().empty:
                top_severity = ano_c_df['predicted_severity'].value_counts().idxmax()
                
        computers.append(ComputerSummary(
            computer=str(comp),
            anomaly_count=anomaly_count,
            top_severity=top_severity
        ))
        
    # Sort by anomaly count descending
    computers.sort(key=lambda x: x.anomaly_count, reverse=True)
    return computers


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
