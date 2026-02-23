import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import DBSCAN
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
import shap
import matplotlib.pyplot as plt
import os

def main():
    print("="*50)
    print("Anomaly Detection ML Pipeline")
    print("="*50)

    # Make output directory
    os.makedirs('./output', exist_ok=True)
    
    # =========================================================
    # Preprocessing
    # =========================================================
    print("\n[Preprocessing] Loading dataset...")
    df = pd.read_csv('./output/final_dataset.csv')
    df_original = df.copy()

    print("[Preprocessing] Parsing Timestamp to datetime...")
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    print("[Preprocessing] Extracting hour_of_day and day_of_week...")
    df['hour_of_day'] = df['Timestamp'].dt.hour
    df['day_of_week'] = df['Timestamp'].dt.dayofweek

    print("[Preprocessing] Computing time_delta...")
    # Sort values to confidently compute time deltas and ensure matching indexes
    df = df.sort_values(['Computer', 'Timestamp']).reset_index(drop=True)
    df_original = df_original.sort_values(['Computer', 'Timestamp']).reset_index(drop=True)

    df['time_delta'] = df.groupby('Computer')['Timestamp'].diff().dt.total_seconds().fillna(0)

    print("[Preprocessing] Computing event_frequency...")
    # Count of events per Computer per hour
    # We floor timestamp to the hour securely
    df['hour_floor'] = df['Timestamp'].dt.floor('h')
    freq_df = df.groupby(['Computer', 'hour_floor']).size().reset_index(name='event_frequency')
    df = pd.merge(df, freq_df, on=['Computer', 'hour_floor'], how='left')
    df.drop('hour_floor', axis=1, inplace=True)

    print("[Preprocessing] Frequency encoding EventID and Channel...")
    df['EventID'] = df['EventID'].map(df['EventID'].value_counts())
    df['Channel'] = df['Channel'].map(df['Channel'].value_counts())

    print("[Preprocessing] Filling missing values in MitreTactics, MitreTags, OtherTags...")
    for col in ['MitreTactics', 'MitreTags', 'OtherTags']:
        if col in df.columns:
            df[col] = df[col].fillna("none")

    print("[Preprocessing] Finalizing feature set...")
    # Final feature set list per instructions
    features = ['hour_of_day', 'day_of_week', 'time_delta', 'event_frequency', 'EventID', 'Channel']
    X = df[features].copy()

    # =========================================================
    # Stage 1 — Isolation Forest
    # =========================================================
    print("\n[Stage 1] Training Isolation Forest...")
    iso = IsolationForest(contamination=0.38, random_state=42, n_estimators=200)
    preds = iso.fit_predict(X)
    
    # Normalize raw scores to 0-1 range (higher = more anomalous)
    # decision_function yields negative for anomalies, positive for normal.
    # Therefore, -decision_function places anomalies higher.
    raw_scores = iso.decision_function(X)
    scaler = MinMaxScaler()
    anomaly_score = scaler.fit_transform((-raw_scores).reshape(-1, 1)).flatten()
    
    is_anomaly = (preds == -1)
    
    df_original['anomaly_score'] = anomaly_score
    df_original['is_anomaly'] = is_anomaly

    total_events = len(df_original)
    total_anomalies = is_anomaly.sum()
    print(f"Total anomalies detected: {total_anomalies}")
    
    # Detection rate vs known malicious events
    if 'Level' in df_original.columns:
        known_malicious = (df_original['Level'].str.lower() != 'info')
        actually_malicious_count = known_malicious.sum()
        if actually_malicious_count > 0:
            true_positives = (is_anomaly & known_malicious).sum()
            detection_rate = true_positives / actually_malicious_count
            print(f"Detection rate vs known malicious events: {detection_rate:.2%}")
        else:
            print("No known malicious events in dataset to compute detection rate.")

    # =========================================================
    # Stage 2 — DBSCAN on anomalies
    # =========================================================
    print("\n[Stage 2] Running DBSCAN on anomalies...")
    anomaly_indices = df_original.index[is_anomaly]
    X_anomalies = X.loc[anomaly_indices]

    dbscan = DBSCAN(eps=0.5, min_samples=5)
    df_original['cluster'] = np.nan
    
    num_clusters = 0
    if len(X_anomalies) > 0:
        cluster_labels = dbscan.fit_predict(X_anomalies)
        df_original.loc[anomaly_indices, 'cluster'] = cluster_labels
        
        unique_clusters = set(cluster_labels)
        if -1 in unique_clusters:
            unique_clusters.remove(-1) # -1 is noise/unclustered
        num_clusters = len(unique_clusters)
        
        print(f"Number of clusters found: {num_clusters}")
        # Size of each cluster
        cluster_counts = pd.Series(cluster_labels).value_counts()
        print("Size of each cluster (-1 = noise/unclustered):")
        for cluster_id, size in sorted(cluster_counts.items()):
            print(f"  Cluster {cluster_id}: {size}")
    else:
        print("No anomalies to cluster.")

    # =========================================================
    # Stage 3 — Random Forest severity classifier
    # =========================================================
    print("\n[Stage 3] Training Random Forest severity classifier...")
    acc = None
    if 'Level' in df_original.columns:
        severity_mask = df_original['Level'].str.lower() != 'info'
        X_sev = X[severity_mask]
        
        # Mapping for target variable
        mapping = {'low': 0, 'med': 1, 'high': 2, 'crit': 3}
        reverse_mapping = {0: 'low', 1: 'med', 2: 'high', 3: 'crit'}
        
        y_sev = df_original.loc[severity_mask, 'Level'].str.lower().map(mapping)
        
        valid_idx = y_sev.dropna().index
        X_sev = X_sev.loc[valid_idx]
        y_sev = y_sev.loc[valid_idx].astype(int)
        
        if len(X_sev) > 0:
            X_train, X_test, y_train, y_test = train_test_split(X_sev, y_sev, test_size=0.2, random_state=42)
            
            rf = RandomForestClassifier(random_state=42)
            rf.fit(X_train, y_train)
            
            y_pred = rf.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            target_names = [reverse_mapping[i] for i in sorted(y_test.unique())]
            
            print("Classification Report:")
            print(classification_report(y_test, y_pred, labels=sorted(y_test.unique()), target_names=target_names))
            print(f"Accuracy Score: {acc:.4f}")
            
            # Predict severity for all anomalies
            df_original['predicted_severity'] = None
            if len(X_anomalies) > 0:
                predictions = rf.predict(X_anomalies)
                df_original.loc[anomaly_indices, 'predicted_severity'] = pd.Series(predictions).map(reverse_mapping).values
        else:
            acc = "N/A"
            df_original['predicted_severity'] = None
            print("No valid severity examples to train the classifier.")
    else:
        acc = "N/A"
        print("No Level column found. Cannot train severity classifier.")

    # =========================================================
    # Stage 4 — SHAP explainability
    # =========================================================
    print("\n[Stage 4] Computing SHAP values...")
    # Explainer for Isolation Forest
    explainer = shap.TreeExplainer(iso)
    shap_values = explainer.shap_values(X)
    
    # Save SHAP summary plot
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_values, X, show=False)
    plt.savefig('./output/shap_summary.png', bbox_inches='tight')
    plt.close()
    print("Saved SHAP summary plot to ./output/shap_summary.png")
    
    # Extract topmost influential feature for each event
    feature_names = np.array(features)
    top_indices = np.argmax(np.abs(shap_values), axis=1)
    df_original['top_feature'] = feature_names[top_indices]

    # =========================================================
    # Output
    # =========================================================
    print("\n[Output] Saving output files...")
    df_original.to_csv('./output/enriched_dataset.csv', index=False)
    print("Saved full enriched DataFrame to ./output/enriched_dataset.csv")
    
    df_anomalies = df_original[df_original['is_anomaly']]
    df_anomalies.to_csv('./output/anomalies_only.csv', index=False)
    print("Saved only anomaly rows to ./output/anomalies_only.csv")
    
    print("\n==================================================")
    print("Final Summary")
    print("==================================================")
    print(f"Total events: {total_events}")
    print(f"Total anomalies: {total_anomalies}")
    print(f"Cluster count: {num_clusters}")
    print(f"Classifier accuracy: {acc if isinstance(acc, str) else f'{acc:.4f}'}")
    print("==================================================")

if __name__ == "__main__":
    main()
