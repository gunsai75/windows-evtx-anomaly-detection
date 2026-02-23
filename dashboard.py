import base64
import json
import requests
import pandas as pd
import dash
from dash import dcc, html, dash_table, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go

API_BASE = "http://localhost:8000"

# ==============================================================================
# Helper functions for API calls
# ==============================================================================
def fetch_api(endpoint, params=None):
    try:
        response = requests.get(f"{API_BASE}/{endpoint}", params=params, timeout=5)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)

def fetch_image(endpoint):
    try:
        response = requests.get(f"{API_BASE}/{endpoint}", timeout=5)
        response.raise_for_status()
        return base64.b64encode(response.content).decode('utf-8'), None
    except requests.exceptions.RequestException as e:
        return None, str(e)

# Initialize data to build the layout components
summary_data, error_msg = fetch_api("summary")
cluster_data, _ = fetch_api("clusters") if not error_msg else ([], None)

if error_msg:
    print(f"Warning: Could not connect to API at startup: {error_msg}")
    summary_data = {
        "total_events": 0, "total_anomalies": 0, "anomaly_rate": 0,
        "cluster_count": 0, "classifier_accuracy": 0,
        "severity_breakdown": {}, "level_distribution": {}
    }

# Setup the Dash app with Darkly theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

# Option sets for dropdowns
cluster_options = [{"label": f"Cluster {c['cluster_id']}", "value": c['cluster_id']} for c in cluster_data]
severity_options = [
    {"label": "Critical", "value": "crit"},
    {"label": "High", "value": "high"},
    {"label": "Medium", "value": "med"},
    {"label": "Low", "value": "low"}
]

# Color palettes
SEVERITY_COLORS = {
    "low": "yellow",
    "med": "orange",
    "high": "red",
    "crit": "darkred"
}

# ==============================================================================
# Layout UI Components
# ==============================================================================

# Navbar
navbar = dbc.NavbarSimple(
    brand="Digital Forensics Anomaly Dashboard",
    brand_style={"fontSize": "24px", "fontWeight": "bold"},
    color="dark",
    dark=True,
    children=[
        dbc.NavItem(dbc.NavLink("Powered by Isolation Forest + DBSCAN + Random Forest", disabled=True))
    ],
    fluid=True,
    className="mb-4 border-bottom border-secondary"
)

# --- Section 1: Top Stats Bar ---
def create_stat_card(title, value, border_color):
    return dbc.Card(
        dbc.CardBody([
            html.H6(title, className="card-title text-muted mb-1"),
            html.H3(value, className="card-text fw-bold")
        ]),
        className=f"border-{border_color} border-2 mb-3",
        style={"backgroundColor": "#222222"}
    )

stats_row = dbc.Row([
    dbc.Col(create_stat_card("Total Events", f"{summary_data.get('total_events', 0):,}", "primary"), width=12, md=True), # blue (primary)
    dbc.Col(create_stat_card("Total Anomalies", f"{summary_data.get('total_anomalies', 0):,}", "danger"), width=12, md=True), # red (danger)
    dbc.Col(create_stat_card("Anomaly Rate", f"{summary_data.get('anomaly_rate', 0)}%", "warning"), width=12, md=True), # orange (warning)
    dbc.Col(create_stat_card("Cluster Count", f"{summary_data.get('cluster_count', 0)}", "success"), width=12, md=True), # green (success)
    dbc.Col(create_stat_card("Classifier Accuracy", f"{summary_data.get('classifier_accuracy', 0)*100:.2f}%", "info"), width=12, md=True), # purple approximation (info/teal)
], className="mb-4")


# --- Section 2: Timeline Chart ---
timeline_section = dbc.Card([
    dbc.CardHeader(html.H5("Events Timeline", className="mb-0")),
    dbc.CardBody([
        dcc.Loading(
            dcc.Graph(id="timeline-chart", style={"height": "400px"}),
            type="dot"
        )
    ])
], className="mb-4")


# --- Section 3: Severity Donut & Top Computers Bar Chart ---
donut_computer_row = dbc.Row([
    dbc.Col(
        dbc.Card([
            dbc.CardHeader(html.H5("Anomaly Severity Breakdown", className="mb-0")),
            dbc.CardBody([
                dcc.Loading(dcc.Graph(id="severity-donut"), type="dot")
            ])
        ]), 
        width=12, lg=5, className="mb-4 mb-lg-0"
    ),
    dbc.Col(
        dbc.Card([
            dbc.CardHeader(html.H5("Top 10 Computers by Anomalies", className="mb-0")),
            dbc.CardBody([
                dcc.Loading(dcc.Graph(id="computers-bar"), type="dot")
            ])
        ]), 
        width=12, lg=7
    )
], className="mb-4")


# --- Section 4: Cluster Explorer ---
cluster_explorer = dbc.Card([
    dbc.CardHeader(html.H5("Cluster Explorer", className="mb-0")),
    dbc.CardBody([
        dbc.Row([
            dbc.Col([
                html.Label("Select a Cluster ID:"),
                dcc.Dropdown(
                    id="cluster-dropdown",
                    options=cluster_options,
                    placeholder="Select a cluster to view details...",
                    className="mb-3 text-dark", # text-dark fixes dropdown text color in darkly theme
                )
            ], width=12, md=4)
        ]),
        html.Div(id="cluster-details-container")
    ])
], className="mb-4")


# --- Section 5: Anomaly Event Table ---
table_section = dbc.Card([
    dbc.CardHeader(
        dbc.Row([
            dbc.Col(html.H5("Anomaly Events Explorer", className="mb-0"), width="auto"),
            dbc.Col(dbc.Button("Download CSV", id="btn-download-csv", color="success", size="sm", className="ms-auto"), width="auto")
        ], align="center")
    ),
    dbc.CardBody([
        dbc.Row([
            dbc.Col([
                dcc.Dropdown(
                    id="table-severity-filter",
                    options=severity_options,
                    placeholder="Filter by Severity...",
                    className="mb-3 text-dark",
                    clearable=True
                )
            ], width=12, md=3),
            dbc.Col([
                dcc.Dropdown(
                    id="table-cluster-filter",
                    options=cluster_options,
                    placeholder="Filter by Cluster ID...",
                    className="mb-3 text-dark",
                    clearable=True
                )
            ], width=12, md=3),
        ]),
        dcc.Loading(
            dash_table.DataTable(
                id="anomaly-table",
                columns=[
                    {"name": "Timestamp", "id": "Timestamp"},
                    {"name": "Computer", "id": "Computer"},
                    {"name": "Channel", "id": "Channel"},
                    {"name": "EventID", "id": "EventID"},
                    {"name": "RuleTitle", "id": "RuleTitle"},
                    {"name": "Anomaly Score", "id": "anomaly_score"},
                    {"name": "Severity", "id": "predicted_severity"},
                    {"name": "Cluster", "id": "cluster"}
                ],
                page_current=0,
                page_size=20,
                page_action='custom',
                style_table={'overflowX': 'auto'},
                style_header={
                    'backgroundColor': '#333',
                    'color': 'white',
                    'fontWeight': 'bold'
                },
                style_cell={
                    'backgroundColor': '#222',
                    'color': '#ddd',
                    'textAlign': 'left',
                    'padding': '10px'
                },
                style_data_conditional=[
                    {'if': {'filter_query': '{predicted_severity} = "crit"'}, 'color': SEVERITY_COLORS['crit'], 'fontWeight': 'bold'},
                    {'if': {'filter_query': '{predicted_severity} = "high"'}, 'color': SEVERITY_COLORS['high'], 'fontWeight': 'bold'},
                    {'if': {'filter_query': '{predicted_severity} = "med"'}, 'color': SEVERITY_COLORS['med'], 'fontWeight': 'bold'},
                    {'if': {'filter_query': '{predicted_severity} = "low"'}, 'color': SEVERITY_COLORS['low'], 'fontWeight': 'bold'},
                ]
            ),
            type="dot"
        ),
        dcc.Download(id="download-dataframe-csv")
    ])
], className="mb-4")


# --- Section 6: SHAP Explainability ---
shap_section = dbc.Card([
    dbc.CardHeader(html.H5("Feature Importance (SHAP)", className="mb-0")),
    dbc.CardBody([
        dcc.Loading(
            html.Div(id="shap-image-container", className="text-center"),
            type="dot"
        ),
        html.P(
            "This chart shows which features contributed most to anomaly detection. Higher SHAP values indicate stronger influence on the model's decision.",
            className="text-muted text-center mt-3 mb-0"
        )
    ])
], className="mb-4")

# Main Container
app.layout = dbc.Container([
    navbar,
    html.Div(id="api-error-alert"),
    stats_row,
    timeline_section,
    donut_computer_row,
    cluster_explorer,
    table_section,
    shap_section
], fluid=True, className="pb-5")

# ==============================================================================
# Callbacks
# ==============================================================================

@app.callback(
    Output("api-error-alert", "children"),
    Input("timeline-chart", "id") # dummy trigger on load
)
def check_api_status(_):
    _, err = fetch_api("summary")
    if err:
        return dbc.Alert(f"API Connection Error: {err}. Please ensure the FastAPI backend is running on {API_BASE}.", color="danger", className="mb-4")
    return None

@app.callback(
    Output("timeline-chart", "figure"),
    Input("timeline-chart", "id")
)
def update_timeline(_):
    data, err = fetch_api("timeline")
    if err or not data:
        return go.Figure().update_layout(template="plotly_dark", title="No timeline data available")
        
    df = pd.DataFrame(data)
    fig = go.Figure()
    
    # All Events (Blue)
    fig.add_trace(go.Scatter(x=df['hour'], y=df['all_count'], mode='lines', name='All Events', line=dict(color='blue')))
    # Anomalies (Red)
    fig.add_trace(go.Scatter(x=df['hour'], y=df['anomaly_count'], mode='lines', name='Anomalies', line=dict(color='red')))
    
    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(title="Time (Hourly)", rangeslider=dict(visible=True)),
        yaxis=dict(title="Event Count"),
        margin=dict(l=40, r=40, t=20, b=40),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    return fig

@app.callback(
    Output("severity-donut", "figure"),
    Input("severity-donut", "id")
)
def update_donut(_):
    data, err = fetch_api("summary")
    if err or not data or not data.get("severity_breakdown"):
        return go.Figure().update_layout(template="plotly_dark", title="No severity data")
        
    sev_data = data["severity_breakdown"]
    labels = list(sev_data.keys())
    values = list(sev_data.values())
    colors = [SEVERITY_COLORS.get(l, "gray") for l in labels]
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.5, marker_colors=colors)])
    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20, r=20, t=20, b=20)
    )
    return fig

@app.callback(
    Output("computers-bar", "figure"),
    Input("computers-bar", "id")
)
def update_computers_bar(_):
    data, err = fetch_api("computers")
    if err or not data:
        return go.Figure().update_layout(template="plotly_dark", title="No computer data available")
        
    # Top 10 only
    df = pd.DataFrame(data[:10])
    # Reverse so top is at the top of horizontal chart
    df = df.iloc[::-1]
    
    colors = [SEVERITY_COLORS.get(sev, "gray") for sev in df['top_severity']]
    
    fig = go.Figure(go.Bar(
        x=df['anomaly_count'],
        y=df['computer'],
        orientation='h',
        marker_color=colors,
        text=df['anomaly_count'],
        textposition='auto'
    ))
    
    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        xaxis_title="Anomaly Count",
        yaxis_title=None,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    return fig

@app.callback(
    Output("cluster-details-container", "children"),
    Input("cluster-dropdown", "value")
)
def update_cluster_details(cluster_id):
    if cluster_id is None:
        return html.Div("Select a cluster from the dropdown to view details.", className="text-muted")
        
    data, err = fetch_api("clusters")
    if err or not data:
        return html.Div("Failed to fetch cluster data.", className="text-danger")
        
    cluster_info = next((c for c in data if c['cluster_id'] == cluster_id), None)
    if not cluster_info:
        return html.Div("Cluster details not found.")
        
    dom_sev = cluster_info.get("dominant_severity", "N/A")
    sev_color = SEVERITY_COLORS.get(dom_sev, "secondary")
    
    return dbc.Row([
        dbc.Col([
            html.H6("Size", className="text-muted mb-1"),
            html.H4(cluster_info['size'])
        ], width=6, md=2),
        dbc.Col([
            html.H6("Dominant Severity", className="text-muted mb-1"),
            html.H4(dbc.Badge(dom_sev.upper(), color=sev_color)) if dom_sev != "N/A" else html.H4("N/A")
        ], width=6, md=3),
        dbc.Col([
            html.H6("Top Channels", className="text-muted mb-1"),
            html.Ul([html.Li(c) for c in cluster_info['top_channels']])
        ], width=12, md=3),
        dbc.Col([
            html.H6("Top Event IDs", className="text-muted mb-1"),
            html.Ul([html.Li(e) for e in cluster_info['top_event_ids']])
        ], width=12, md=4),
        dbc.Col([
            html.H6("Sample Rules Triggered", className="text-muted mb-1 mt-3"),
            html.Ul([html.Li(r) for r in cluster_info['sample_rules']])
        ], width=12)
    ])

@app.callback(
    Output("anomaly-table", "data"),
    Input("anomaly-table", "page_current"),
    Input("anomaly-table", "page_size"),
    Input("table-severity-filter", "value"),
    Input("table-cluster-filter", "value")
)
def update_table(page_current, page_size, severity, cluster):
    params = {
        "page": page_current + 1, # Dash is 0-indexed, API is 1-indexed
        "page_size": page_size
    }
    if severity: params["severity"] = severity
    if cluster is not None: params["cluster"] = cluster
    
    data, err = fetch_api("anomalies", params)
    if err or not data:
        return []
    
    return data.get("data", [])

@app.callback(
    Output("download-dataframe-csv", "data"),
    Input("btn-download-csv", "n_clicks"),
    State("table-severity-filter", "value"),
    State("table-cluster-filter", "value"),
    prevent_initial_call=True
)
def download_csv(n_clicks, severity, cluster):
    # Fetch all data for the filter (use a large page size)
    params = {"page": 1, "page_size": 100000}
    if severity: params["severity"] = severity
    if cluster is not None: params["cluster"] = cluster
    
    data, err = fetch_api("anomalies", params)
    if err or not data or not data.get("data"):
        return dash.no_update
        
    df = pd.DataFrame(data["data"])
    return dcc.send_data_frame(df.to_csv, "filtered_anomalies.csv", index=False)

@app.callback(
    Output("shap-image-container", "children"),
    Input("shap-image-container", "id")
)
def load_shap_image(_):
    img_b64, err = fetch_image("shap")
    if err or not img_b64:
        return html.Div(f"Failed to load SHAP image: {err}", className="text-danger")
        
    return html.Img(src=f"data:image/png;base64,{img_b64}", style={"maxWidth": "100%", "height": "auto", "borderRadius": "8px"})


if __name__ == "__main__":
    app.run(debug=True, port=8050)
