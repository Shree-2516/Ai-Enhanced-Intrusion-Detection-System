import pandas as pd
import plotly.express as px
import plotly.io as pio
from db.models import TrafficRecord

# Configure standard dark theme overrides
pio.templates.default = "plotly_dark"

def get_charts_data(db) -> dict:
    """
    Queries database logs and generates interactive dark-themed Plotly charts as data dicts
    for React-style dynamic rendering in the frontend:
    - Pie Chart: Attack Distribution (all classes)
    - Bar Chart: Threat Counts (only malicious classes)
    - Line Chart: Threat Trend over time
    """
    try:
        # Query logs
        records = db.query(
            TrafficRecord.predicted_class, 
            TrafficRecord.is_anomaly, 
            TrafficRecord.timestamp
        ).all()
        
        if not records:
            return {}
            
        df = pd.DataFrame(records, columns=["predicted_class", "is_anomaly", "timestamp"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        
        # Color mapping corresponding to CSS variables
        color_map = {
            "Benign": "#10b981",       # Success Green
            "DDoS Attack": "#ef4444",  # Danger Red
            "Port Scan": "#f59e0b",    # Warning Yellow
            "Botnet": "#ec4899",       # Critical Pink
            "Brute Force": "#a855f7",  # Purple
            "Web Attack": "#06b6d4"    # Cyan
        }
        
        # 1. Pie Chart: Attack Distribution
        dist = df["predicted_class"].value_counts().reset_index(name="Count")
        dist.columns = ["Class", "Count"]
        
        fig_pie = px.pie(
            dist,
            values="Count",
            names="Class",
            hole=0.4,
            color="Class",
            color_discrete_map=color_map
        )
        fig_pie.update_traces(
            textposition="inside",
            textinfo="percent+label",
            marker=dict(line=dict(color="#111827", width=2))
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f3f4f6", family="Outfit, sans-serif", size=11),
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
            margin=dict(t=10, b=50, l=10, r=10),
            height=280
        )
        
        # 2. Bar Chart: Threat Counts (Anomaly classes only)
        threats_df = df[df["is_anomaly"] == 1]
        if not threats_df.empty:
            threats_counts = threats_df["predicted_class"].value_counts().reset_index(name="Count")
            threats_counts.columns = ["Attack Type", "Count"]
        else:
            threats_counts = pd.DataFrame(columns=["Attack Type", "Count"])
            
        fig_bar = px.bar(
            threats_counts,
            x="Count",
            y="Attack Type",
            orientation="h",
            color="Attack Type",
            color_discrete_map=color_map,
            category_orders={"Attack Type": ["Web Attack", "Botnet", "Brute Force", "Port Scan", "DDoS Attack"]}
        )
        fig_bar.update_traces(
            marker=dict(line=dict(color="#111827", width=1))
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f3f4f6", family="Outfit, sans-serif", size=11),
            showlegend=False,
            xaxis=dict(
                showgrid=True, 
                gridcolor="rgba(75, 85, 99, 0.15)", 
                title=dict(text="Occurrences", font=dict(size=10))
            ),
            yaxis=dict(title=None),
            margin=dict(t=10, b=20, l=10, r=10),
            height=280
        )
        
        # 3. Line Chart: Threat Trend over time (anomaly = 1)
        if not threats_df.empty:
            df_line = threats_df.copy()
            # Floor to minutes or 5 minutes based on range of data
            time_range = df_line["timestamp"].max() - df_line["timestamp"].min()
            
            if time_range.total_seconds() > 3600 * 24:
                df_line["time_bin"] = df_line["timestamp"].dt.floor("1h")
                x_title = "Hour"
            else:
                df_line["time_bin"] = df_line["timestamp"].dt.floor("5min")
                x_title = "Time (5-min Bins)"
                
            trend = df_line.groupby("time_bin").size().reset_index(name="Threats Count")
            trend = trend.sort_values("time_bin")
        else:
            trend = pd.DataFrame(columns=["time_bin", "Threats Count"])
            x_title = "Time"
            
        fig_line = px.line(
            trend,
            x="time_bin",
            y="Threats Count"
        )
        fig_line.update_traces(
            line=dict(color="#ef4444", width=3),
            mode="lines+markers",
            marker=dict(size=5, color="#ec4899", line=dict(color="#111827", width=1))
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f3f4f6", family="Outfit, sans-serif", size=11),
            xaxis=dict(
                showgrid=True, 
                gridcolor="rgba(75, 85, 99, 0.15)", 
                title=dict(text=x_title, font=dict(size=10))
            ),
            yaxis=dict(
                showgrid=True, 
                gridcolor="rgba(75, 85, 99, 0.15)", 
                title=dict(text="Alert Counts", font=dict(size=10))
            ),
            margin=dict(t=20, b=20, l=20, r=20),
            height=280
        )
        
        # Return JSON serialization
        import json
        return {
            "pie_chart": json.loads(fig_pie.to_json()),
            "bar_chart": json.loads(fig_bar.to_json()),
            "line_chart": json.loads(fig_line.to_json())
        }
    except Exception as e:
        print(f"Error in charts data generation: {e}")
        return {}
