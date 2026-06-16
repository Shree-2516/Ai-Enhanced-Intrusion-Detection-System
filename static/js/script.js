async function fetchStats() {
    try {
        const response = await fetch('/dashboard-stats');
        const data = await response.json();
        
        if (data.error) {
            console.error("Error fetching stats:", data.error);
            return;
        }

        // Update metric cards
        document.getElementById('stat-total-scanned').innerText = Number(data.total_records).toLocaleString();
        document.getElementById('stat-threats').innerText = Number(data.threats).toLocaleString();
        document.getElementById('stat-safe').innerText = Number(data.safe).toLocaleString();
        document.getElementById('stat-accuracy').innerText = data.accuracy + "%";
        
        if (document.getElementById('stat-precision')) {
            document.getElementById('stat-precision').innerText = data.precision + "%";
        }
        if (document.getElementById('stat-recall')) {
            document.getElementById('stat-recall').innerText = data.recall + "%";
        }
        if (document.getElementById('stat-f1')) {
            document.getElementById('stat-f1').innerText = data.f1_score + "%";
        }

        // Update threat distribution chart (custom bar chart)
        updateChart(data.threat_distribution);

        // Update Recent Alerts Table
        updateAlertsTable(data.recent_alerts);

        // Render dynamic interactive Plotly charts
        if (data.charts && Object.keys(data.charts).length > 0) {
            Plotly.react('plotly-pie-chart', data.charts.pie_chart.data, data.charts.pie_chart.layout, {responsive: true, displayModeBar: false});
            Plotly.react('plotly-bar-chart', data.charts.bar_chart.data, data.charts.bar_chart.layout, {responsive: true, displayModeBar: false});
            Plotly.react('plotly-line-chart', data.charts.line_chart.data, data.charts.line_chart.layout, {responsive: true, displayModeBar: false});
        }
    } catch (err) {
        console.error("Failed to load dashboard statistics:", err);
    }
}

function updateChart(dist) {
    const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
    
    const classes = [
        { key: 'Benign', class: 'benign', fillId: 'fill-benign', valId: 'val-benign' },
        { key: 'DDoS Attack', class: 'ddos', fillId: 'fill-ddos', valId: 'val-ddos' },
        { key: 'Port Scan', class: 'port', fillId: 'fill-port', valId: 'val-port' },
        { key: 'Botnet', class: 'botnet', fillId: 'fill-botnet', valId: 'val-botnet' },
        { key: 'Brute Force', class: 'brute', fillId: 'fill-brute', valId: 'val-brute' },
        { key: 'Web Attack', class: 'web', fillId: 'fill-web', valId: 'val-web' }
    ];

    classes.forEach(c => {
        const count = dist[c.key] || 0;
        const pct = ((count / total) * 100).toFixed(1);
        
        const fillEl = document.getElementById(c.fillId);
        const valEl = document.getElementById(c.valId);
        
        if (fillEl) fillEl.style.width = `${pct}%`;
        if (valEl) valEl.innerText = `${count.toLocaleString()} (${pct}%)`;
    });
}

function updateAlertsTable(alerts) {
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;

    if (alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-secondary);">No alerts logged in the database.</td></tr>`;
        return;
    }

    let html = "";
    alerts.forEach(alert => {
        let badgeClass = "badge-benign";
        if (alert.severity === "CRITICAL") badgeClass = "badge-critical";
        else if (alert.severity === "HIGH") badgeClass = "badge-high";
        else if (alert.severity === "MEDIUM") badgeClass = "badge-medium";
        else if (alert.severity === "LOW") badgeClass = "badge-benign";

        html += `
            <tr>
                <td><span class="badge ${badgeClass}">${alert.severity}</span></td>
                <td style="font-weight: 500;">${alert.attack_type}</td>
                <td style="font-family: monospace;">${alert.source_ip}</td>
                <td style="font-family: monospace;">${alert.destination_ip}</td>
                <td style="font-weight: 600; color: ${alert.severity === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-danger)'};">${alert.confidence_score}%</td>
                <td style="color: var(--text-secondary);">${alert.detection_time}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

async function triggerScan() {
    const scanBtn = document.getElementById('scan-btn');
    const feed = document.getElementById('scan-feed');
    
    // Disable button & clear previous feed
    scanBtn.disabled = true;
    feed.innerHTML = `<div class="feed-line" style="color:var(--color-primary);"><span class="feed-time">[SYS]</span> Initializing Network Traffic Scan...</div>`;
    
    try {
        const response = await fetch('/predict');
        const data = await response.json();
        
        if (data.error) {
            feed.innerHTML += `<div class="feed-line" style="color:var(--color-danger);"><span class="feed-time">[ERR]</span> Scan Failed: ${data.error}</div>`;
            scanBtn.disabled = false;
            return;
        }
        
        feed.innerHTML += `<div class="feed-line" style="color:var(--color-primary);"><span class="feed-time">[SYS]</span> Scanning batch of ${data.scanned_count} active traffic channels...</div>`;
        
        // Dynamic simulated line-by-line feed rendering
        let i = 0;
        const interval = setInterval(() => {
            if (i < data.results.length) {
                const item = data.results[i];
                const now = new Date().toLocaleTimeString();
                const isAnomaly = item.is_anomaly === 1;
                
                const logLine = document.createElement('div');
                logLine.className = 'feed-line';
                
                const timeSpan = document.createElement('span');
                timeSpan.className = 'feed-time';
                timeSpan.innerText = `[${now}]`;
                
                const detailSpan = document.createElement('span');
                detailSpan.innerText = `SRC: ${item.source_ip} ➔ DST: ${item.destination_ip}:${item.destination_port} | PROTO: ${item.protocol} | `;
                
                const classSpan = document.createElement('span');
                classSpan.className = `feed-class ${isAnomaly ? 'threat' : 'safe'}`;
                classSpan.innerText = isAnomaly ? `${item.predicted_class} DETECTED (${item.confidence_score}%)` : `Benign (Safe)`;
                
                logLine.appendChild(timeSpan);
                logLine.appendChild(detailSpan);
                logLine.appendChild(classSpan);
                
                feed.appendChild(logLine);
                feed.scrollTop = feed.scrollHeight;
                i++;
            } else {
                clearInterval(interval);
                feed.innerHTML += `<div class="feed-line" style="color:var(--color-success); font-weight:600;"><span class="feed-time">[SYS]</span> Traffic Scan Completed successfully! ${data.threats_count} threats mitigated.</div>`;
                feed.scrollTop = feed.scrollHeight;
                scanBtn.disabled = false;
                
                // Refresh statistics and charts
                fetchStats();
            }
        }, 60);

    } catch (err) {
        feed.innerHTML += `<div class="feed-line" style="color:var(--color-danger);"><span class="feed-time">[ERR]</span> Failed to execute prediction scan.</div>`;
        scanBtn.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    fetchStats();
});