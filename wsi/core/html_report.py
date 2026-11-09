"""Self-contained interactive HTML report generator for WSI (read-only).

Generates a modern, single-file dashboard with live search, filtering,
and diagnostic drilldowns. Completely offline (zero CDNs or external assets).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from wsi.core.base import AnalysisResult, CollectorResult


def generate_html_report(
    collector_results: dict[str, CollectorResult],
    analysis_results: dict[str, AnalysisResult],
) -> str:
    """Generate a single-file interactive HTML dashboard."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Aggregate counts
    total_apps = len(collector_results.get("installed_apps", CollectorResult("")).data)
    total_services = len(collector_results.get("services", CollectorResult("")).data)
    total_startup = len(collector_results.get("startup", CollectorResult("")).data)

    all_findings = []
    for an in analysis_results.values():
        all_findings.extend(an.findings)

    crit_count = sum(1 for f in all_findings if f.severity == "critical")
    warn_count = sum(1 for f in all_findings if f.severity == "warning")
    info_count = sum(1 for f in all_findings if f.severity == "info")

    sys_data = (
        collector_results.get("system_info", CollectorResult("")).data[0]
        if collector_results.get("system_info", CollectorResult("")).data
        else {}
    )
    os_info = sys_data.get("os", {})
    hw_info = sys_data.get("hardware", {})
    ident = sys_data.get("identity", {})

    storage_data = (
        collector_results.get("storage", CollectorResult("")).data[0]
        if collector_results.get("storage", CollectorResult("")).data
        else {}
    )

    network_data = (
        collector_results.get("network_surface", CollectorResult("")).data[0]
        if collector_results.get("network_surface", CollectorResult("")).data
        else {}
    )

    # Prepare JSON payloads for interactive client tables
    apps_json = json.dumps(collector_results.get("installed_apps", CollectorResult("")).data)
    services_json = json.dumps(collector_results.get("services", CollectorResult("")).data)
    startup_json = json.dumps(collector_results.get("startup", CollectorResult("")).data)
    storage_json = json.dumps(storage_data.get("logical_disks", []))
    events_json = json.dumps(collector_results.get("event_logs", CollectorResult("")).data)
    network_json = json.dumps(network_data)

    findings_json = json.dumps([f.to_dict() for f in all_findings])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Windows System Intelligence — Report</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface-hover: #334155;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --crit: #ef4444;
    --warn: #f59e0b;
    --info: #3b82f6;
    --success: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
  h1 {{ font-size: 1.75rem; font-weight: 700; color: var(--accent); }}
  .timestamp {{ color: var(--text-muted); font-size: 0.875rem; }}
  
  /* Metric cards */
  .grid-metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
  .card-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}
  .card-val {{ font-size: 1.5rem; font-weight: 700; margin-top: 4px; }}
  .badge-crit {{ color: var(--crit); }}
  .badge-warn {{ color: var(--warn); }}
  .badge-info {{ color: var(--info); }}
  
  /* Tabs */
  .tabs {{ display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
  .tab-btn {{ background: none; border: none; color: var(--text-muted); padding: 10px 16px; cursor: pointer; font-size: 0.95rem; font-weight: 500; border-bottom: 2px solid transparent; }}
  .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}

  /* Filter bar */
  .filter-bar {{ display: flex; gap: 12px; margin-bottom: 16px; }}
  .search-input {{ background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 6px; flex: 1; font-size: 0.9rem; }}
  .search-input:focus {{ outline: 1px solid var(--accent); }}

  /* Findings list */
  .finding-item {{ background: var(--surface); border-left: 4px solid var(--border); padding: 14px 18px; border-radius: 0 6px 6px 0; margin-bottom: 12px; }}
  .finding-item.critical {{ border-left-color: var(--crit); }}
  .finding-item.warning {{ border-left-color: var(--warn); }}
  .finding-item.info {{ border-left-color: var(--info); }}
  .finding-title {{ font-weight: 600; font-size: 1rem; display: flex; justify-content: space-between; }}
  .finding-desc {{ color: var(--text-muted); font-size: 0.875rem; margin-top: 4px; }}
  .finding-rec {{ background: rgba(56, 189, 248, 0.08); border-radius: 4px; padding: 6px 10px; margin-top: 8px; font-size: 0.85rem; color: var(--accent); }}

  /* Table styling */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; text-align: left; }}
  th {{ background: var(--surface); color: var(--text-muted); padding: 10px 14px; font-weight: 600; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--surface-hover); }}
  .table-wrapper {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Windows System Intelligence</h1>
      <div class="timestamp">Generated: {now} | Target: {ident.get('computer_name', 'PC')} ({ident.get('username', '')})</div>
    </div>
    <div style="text-align: right;">
      <span style="font-size: 0.8rem; background: rgba(16,185,129,0.15); color: var(--success); padding: 4px 10px; border-radius: 12px; font-weight: 600;">READ-ONLY VALIDATED</span>
    </div>
  </header>

  <div class="grid-metrics">
    <div class="card">
      <div class="card-label">Diagnostic Findings</div>
      <div class="card-val"><span class="badge-crit">{crit_count}</span> / <span class="badge-warn">{warn_count}</span> / <span class="badge-info">{info_count}</span></div>
    </div>
    <div class="card">
      <div class="card-label">Operating System</div>
      <div class="card-val" style="font-size: 1.1rem; padding-top: 6px;">{os_info.get('caption', 'Windows')}</div>
    </div>
    <div class="card">
      <div class="card-label">Hardware Profile</div>
      <div class="card-val" style="font-size: 1.1rem; padding-top: 6px;">{hw_info.get('memory_total_gb', '?')} GB RAM</div>
    </div>
    <div class="card">
      <div class="card-label">Installed Applications</div>
      <div class="card-val">{total_apps}</div>
    </div>
    <div class="card">
      <div class="card-label">Active Services & Drivers</div>
      <div class="card-val">{total_services}</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="openTab('findings')">Diagnostics ({len(all_findings)})</button>
    <button class="tab-btn" onclick="openTab('storage')">Storage</button>
    <button class="tab-btn" onclick="openTab('apps')">Applications ({total_apps})</button>
    <button class="tab-btn" onclick="openTab('services')">Services & Drivers</button>
    <button class="tab-btn" onclick="openTab('startup')">Startup ({total_startup})</button>
    <button class="tab-btn" onclick="openTab('events')">Event Logs</button>
    <button class="tab-btn" onclick="openTab('network')">Network Surface</button>
  </div>

  <!-- Findings Tab -->
  <div id="findings" class="tab-panel active">
    <div id="findings-list"></div>
  </div>

  <!-- Storage Tab -->
  <div id="storage" class="tab-panel">
    <div class="table-wrapper">
      <table id="storage-table">
        <thead><tr><th>Drive</th><th>Label</th><th>File System</th><th>Total (GB)</th><th>Free (GB)</th><th>Usage</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Apps Tab -->
  <div id="apps" class="tab-panel">
    <div class="filter-bar">
      <input type="text" id="apps-search" class="search-input" placeholder="Filter installed applications by name, publisher, or version..." oninput="renderApps()">
    </div>
    <div class="table-wrapper">
      <table id="apps-table">
        <thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Source</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Services Tab -->
  <div id="services" class="tab-panel">
    <div class="filter-bar">
      <input type="text" id="services-search" class="search-input" placeholder="Filter services and drivers by name, state, or start mode..." oninput="renderServices()">
    </div>
    <div class="table-wrapper">
      <table id="services-table">
        <thead><tr><th>Category</th><th>Name</th><th>Display Name</th><th>State</th><th>Start Mode</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Startup Tab -->
  <div id="startup" class="tab-panel">
    <div class="table-wrapper">
      <table id="startup-table">
        <thead><tr><th>Name</th><th>Source</th><th>Scope</th><th>Command</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Events Tab -->
  <div id="events" class="tab-panel">
    <div class="table-wrapper">
      <table id="events-table">
        <thead><tr><th>Time</th><th>Category</th><th>Event ID</th><th>Provider</th><th>Message</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Network Tab -->
  <div id="network" class="tab-panel">
    <div style="margin-bottom: 20px;">
      <h3 style="margin-bottom: 10px; color: var(--accent); font-size: 1.1rem;">Firewall Profiles</h3>
      <div id="firewall-cards" style="display: flex; gap: 12px; flex-wrap: wrap;"></div>
    </div>

    <h3 style="margin-bottom: 10px; color: var(--accent); font-size: 1.1rem;">Listening TCP Ports</h3>
    <div class="table-wrapper">
      <table id="network-table">
        <thead><tr><th>Port</th><th>Address</th><th>Owning Process (PID)</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</div>

<script>
  const findingsData = {findings_json};
  const appsData = {apps_json};
  const servicesData = {services_json};
  const startupData = {startup_json};
  const storageData = {storage_json};
  const eventsData = {events_json};
  const networkData = {network_json};

  function openTab(name) {{
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(name).classList.add('active');
    event.currentTarget.classList.add('active');
  }}

  // Render Findings
  function renderFindings() {{
    const list = document.getElementById('findings-list');
    if (!findingsData.length) {{
      list.innerHTML = '<div class="finding-item info"><div class="finding-title">No diagnostic findings</div><div class="finding-desc">System passed all health checks.</div></div>';
      return;
    }}
    list.innerHTML = findingsData.map(f => `
      <div class="finding-item ${{f.severity}}">
        <div class="finding-title">
          <span>${{f.title}}</span>
          <span style="font-size:0.75rem; text-transform:uppercase; font-weight:700;">${{f.severity}}</span>
        </div>
        <div class="finding-desc">${{f.description}}</div>
        ${{f.recommendation ? `<div class="finding-rec">💡 ${{f.recommendation}}</div>` : ''}}
      </div>
    `).join('');
  }}

  // Render Storage
  function renderStorage() {{
    const tbody = document.querySelector('#storage-table tbody');
    tbody.innerHTML = storageData.map(d => `
      <tr>
        <td><strong>${{d.drive || 'N/A'}}</strong></td>
        <td>${{d.label || ''}}</td>
        <td>${{d.file_system || ''}}</td>
        <td>${{d.size_gb || 0}} GB</td>
        <td>${{d.free_gb || 0}} GB</td>
        <td><strong>${{d.usage_percent || 0}}%</strong></td>
      </tr>
    `).join('');
  }}

  // Render Apps
  function renderApps() {{
    const q = (document.getElementById('apps-search').value || '').toLowerCase();
    const tbody = document.querySelector('#apps-table tbody');
    const filtered = appsData.filter(a => 
      (a.name || '').toLowerCase().includes(q) ||
      (a.publisher || '').toLowerCase().includes(q) ||
      (a.version || '').toLowerCase().includes(q)
    );
    tbody.innerHTML = filtered.slice(0, 200).map(a => `
      <tr>
        <td><strong>${{a.name || ''}}</strong></td>
        <td>${{a.version || ''}}</td>
        <td>${{a.publisher || ''}}</td>
        <td>${{a.source || ''}}</td>
      </tr>
    `).join('');
  }}

  // Render Services
  function renderServices() {{
    const q = (document.getElementById('services-search').value || '').toLowerCase();
    const tbody = document.querySelector('#services-table tbody');
    const filtered = servicesData.filter(s =>
      (s.name || '').toLowerCase().includes(q) ||
      (s.display_name || '').toLowerCase().includes(q) ||
      (s.state || '').toLowerCase().includes(q)
    );
    tbody.innerHTML = filtered.slice(0, 200).map(s => `
      <tr>
        <td>${{s.category || ''}}</td>
        <td><strong>${{s.name || ''}}</strong></td>
        <td>${{s.display_name || ''}}</td>
        <td><span style="color:${{s.state === 'Running' ? 'var(--success)' : 'var(--text-muted)'}}">${{s.state || ''}}</span></td>
        <td>${{s.start_mode || ''}}</td>
      </tr>
    `).join('');
  }}

  // Render Startup
  function renderStartup() {{
    const tbody = document.querySelector('#startup-table tbody');
    tbody.innerHTML = startupData.map(st => `
      <tr>
        <td><strong>${{st.name || ''}}</strong></td>
        <td>${{st.source || ''}}</td>
        <td>${{st.scope || ''}}</td>
        <td style="font-family: monospace; font-size: 0.8rem; word-break: break-all;">${{st.command || ''}}</td>
      </tr>
    `).join('');
  }}

  // Render Events
  function renderEvents() {{
    const tbody = document.querySelector('#events-table tbody');
    if (!eventsData.length) {{
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No critical crash or disk warning events detected.</td></tr>';
      return;
    }}
    tbody.innerHTML = eventsData.map(e => `
      <tr>
        <td>${{e.time_created || ''}}</td>
        <td><strong>${{e.category || ''}}</strong></td>
        <td>${{e.id || ''}}</td>
        <td>${{e.provider || ''}}</td>
        <td>${{e.message || ''}}</td>
      </tr>
    `).join('');
  }}

  // Render Network
  function renderNetwork() {{
    const fwContainer = document.getElementById('firewall-cards');
    const profiles = networkData.firewall_profiles || [];
    fwContainer.innerHTML = profiles.map(p => `
      <div class="card" style="min-width: 200px; flex: 1;">
        <div class="card-label">${{p.name || ''}} Profile</div>
        <div class="card-val" style="font-size: 1.1rem; color: ${{p.enabled ? 'var(--success)' : 'var(--crit)'}};">
          ${{p.enabled ? 'Active / Protected' : 'DISABLED'}}
        </div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
          Inbound: ${{p.inbound_action || 'Block'}} | Outbound: ${{p.outbound_action || 'Allow'}}
        </div>
      </div>
    `).join('');

    const tbody = document.querySelector('#network-table tbody');
    const ports = networkData.listening_tcp || [];
    if (!ports.length) {{
      tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--text-muted);">No active listening TCP ports detected.</td></tr>';
      return;
    }}
    tbody.innerHTML = ports.map(pt => `
      <tr>
        <td><strong>${{pt.port || ''}}</strong></td>
        <td>${{pt.address || ''}}</td>
        <td>PID ${{pt.pid || ''}}</td>
      </tr>
    `).join('');
  }}

  // Initialize
  renderFindings();
  renderStorage();
  renderApps();
  renderServices();
  renderStartup();
  renderEvents();
  renderNetwork();
</script>
</body>
</html>
"""
    return html

