#!/usr/bin/env python3
"""PNDCC SIEM Standalone Dashboard V3.4.3 — Isolated health-check trial.

Features:
- Python standard library only; binds to 127.0.0.1 by default.
- SQLite event store with bounded retention and fingerprint deduplication.
- Import JSON / JSONL alerts, including Wazuh-style objects and PNDCC Windows exports.
- macOS Unified Log collection with authentication-failure filtering (best-effort; macOS only, privacy restrictions may limit results).
- V3.2: narrows the macOS process predicate, uses a shorter collection window, and records collection failures in source health.
- V3.4: uses device + event channel + native Windows RecordID as a timestamp-independent identity and checks existing stored identities before import.
- V3.4.1: normalizes Windows timestamps with 7 fractional digits for Python 3.9 and preserves fractional seconds in storage.
- Downloadable PowerShell collector for Windows Security/System event logs; import its JSONL file on Mac.
- Transparent local detections for repeated failed-login indicators and selected high-impact Windows events.
- Wazuh/cloud integrations are explicitly reported as unconfigured; no fake data is generated.

Run from the PNDCC app folder:
    python3 PNDCC_SIEM_Standalone_Dashboard_V3_LOCAL_SIEM.py
Dashboard: http://127.0.0.1:8802
Developer: Saiful Quadir
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

APP_NAME = "PNDCC SIEM Security Dashboard"
APP_VERSION = "V3.4.3 Local SIEM · Synthetic/Real Separation Trial"
HOST = "127.0.0.1"
PORT = int(os.environ.get("PNDCC_SIEM_PORT", "8793"))
MAX_EVENTS = max(100, int(os.environ.get("PNDCC_SIEM_MAX_EVENTS", "5000")))
MAX_BODY_BYTES = 12 * 1024 * 1024
DATA_DIR = Path(os.environ.get("PNDCC_SIEM_DATA_DIR", str(Path(__file__).resolve().parent / "siem_data_v3")))
DB_PATH = DATA_DIR / "events.sqlite3"
LOCK = threading.RLock()

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1, "unknown": 0}
FAILED_LOGIN_RE = re.compile(
    r"failed\s+log(?:in|on)|log(?:in|on)\s+failure|authentication\s+failure|"
    r"failed\s+authentication|authentication\s+failed|failed\s+to\s+authenticate|"
    r"authentication\s+denied|invalid\s+password|incorrect\s+password|bad\s+password|"
    r"unknown\s+user|invalid\s+user|user\s+not\s+found|invalid\s+credentials|"
    r"logon failure|account failed to log on|too many authentication failures|"
    r"status:\s*0xc000006d|event.?id\s*[:=]?\s*4625",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

WINDOWS_COLLECTOR = r'''
# PNDCC SIEM Windows Event Collector V3.4.3 - Read Query Fix
# Developer: Saiful Quadir
# Read-only export of selected Windows Security/System events from the last 24 hours.
# This script does not transmit logs over the network or change system settings.
# Run PowerShell as Administrator for the fullest Security log access.

$ErrorActionPreference = 'Continue'
$Since = (Get-Date).AddHours(-24)
$Desktop = [Environment]::GetFolderPath('Desktop')
$Out = Join-Path $Desktop ("PNDCC_Windows_Security_Events_{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$Rows = New-Object System.Collections.Generic.List[object]
$Warnings = New-Object System.Collections.Generic.List[string]

# Query each channel and filter the returned events locally. This avoids the
# FilterHashtable path that produced "The parameter is incorrect" on this system.
$Queries = @(
    @{ LogName = 'Security'; Ids = @(4624,4625,4672,4719,4720,4726,1102) },
    @{ LogName = 'System';   Ids = @(6005,6006,7045) }
)

foreach ($Q in $Queries) {
    try {
        $Found = @(
            Get-WinEvent -LogName $Q.LogName -MaxEvents 10000 -ErrorAction Stop |
                Where-Object {
                    ($_.TimeCreated -ge $Since) -and ($Q.Ids -contains [int]$_.Id)
                }
        )

        foreach ($Ev in $Found) {
            $Msg = [string]$Ev.Message
            if ($Msg.Length -gt 5000) { $Msg = $Msg.Substring(0, 5000) }
            $Severity = 'info'
            $Category = 'Windows Event Log'
            $Title = "Windows event $($Ev.Id)"

            switch ([int]$Ev.Id) {
                4625 { $Severity = 'medium'; $Category = 'Authentication'; $Title = 'Failed Windows logon' }
                4624 { $Severity = 'info'; $Category = 'Authentication'; $Title = 'Successful Windows logon' }
                4672 { $Severity = 'low'; $Category = 'Privilege'; $Title = 'Special privileges assigned to logon' }
                4719 { $Severity = 'high'; $Category = 'Audit Policy'; $Title = 'System audit policy changed' }
                4720 { $Severity = 'medium'; $Category = 'Account Management'; $Title = 'User account created' }
                4726 { $Severity = 'medium'; $Category = 'Account Management'; $Title = 'User account deleted' }
                1102 { $Severity = 'high'; $Category = 'Audit Log'; $Title = 'Security audit log cleared' }
                6005 { $Severity = 'info'; $Category = 'System'; $Title = 'Event Log service started' }
                6006 { $Severity = 'info'; $Category = 'System'; $Title = 'Event Log service stopped' }
                7045 { $Severity = 'medium'; $Category = 'Service Installation'; $Title = 'New Windows service installed' }
            }

            $SourceIP = ''
            foreach ($Pattern in @('Source Network Address:\s*([^\s]+)', 'Source Address:\s*([^\s]+)', 'Client Address:\s*([^\s]+)')) {
                $M = [regex]::Match($Msg, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($M.Success) {
                    $Candidate = $M.Groups[1].Value.Trim()
                    if ($Candidate -notin @('-', '::1', '127.0.0.1')) { $SourceIP = $Candidate }
                    break
                }
            }

            $Rows.Add([pscustomobject]@{
                timestamp = $Ev.TimeCreated.ToUniversalTime().ToString('o')
                severity = $Severity
                title = $Title
                category = $Category
                source = 'Windows Event Log'
                device = $env:COMPUTERNAME
                source_ip = $SourceIP
                event_id = [int]$Ev.Id
                record_id = [string]$Ev.RecordId
                channel = $Q.LogName
                message = $Msg
            })
        }
    }
    catch {
        $Warnings.Add(("{0} query: {1}" -f $Q.LogName, $_.Exception.Message))
    }
}

$Lines = New-Object System.Collections.Generic.List[string]
foreach ($Row in ($Rows | Sort-Object timestamp)) {
    $Lines.Add(($Row | ConvertTo-Json -Compress -Depth 5))
}

if ($Lines.Count -gt 0) {
    [System.IO.File]::WriteAllLines($Out, [string[]]$Lines, (New-Object System.Text.UTF8Encoding($false)))
} else {
    [System.IO.File]::WriteAllText($Out, '', (New-Object System.Text.UTF8Encoding($false)))
}

Write-Host ''
Write-Host 'PNDCC Windows event export completed (read-only).' -ForegroundColor Green
Write-Host ("Events exported: {0}" -f $Rows.Count)
Write-Host ("Output file: {0}" -f $Out)
Write-Host 'Event ID counts:'
foreach ($Id in @(4624, 4625, 4672, 4719, 4720, 4726, 1102, 6005, 6006, 7045)) {
    $Count = @($Rows | Where-Object { $_.event_id -eq $Id }).Count
    Write-Host ("  {0}: {1}" -f $Id, $Count)
}
if ($Warnings.Count -gt 0) {
    Write-Host 'Warnings (some channels may require Administrator access):' -ForegroundColor Yellow
    $Warnings | ForEach-Object { Write-Host (" - " + $_) -ForegroundColor Yellow }
}
Write-Host 'Next: transfer this JSONL file to your Mac using your trusted method, then import it in the PNDCC SIEM dashboard.'
Write-Host 'Developer: Saiful Quadir'
'''

HTML_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PNDCC SIEM V3.4.3 · Synthetic/Real Separation Trial</title>
<style>
:root{color-scheme:light;--ink:#172033;--muted:#667085;--line:#e4e7ec;--paper:#f7f8fa;--card:#fff;--blue:#2457c5;--bluep:#eaf0ff;--red:#b42318;--amber:#b54708;--green:#067647}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:var(--paper)}header{background:#fff;border-bottom:1px solid var(--line);padding:20px max(18px,calc((100vw - 1260px)/2));display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.logo{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:var(--bluep);color:var(--blue);font-size:23px}.brand h1{font-size:20px;margin:0}.subtitle{color:var(--muted);font-size:12px}.local{background:#ecfdf3;border:1px solid #abefc6;color:#067647;padding:5px 9px;border-radius:999px;font-size:12px;font-weight:650}.wrap{max-width:1260px;margin:20px auto;padding:0 18px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:18px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;min-width:0}.metric-label{color:var(--muted);font-size:12px}.metric{font-size:28px;font-weight:750;margin-top:6px;letter-spacing:-.04em}.hint{color:var(--muted);font-size:12px;margin-top:5px}.section-title{font-size:16px;margin:0 0 4px}.section-desc{font-size:12px;color:var(--muted);margin:0 0 14px}.panel{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}.statusgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.source{border:1px solid var(--line);padding:12px;border-radius:10px}.source strong{display:block;font-size:13px}.pill{display:inline-block;border-radius:999px;font-size:11px;padding:3px 7px;background:#f2f4f7;color:#475467}.pill.ok{background:#ecfdf3;color:#067647}.pill.warn{background:#fffaeb;color:#b54708}.pill.bad{background:#fef3f2;color:#b42318}.btn{border:1px solid #cfd4dc;border-radius:8px;background:white;color:var(--ink);padding:9px 12px;cursor:pointer;font-weight:600;font-size:12px}.btn.primary{background:var(--blue);border-color:var(--blue);color:white}.btn:disabled{opacity:.45;cursor:not-allowed}input[type=search],select{border:1px solid #cfd4dc;border-radius:8px;padding:9px 10px;background:#fff;color:var(--ink);min-width:140px}input[type=file]{max-width:100%;font-size:12px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%;min-width:1040px;background:white}th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#667085;background:#f9fafb}th,td{padding:11px 12px;border-bottom:1px solid #eaecf0;vertical-align:top}td{font-size:12px}tr:last-child td{border-bottom:0}.sev{font-size:11px;text-transform:uppercase;font-weight:750}.sev.critical,.sev.high{color:var(--red)}.sev.medium{color:var(--amber)}.sev.low{color:var(--blue)}.sev.info{color:var(--muted)}.muted{color:var(--muted)}.event-title{font-weight:700}.message{max-width:420px;white-space:pre-wrap;overflow-wrap:anywhere;color:#475467;margin-top:4px}.foot{color:var(--muted);font-size:11px;text-align:center;padding:18px}.note{border-left:3px solid #84adff;background:#f5f8ff;padding:10px 12px;border-radius:5px;font-size:12px;color:#344054}.statusline{font-size:12px;color:var(--muted);min-height:18px;margin-top:8px}.mini{font-size:11px;color:var(--muted)}.empty{text-align:center;color:var(--muted);padding:28px}.dangertext{color:var(--red)}.provenance-tag{display:inline-block;border-radius:999px;padding:4px 7px;font-size:10px;line-height:1.35;font-weight:750;letter-spacing:.01em}.provenance-tag.real{background:#ecfdf3;color:#067647;border:1px solid #abefc6}.provenance-tag.synthetic{background:#fffaeb;color:#b54708;border:1px solid #fedf89}.provenance-tag.mixed{background:#fef3f2;color:#b42318;border:1px solid #fecdca}.provenance-tag.detection{background:#eef4ff;color:#3538cd;border:1px solid #c7d7fe}.provenance-cell{min-width:150px}.provenance-cell .mini{margin-top:5px;max-width:190px}@media(max-width:900px){.grid,.statusgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.grid,.statusgrid{grid-template-columns:1fr}.wrap{padding:0 10px}.panel{padding:13px}header{padding:15px}}
</style></head><body>
<header><div class="brand"><div class="logo">⌁</div><div><h1>Personal Network &amp; Device Command Center</h1><div class="subtitle">SIEM Security Dashboard · V3.4.3 Synthetic/Real Separation Trial · Simple is the best.</div></div></div><div class="row"><span class="local">LOCAL ONLY</span><span class="mini" id="updated">Loading status…</span></div></header>
<main class="wrap">
<section class="grid summary-grid">
 <div class="card"><div class="metric-label">Critical / High open alerts</div><div class="metric" id="critical">—</div><div class="hint" id="criticalHint">Needs review; not proof of compromise</div></div>
<div class="card"><div class="metric-label">Critical / High new alerts</div><div class="metric" id="newCritical">—</div><div class="hint">Not yet acknowledged; review these first</div></div>
 <div class="card"><div class="metric-label">Non-test source events · last 24 hours</div><div class="metric" id="last24">—</div><div class="hint">Excludes explicitly marked test records and generated alerts; source authenticity is not verified</div></div>
 <div class="card"><div class="metric-label">Synthetic test events retained</div><div class="metric" id="synthetic">—</div><div class="hint">Explicitly marked test data; not real telemetry</div></div>
 <div class="card"><div class="metric-label">Devices observed (non-test sources)</div><div class="metric" id="devices">—</div><div class="hint">Excludes explicitly marked test devices</div></div>
 <div class="card"><div class="metric-label">Detection alerts retained</div><div class="metric" id="detectionCount">—</div><div class="hint" id="detectionHint">Rule-generated alerts; review evidence</div></div>
 <div class="card"><div class="metric-label">All records retained</div><div class="metric" id="total">—</div><div class="hint">Source events + detection alerts; bounded to 5,000</div></div>
</section>
<section class="panel"><h2 class="section-title">Security events</h2><p class="section-desc">Use Data view to separate source events from synthetic/test records and generated detection alerts. “Real source” means not explicitly marked as test; it is not cryptographic verification.</p><div class="note" id="provenanceNotice" hidden>Test data is present. Synthetic/test records and alerts derived from them are labeled in the table and excluded from non-test source metrics.</div>
 <div class="toolbar"><select id="dataType" aria-label="Filter by data type"><option value="all">All records</option><option value="real_source">Real source events</option><option value="synthetic_source">Synthetic/test source events</option><option value="detection">Detection alerts</option><option value="mixed">Mixed test/real records</option></select><input type="search" id="search" placeholder="Search event, device, IP…"><select id="severity"><option value="all">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option><option>unknown</option></select><select id="status"><option value="all">All statuses</option><option value="new">New</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select><button class="btn" id="refresh">Refresh</button><button class="btn" id="export">Export JSONL</button></div>
 <div class="tablewrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Event / evidence</th><th>Data type / provenance</th><th>Source / device</th><th>Source IP</th><th>Status</th><th>Action</th></tr></thead><tbody id="events"><tr><td colspan="8" class="empty">Loading events…</td></tr></tbody></table></div><div class="statusline" id="eventStatus"></div>
</section></section>
<section class="grid" style="grid-template-columns:repeat(2,minmax(0,1fr))">
 <div class="panel"><h2 class="section-title">Collect local Mac logs</h2><p class="section-desc">Focused, best-effort check of recent macOS authentication-related logs (last 10 minutes). macOS privacy settings may limit results; only recognized authentication-failure messages are retained.</p><button class="btn primary" id="collectMac">Collect last 10 minutes</button><div class="statusline" id="macStatus"></div></div>
 <div class="panel"><h2 class="section-title">Import Windows or other alerts</h2><p class="section-desc">Import JSON or JSONL from the Windows collector or another trusted source. Imports are deduplicated.</p><div class="toolbar"><input id="file" type="file" accept=".json,.jsonl,.txt,application/json,text/plain"><button class="btn primary" id="import">Import file</button></div><div class="statusline" id="importStatus"></div></div>
</section>
<section class="panel"><h2 class="section-title">Source health</h2><p class="section-desc">Only observed or configured sources are described as available.</p><div class="statusgrid" id="sources">
 <div class="source"><strong>Local event store</strong><span class="pill ok">Ready</span><div class="hint">SQLite file on this Mac</div></div>
 <div class="source"><strong>macOS Unified Log</strong><span class="pill warn">Not checked</span><div class="hint">Manual collection available</div></div>
 <div class="source"><strong>Windows Event Log</strong><span class="pill warn">Awaiting import</span><div class="hint">Export with PowerShell collector</div></div>
 <div class="source"><strong>Wazuh / Cloud SIEM</strong><span class="pill">Not configured</span><div class="hint">No external SIEM assumed</div></div>
</div></section>
<section class="panel"><h2 class="section-title">Windows event collector</h2><p class="section-desc">Download the PowerShell collector, run it on Windows (Administrator recommended), then transfer its JSONL export to your Mac using your existing trusted method and import the file above. The script makes no network connection and changes no Windows settings.</p><a class="btn" href="/download/windows-collector.ps1">Download Windows PowerShell collector (.ps1)</a><div class="statusline">Collection window: last 24 hours · selected Security/System event IDs · Developer: Saiful Quadir</div></section>
<section class="panel"><h2 class="section-title">Detection rule</h2><p class="section-desc">Transparent local heuristic; a signal is not proof of compromise.</p><div class="row"><span class="pill warn">Medium / High review signal</span><strong>Possible brute-force activity</strong></div><p class="mini">Creates a high-severity alert when at least 5 failed-login indicators from the same source IP or device occur within 10 minutes. Selected Windows events (audit log cleared, audit policy changed) are also flagged for review. Legitimate administration can trigger these rules.</p><div class="mini">Rule ID: PNDCC-LOCAL-001 · Retention is bounded to the latest configured record count.</div></section>
<div class="note">This is a lightweight local-first SIEM foundation, not a replacement for full Wazuh capabilities. It does not monitor continuously unless collection/import is run, and Wazuh/cloud integrations are not connected. Keep the Windows export and local database access restricted because logs may contain usernames, IPs, and system details.</div>
<div class="foot">PNDCC SIEM V3.4.3 · Synthetic/Real Separation Trial · Local SQLite store · “Simple is the best.”<br><strong>Developer: Saiful Quadir</strong></div>
</main>
<script>
const $=id=>document.getElementById(id);let ALL=[];const fmtTime=s=>{if(!s)return '—';const d=new Date(s);return isNaN(d)?String(s):d.toLocaleString()};
async function api(url,opts={}){const r=await fetch(url,{cache:'no-store',...opts});let j={};try{j=await r.json()}catch{}if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
function sevClass(s){return ['critical','high','medium','low','info'].includes((s||'').toLowerCase())?(s||'').toLowerCase():'info'}
function td(text,cls){const e=document.createElement('td');if(cls)e.className=cls;e.textContent=text==null?'':String(text);return e}
function buildRow(e){const tr=document.createElement('tr');tr.append(td(fmtTime(e.timestamp)));const sev=td((e.severity||'unknown').toUpperCase(),'sev '+sevClass(e.severity));tr.append(sev);const ev=document.createElement('td');const title=document.createElement('div');title.className='event-title';title.textContent=e.title||'Security event';ev.append(title);const msg=document.createElement('div');msg.className='message';msg.textContent=e.message||'';ev.append(msg);if(e.event_id){const meta=document.createElement('div');meta.className='mini';meta.textContent='Event ID: '+e.event_id+(e.category?' · '+e.category:'');ev.append(meta)}tr.append(ev);const pc=document.createElement('td');pc.className='provenance-cell';const tag=document.createElement('span');if(e.provenance==='synthetic_test'){tag.className='provenance-tag synthetic';tag.textContent=e.record_type==='detection_alert'?'SYNTHETIC-TEST DETECTION':'SYNTHETIC / TEST'}else if(e.provenance==='mixed_test_real'){tag.className='provenance-tag mixed';tag.textContent='MIXED — includes test data'}else if(e.record_type==='detection_alert'){tag.className='provenance-tag detection';tag.textContent='DETECTION ALERT'}else{tag.className='provenance-tag real';tag.textContent='SOURCE EVENT'}pc.append(tag);const pnote=document.createElement('div');pnote.className='mini';pnote.textContent=e.provenance==='synthetic_test'?'Not real telemetry':(e.provenance==='mixed_test_real'?'Do not treat as fully real':'Source record / generated finding');pc.append(pnote);tr.append(pc);const src=document.createElement('td');src.textContent=(e.source||'Unknown')+'\n'+(e.device||'Unknown device');src.style.whiteSpace='pre-line';tr.append(src);tr.append(td(e.source_ip||'—'));const st=td(e.status||'new');tr.append(st);const action=document.createElement('td');const sel=document.createElement('select');['new','acknowledged','resolved'].forEach(s=>{let o=document.createElement('option');o.value=s;o.textContent=s.charAt(0).toUpperCase()+s.slice(1);if(s===(e.status||'new'))o.selected=true;sel.append(o)});sel.addEventListener('change',async()=>{sel.disabled=true;try{await api('/api/events/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:e.id,status:sel.value})});await load()}catch(err){alert('Could not update status: '+err.message);sel.disabled=false}});action.append(sel);tr.append(action);return tr}
function render(){const s=$('search').value.trim().toLowerCase(),sev=$('severity').value,st=$('status').value,dt=$('dataType').value;const rows=ALL.filter(e=>{const provenance=e.provenance||'real_source',recordType=e.record_type||'source_event';const dataMatch=dt==='all'||(dt==='real_source'&&recordType==='source_event'&&provenance==='real_source')||(dt==='synthetic_source'&&recordType==='source_event'&&provenance==='synthetic_test')||(dt==='detection'&&recordType==='detection_alert')||(dt==='mixed'&&provenance==='mixed_test_real');return dataMatch&&(sev==='all'||e.severity===sev)&&(st==='all'||e.status===st)&&(!s||[e.title,e.message,e.source,e.device,e.source_ip,e.category,e.event_id,e.provenance,e.record_type].join(' ').toLowerCase().includes(s))});const tb=$('events');tb.replaceChildren();if(!rows.length){const tr=document.createElement('tr'),td0=td(ALL.length?'No events match the selected filters.':'No events received yet. Import a trusted source event file or collect Mac logs.','empty');td0.colSpan=8;tr.append(td0);tb.append(tr)}else rows.forEach(e=>tb.append(buildRow(e)));$('eventStatus').textContent=`Showing ${rows.length} of ${ALL.length} matching retained records`}
async function load(){try{const [s,ev]=await Promise.all([api('/api/status'),api('/api/events?limit=5000')]);ALL=ev.events||[];$('critical').textContent=s.open_critical_high;$('newCritical').textContent=s.new_critical_high;$('criticalHint').textContent=s.open_critical_high_test_data+' open Critical/High record(s) originate from synthetic/test data; alerts are not proof of compromise.';$('last24').textContent=s.events_last_24h;$('synthetic').textContent=s.synthetic_test_events_retained;$('devices').textContent=s.devices_observed;$('detectionCount').textContent=s.detection_alerts_retained;$('detectionHint').textContent=s.synthetic_detection_alerts+' detection alert(s) derived from synthetic/test data.';$('total').textContent=s.events_retained;$('provenanceNotice').hidden=(s.synthetic_test_events_retained===0&&s.synthetic_detection_alerts===0&&s.mixed_source_events_retained===0);$('updated').textContent='Updated '+new Date().toLocaleTimeString();render();const ms=s.macos_note||(s.last_macos_collection?'Collection attempted at '+fmtTime(s.last_macos_collection):'Not collected yet');$('macStatus').textContent=ms;$('sources').innerHTML='';const winHint=s.windows_events+' unmarked Windows source records · '+s.synthetic_windows_events+' synthetic/test records';const winState=s.windows_events>0?'Unmarked source data imported':(s.synthetic_windows_events>0?'Synthetic tests only':'Awaiting import');const sourceItems=[['Local event store','Ready','SQLite database on this Mac','ok'],['macOS Unified Log',s.macos_status||'Not checked',s.macos_note||'Manual collection available',(s.macos_status==='Matching events found/imported'||s.macos_status==='Matching events found; no new events imported')?'ok':(s.macos_status==='Collection failed'?'bad':'warn')],['Windows Event Log',winState,winHint,s.windows_events>0?'ok':'warn'],['Wazuh / Cloud SIEM','Not configured','No external SIEM connection is active','']];for(const it of sourceItems){const div=document.createElement('div');div.className='source';const strong=document.createElement('strong');strong.textContent=it[0];const pill=document.createElement('span');pill.className='pill '+it[3];pill.textContent=it[1];const hint=document.createElement('div');hint.className='hint';hint.textContent=it[2];div.append(strong,pill,hint);$('sources').append(div)}}catch(e){$('updated').textContent='Refresh failed: '+e.message}}
$('refresh').onclick=load;$('search').oninput=render;$('dataType').onchange=render;$('severity').onchange=render;$('status').onchange=render;
$('collectMac').onclick=async()=>{const b=$('collectMac');b.disabled=true;b.textContent='Collecting…';$('macStatus').textContent='Running a focused macOS authentication-log query (last 10 minutes).';try{const r=await api('/api/collect/macos',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});$('macStatus').textContent=r.message||`Collected ${r.imported||0} events; duplicates ${r.duplicates||0}.`;await load()}catch(e){$('macStatus').textContent='Collection failed: '+e.message;await load()}finally{b.disabled=false;b.textContent='Collect last 10 minutes'}};
$('import').onclick=async()=>{const f=$('file').files[0];if(!f){$('importStatus').textContent='Choose a JSON or JSONL file first.';return}const b=$('import');b.disabled=true;$('importStatus').textContent='Reading '+f.name+'…';try{const text=await f.text();const r=await api('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:f.name,content:text})});$('importStatus').textContent=`Imported ${r.imported}; skipped ${r.skipped}; duplicates ${r.duplicates}.`;await load()}catch(e){$('importStatus').textContent='Import failed: '+e.message}finally{b.disabled=false}};
$('export').onclick=()=>{window.location='/api/export'};
load();setInterval(load,30000);
</script></body></html>'''


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value) -> datetime:
    if value is None or value == "":
        return now_utc()
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().replace(".", "", 1).isdigit()):
            num = float(value)
            if num > 100_000_000_000:
                num /= 1000.0
            return datetime.fromtimestamp(num, tz=timezone.utc)
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Windows PowerShell/.NET "o" timestamps can contain seven fractional
        # digits. Python 3.9 datetime.fromisoformat accepts at most six
        # (microsecond precision); truncate excess precision rather than
        # silently replacing the event time with the current time.
        text = re.sub(r"(\.\d{6})\d+(?=(?:[+-]\d{2}:?\d{2})?$)", r"\1", text)
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return now_utc()


def as_iso(value) -> str:
    # Preserve fractional seconds when supplied by the original event. The
    # parser intentionally stores Python's supported microsecond precision.
    return parse_time(value).isoformat(timespec="auto").replace("+00:00", "Z")


def nested(obj, *paths, default=None):
    for path in paths:
        cur = obj
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, "", [], {}):
            return cur
    return default


def native_windows_identity(raw: dict | None):
    """Stable Windows event identity, independent of timestamp formatting.

    Windows EventRecordID is unique within an event channel on a device.
    Require device + channel + record ID so IDs from different channels/devices
    are never accidentally merged. This also recognizes older JSON key aliases.
    """
    if not isinstance(raw, dict):
        return None
    record_id = nested(raw, "record_id", "recordId", "event_record_id", "eventRecordId", "winlog.record_id", default=None)
    channel = nested(raw, "channel", "winlog.channel", default=None)
    source = nested(raw, "source", "log_source", "observer.name", default="")
    device = nested(raw, "device", "host.name", "hostname", "agent.name", default="")
    if record_id in (None, "") or channel in (None, "") or device in (None, ""):
        return None
    source_text = str(source).strip().casefold()
    channel_text = str(channel).strip().casefold()
    if "windows" not in source_text and channel_text not in {
        "security", "system", "application", "setup", "forwarded events"
    }:
        return None
    # Identity is the device + channel + native Record ID. Source labels are
    # deliberately excluded because different exporters may label the same
    # Windows channel differently; including the label defeats deduplication.
    return "|".join((
        "windows-native-record",
        str(device).strip().casefold(),
        channel_text,
        str(record_id).strip(),
    ))


def raw_provenance(raw) -> str:
    """Classify explicit synthetic/test markers; otherwise treat as source data.

    This is a practical UI label, not cryptographic proof that a source record
    is authentic. Explicit fixture markers and trusted provenance fields are
    used; event IDs or device names alone are not used to guess test status.
    """
    if not isinstance(raw, dict):
        return "real_source"
    value = str(raw.get("provenance") or raw.get("data_classification") or "").strip().casefold().replace("-", "_").replace(" ", "_")
    if value in {"mixed_test_real", "mixed_test_and_real", "mixed"}:
        return "mixed_test_real"
    if value in {"synthetic", "synthetic_test", "test", "synthetic_test_data"}:
        return "synthetic_test"
    if raw.get("synthetic_test") is True or raw.get("is_synthetic") is True or raw.get("test_data") is True:
        return "synthetic_test"
    try:
        serialized = json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str).casefold()
    except Exception:
        serialized = str(raw).casefold()
    if "synthetic test only" in serialized:
        return "synthetic_test"
    return "real_source"


def event_provenance(source, raw_json, title="", message="") -> str:
    """Classify a stored event, including detections that inherit test origin."""
    try:
        raw = json.loads(raw_json or "{}")
    except (json.JSONDecodeError, TypeError):
        raw = {}
    provenance = raw_provenance(raw)
    if provenance == "real_source" and "synthetic test only" in (str(title) + " " + str(message)).casefold():
        provenance = "synthetic_test"
    return provenance


def normalize_severity(raw) -> str:
    if isinstance(raw, dict):
        value = nested(raw, "severity", "level", "priority", "rule.level", default=None)
    else:
        value = raw
    if value is None:
        return "unknown"
    if isinstance(value, (int, float)):
        if value >= 12: return "critical"
        if value >= 8: return "high"
        if value >= 4: return "medium"
        if value >= 1: return "low"
        return "info"
    val = str(value).strip().lower()
    aliases = {"informational": "info", "notice": "info", "warning": "medium", "moderate": "medium", "error": "high", "fatal": "critical", "severe": "critical"}
    val = aliases.get(val, val)
    return val if val in SEVERITY_RANK else "unknown"


def infer_source_ip(raw: dict, message: str) -> str:
    candidate = nested(raw, "source_ip", "src_ip", "srcip", "data.srcip", "data.src_ip", "client.ip", "source.ip", "agent.ip", default=None)
    if candidate:
        s = str(candidate).strip()
        if s not in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            return s
    m = re.search(r"(?:source network address|source address|client address|remote address|srcip|source_ip)\s*[:=]\s*([^\s,;]+)", message, re.IGNORECASE)
    if m:
        s = m.group(1).strip()
        if s not in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            return s
    return ""


def normalize_event(raw, fallback_source="Imported Event") -> dict | None:
    if not isinstance(raw, dict):
        return None
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    title = nested(raw, "title", "name", "description", "event", "message", "rule.description", "alert.description", default=None)
    if isinstance(title, (dict, list)):
        title = nested(raw, "event.action", "event.code", "rule.description", default=None)
    title = str(title or nested(raw, "event.action", "event.code", default="Security event"))[:300]
    msg = nested(raw, "message", "full_log", "eventMessage", "details", "data.message", default="")
    message = str(msg or "")[:6000]
    source = nested(raw, "source", "log_source", "observer.name", default=None)
    if not source:
        source = "Wazuh" if rule and ("id" in rule or "level" in rule) else fallback_source
    device = nested(raw, "device", "host.name", "hostname", "agent.name", default=None)
    if not device and isinstance(agent, dict): device = agent.get("name")
    category = nested(raw, "category", "event.category", "channel", default=None)
    event_id = nested(raw, "event_id", "event.code", "winlog.event_id", "rule.id", default=None)
    source_ip = infer_source_ip(raw, message)
    # Preserve the native Windows EventRecordID when present so two distinct
    # records with identical visible text are not collapsed as duplicates.
    record_id = nested(raw, "record_id", "recordId", "event_record_id", "eventRecordId", "winlog.record_id", default=None)
    severity = normalize_severity(raw)
    if severity == "unknown" and rule:
        severity = normalize_severity(nested(rule, "level", default=None))
    timestamp = as_iso(nested(raw, "timestamp", "@timestamp", "time", "date", "event.created", default=None))
    status = str(raw.get("status", "new")).lower()
    if status not in ("new", "acknowledged", "resolved"): status = "new"
    raw_json = json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str)
    native_identity = native_windows_identity(raw)
    if native_identity:
        # Record identity must not depend on the timestamp. A repeated native
        # Windows record keeps the same fingerprint even if timestamps are
        # formatted or normalized differently by exporters/importers.
        key_material = native_identity
    else:
        key_material = "|".join([timestamp, str(source), str(device or ""), str(event_id or ""), str(record_id or ""), title, message, source_ip])
    fingerprint = hashlib.sha256(key_material.encode("utf-8", errors="replace")).hexdigest()
    return {
        "timestamp": timestamp,
        "severity": severity,
        "title": title,
        "category": str(category or "General")[:100],
        "source": str(source or fallback_source)[:160],
        "device": str(device or "Unknown device")[:160],
        "source_ip": source_ip[:64],
        "event_id": str(event_id)[:80] if event_id is not None else "",
        "status": status,
        "message": message,
        "fingerprint": fingerprint,
        "raw_json": raw_json,
    }


def ensure_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL,
            device TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            message TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            raw_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity_status ON events(severity,status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_device ON events(source,device)")
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.commit()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def insert_one(conn, event: dict) -> bool:
    try:
        conn.execute("""INSERT INTO events
        (timestamp,severity,title,category,source,device,source_ip,event_id,status,message,fingerprint,raw_json,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event["timestamp"], event["severity"], event["title"], event["category"], event["source"], event["device"], event["source_ip"], event["event_id"], event["status"], event["message"], event["fingerprint"], event["raw_json"], iso_now()))
        return True
    except sqlite3.IntegrityError:
        return False


def trim_db(conn):
    conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (MAX_EVENTS,))


def is_failed_event(event: dict) -> bool:
    if str(event.get("event_id", "")) == "4625":
        return True
    text = " ".join([event.get("title", ""), event.get("message", ""), event.get("category", "")])
    return bool(FAILED_LOGIN_RE.search(text))


def is_relevant_macos_security_event(message: str, sender: str = "") -> bool:
    """Accept recognized authentication-failure signals, not generic OS errors."""
    return bool(FAILED_LOGIN_RE.search(f"{message} {sender}"))


def apply_detection_rules(conn):
    # Detection is based on ingested source events, not previous generated detections.
    since = (now_utc() - timedelta(minutes=10)).isoformat(timespec="seconds").replace("+00:00", "Z")
    rows = conn.execute("SELECT * FROM events WHERE timestamp >= ? AND source != 'PNDCC Local Detection Engine' ORDER BY timestamp ASC", (since,)).fetchall()
    groups: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        d = dict(row)
        if not is_failed_event(d):
            continue
        key = d.get("source_ip") or (d.get("device") if d.get("device") != "Unknown device" else d.get("source"))
        groups.setdefault(key, []).append(row)
    created = 0
    for key, hits in groups.items():
        if len(hits) < 5:
            continue
        # Avoid repeating the same open detection every time new events arrive.
        detected_ip = key if IPV4_RE.fullmatch(key or "") else ""
        detected_device = key if not detected_ip else f"Source {key}"
        existing = conn.execute("SELECT id FROM events WHERE source='PNDCC Local Detection Engine' AND title='Possible brute-force activity' AND source_ip=? AND device=? AND status!='resolved' AND created_at >= ? LIMIT 1", (detected_ip, detected_device, (now_utc()-timedelta(minutes=10)).isoformat(timespec="seconds").replace("+00:00", "Z"))).fetchone()
        if existing:
            continue
        earliest = hits[0]["timestamp"]
        latest = hits[-1]["timestamp"]
        hit_provenance = [event_provenance(hit["source"], hit["raw_json"], hit["title"], hit["message"]) for hit in hits]
        if hit_provenance and all(p == "synthetic_test" for p in hit_provenance):
            detection_provenance = "synthetic_test"
        elif any(p != "real_source" for p in hit_provenance):
            detection_provenance = "mixed_test_real"
        else:
            detection_provenance = "real_source"
        raw = {"rule_id": "PNDCC-LOCAL-001", "source_key": key, "matching_events": len(hits), "window_minutes": 10, "provenance": detection_provenance}
        ev = {
            "timestamp": iso_now(), "severity": "high", "title": "Possible brute-force activity",
            "category": "Detection", "source": "PNDCC Local Detection Engine",
            "device": detected_device, "source_ip": detected_ip,
            "event_id": "PNDCC-LOCAL-001", "status": "new",
            "message": f"Detected {len(hits)} failed-login indicators within 10 minutes. Group key: {key}. Event timestamps: {earliest} to {latest}. Review the underlying records; this heuristic is not proof of compromise.",
            "fingerprint": hashlib.sha256(f"PNDCC-LOCAL-001|{key}|{earliest}|{latest}".encode()).hexdigest(),
            "raw_json": json.dumps(raw, sort_keys=True),
        }
        if insert_one(conn, ev): created += 1
    # Selected Windows event IDs merit review even when imported logs are older than 10 minutes.
    # Markers keep repeated imports idempotent.
    sensitive_map = {"1102": ("high", "Security audit log cleared"), "4719": ("high", "System audit policy changed")}
    sensitive_rows = conn.execute("SELECT * FROM events WHERE source != 'PNDCC Local Detection Engine' AND event_id IN ('1102','4719') ORDER BY timestamp ASC").fetchall()
    for row in sensitive_rows:
        eid = str(row["event_id"] or "")
        if eid not in sensitive_map: continue
        sev, title = sensitive_map[eid]
        event_time = row["timestamp"]
        source_ip = row["source_ip"] or ""
        marker = hashlib.sha256(f"PNDCC-WIN-EVENT-{eid}|{row['fingerprint']}".encode()).hexdigest()
        source_provenance = event_provenance(row["source"], row["raw_json"], row["title"], row["message"])
        detection_raw = {"rule_id": f"PNDCC-WIN-{eid}", "source_fingerprint": row["fingerprint"], "provenance": source_provenance}
        ev = {"timestamp": event_time, "severity": sev, "title": f"Review required: {title}", "category": "Detection", "source": "PNDCC Local Detection Engine", "device": row["device"], "source_ip": source_ip, "event_id": f"PNDCC-WIN-{eid}", "status": "new", "message": f"Windows event ID {eid} was imported. This can be legitimate administration; verify the time, account and change context. Original event: {row['title']}. {row['message'][:2000]}", "fingerprint": marker, "raw_json": json.dumps(detection_raw, sort_keys=True)}
        # Avoid creating the same event-based detection more than once.
        if not conn.execute("SELECT 1 FROM events WHERE fingerprint=? LIMIT 1", (marker,)).fetchone():
            if insert_one(conn, ev): created += 1
    return created


def ingest_raw(raw_items, fallback_source="Imported Event"):
    imported = duplicates = skipped = 0
    with LOCK, db_connect() as conn:
        # Index native Windows identities already in the store. This catches
        # duplicates even when a prior version generated different fingerprints
        # because its timestamp was part of the key.
        native_seen = set()
        for existing in conn.execute("SELECT raw_json FROM events WHERE raw_json IS NOT NULL AND raw_json != ''"):
            try:
                stored_raw = json.loads(existing["raw_json"])
            except (json.JSONDecodeError, TypeError):
                continue
            identity = native_windows_identity(stored_raw)
            if identity:
                native_seen.add(identity)

        for raw in raw_items:
            ev = normalize_event(raw, fallback_source=fallback_source)
            if ev is None:
                skipped += 1
                continue
            identity = native_windows_identity(raw)
            if identity and identity in native_seen:
                duplicates += 1
                continue
            if insert_one(conn, ev):
                imported += 1
                if identity:
                    native_seen.add(identity)
            else:
                duplicates += 1
                if identity:
                    native_seen.add(identity)
        detections = apply_detection_rules(conn)
        trim_db(conn)
        conn.commit()
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped, "detections_created": detections}


def list_events(limit=1000):
    limit = max(1, min(int(limit), MAX_EVENTS))
    with db_connect() as conn:
        rows = conn.execute("SELECT id,timestamp,severity,title,category,source,device,source_ip,event_id,status,message,created_at,raw_json FROM events ORDER BY timestamp DESC,id DESC LIMIT ?", (limit,)).fetchall()
    public = []
    for row in rows:
        item = dict(row)
        provenance = event_provenance(item.get("source"), item.get("raw_json"), item.get("title"), item.get("message"))
        item["provenance"] = provenance
        item["record_type"] = "detection_alert" if item.get("source") == "PNDCC Local Detection Engine" else "source_event"
        item["is_synthetic"] = provenance == "synthetic_test"
        item["includes_test_data"] = provenance in ("synthetic_test", "mixed_test_real")
        item.pop("raw_json", None)
        item.pop("fingerprint", None)
        public.append(item)
    return public


def status_data():
    since = (now_utc() - timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with db_connect() as conn:
        rows = conn.execute("SELECT timestamp,severity,status,source,device,event_id,title,message,category,raw_json FROM events").fetchall()
        total = len(rows)
        critical = sum(1 for r in rows if r["status"] != "resolved" and str(r["severity"]).lower() in ("critical", "high"))
        new_critical = sum(1 for r in rows if str(r["status"]).lower() == "new" and str(r["severity"]).lower() in ("critical", "high"))
        meta_row = conn.execute("SELECT value FROM meta WHERE key='last_macos_collection' LIMIT 1").fetchone()
        last_mac = meta_row[0] if meta_row else None
        error_row = conn.execute("SELECT value FROM meta WHERE key='last_macos_error' LIMIT 1").fetchone()
        last_mac_error = error_row[0] if error_row else None
        result_row = conn.execute("SELECT value FROM meta WHERE key='last_macos_result' LIMIT 1").fetchone()
        last_mac_result = result_row[0] if result_row else None
        message_row = conn.execute("SELECT value FROM meta WHERE key='last_macos_message' LIMIT 1").fetchone()
        last_mac_message = message_row[0] if message_row else None

    detector = "PNDCC Local Detection Engine"
    real_source_rows, synthetic_source_rows, mixed_source_rows = [], [], []
    detection_rows, synthetic_detection_rows = [], []
    open_high_synthetic = 0
    for row in rows:
        provenance = event_provenance(row["source"], row["raw_json"], row["title"], row["message"])
        is_detection = row["source"] == detector
        if is_detection:
            detection_rows.append(row)
            if provenance in ("synthetic_test", "mixed_test_real"):
                synthetic_detection_rows.append(row)
        elif provenance == "synthetic_test":
            synthetic_source_rows.append(row)
        elif provenance == "mixed_test_real":
            mixed_source_rows.append(row)
        else:
            real_source_rows.append(row)
        if row["status"] != "resolved" and str(row["severity"]).lower() in ("critical", "high") and provenance in ("synthetic_test", "mixed_test_real"):
            open_high_synthetic += 1

    real_last24 = sum(1 for r in real_source_rows if str(r["timestamp"]) >= since)
    devices = len({str(r["device"]) for r in real_source_rows if r["device"] and r["device"] != "Unknown device"})
    def is_windows_row(r):
        return (str(r["source"] or "").startswith("Windows Event Log") or "Windows" in str(r["source"] or "") or r["category"] == "Windows Event Log")
    win_real = sum(1 for r in real_source_rows if is_windows_row(r))
    win_synthetic = sum(1 for r in synthetic_source_rows if is_windows_row(r))
    synthetic_last24 = sum(1 for r in synthetic_source_rows if str(r["timestamp"]) >= since)

    mac_status = "Not checked"
    mac_note = "Use Collect last 10 minutes to run a focused local Unified Logging query."
    if last_mac_error or last_mac_result == "failed":
        mac_status = "Collection failed"
        mac_note = last_mac_error or last_mac_message or "The macOS log query failed."
    elif last_mac_result == "no_match":
        mac_status = "Query succeeded — no matching events"
        mac_note = last_mac_message or "The query succeeded, but no matching records were found. This does not prove no security events occurred."
    elif last_mac_result == "matched_imported":
        mac_status = "Matching events found/imported"
        mac_note = last_mac_message or "Matching macOS events were found and imported."
    elif last_mac_result == "matched_no_new_import":
        mac_status = "Matching events found; no new events imported"
        mac_note = last_mac_message or "Matching records were found, but no new events were imported."
    elif last_mac:
        # Legacy metadata has a timestamp but no outcome; do not infer success.
        mac_status = "Collection attempted"
        mac_note = "A previous collection attempt was recorded at " + last_mac + "; its outcome is unknown."
    return {
        "app": APP_NAME, "version": APP_VERSION, "host": HOST, "port": PORT,
        "events_retained": total, "open_critical_high": critical,
        "new_critical_high": new_critical,
        "events_last_24h": real_last24, "real_source_events_retained": len(real_source_rows),
        "synthetic_test_events_retained": len(synthetic_source_rows),
        "synthetic_test_events_last_24h": synthetic_last24,
        "mixed_source_events_retained": len(mixed_source_rows),
        "detection_alerts_retained": len(detection_rows),
        "synthetic_detection_alerts": len(synthetic_detection_rows),
        "open_critical_high_test_data": open_high_synthetic,
        "devices_observed": devices, "windows_events": win_real,
        "synthetic_windows_events": win_synthetic,
        "last_macos_collection": last_mac, "last_macos_error": last_mac_error,
        "last_macos_result": last_mac_result,
        "macos_status": mac_status, "macos_note": mac_note,
        "wazuh_status": "not configured", "cloud_status": "not configured",
        "local_only": True, "retention_limit": MAX_EVENTS
    }


def parse_import_content(content: str):
    content = content.lstrip("\ufeff\u200b\n\r\t ")
    if not content.strip(): return []
    try:
        obj = json.loads(content)
        if isinstance(obj, list): return obj
        if isinstance(obj, dict):
            for key in ("events", "alerts", "data"):
                if isinstance(obj.get(key), list): return obj[key]
            return [obj]
    except json.JSONDecodeError:
        pass
    out = []
    for line in content.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line: continue
        try:
            item = json.loads(line)
            if isinstance(item, list): out.extend(item)
            else: out.append(item)
        except json.JSONDecodeError:
            continue
    return out


def _record_macos_attempt(
    error: str | None = None,
    result: str | None = None,
    message: str | None = None,
):
    """Persist collection outcome and a concise summary, never raw OS output."""
    with LOCK, db_connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('last_macos_collection',?)",
            (iso_now(),),
        )
        if error:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('last_macos_error',?)",
                (str(error)[:1000],),
            )
        else:
            conn.execute("DELETE FROM meta WHERE key='last_macos_error'")
        if result:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('last_macos_result',?)",
                (str(result)[:100],),
            )
        else:
            conn.execute("DELETE FROM meta WHERE key='last_macos_result'")
        if message:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('last_macos_message',?)",
                (str(message)[:1200],),
            )
        else:
            conn.execute("DELETE FROM meta WHERE key='last_macos_message'")
        conn.commit()


def collect_macos_logs() -> dict:
    if sys.platform != "darwin":
        return {"ok": False, "error": "Local macOS log collection is available only when this dashboard runs on macOS."}
    # Restrict the search to a short window and common authentication-related processes.
    # Do not ask for --info; retain only recognized failed-authentication messages below.
    predicate = (
        'process == "sshd" OR process == "sudo" OR process == "loginwindow" OR '
        'process == "authd" OR process == "opendirectoryd" OR '
        'process == "securityd" OR process == "coreauthd"'
    )
    cmd = ["/usr/bin/log", "show", "--last", "10m", "--style", "json", "--predicate", predicate]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        err = "Focused macOS log query exceeded 30 seconds. The query was stopped; no event data was imported."
        _record_macos_attempt(err, result="failed", message=err)
        return {"ok": False, "error": err}
    except Exception as exc:
        err = f"Could not execute macOS log command: {exc}"
        _record_macos_attempt(err, result="failed", message=err)
        return {"ok": False, "error": err}
    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "macOS log command failed")[:1000]
        _record_macos_attempt(err, result="failed", message=err)
        return {"ok": False, "error": err}
    text = proc.stdout.strip()
    records = []
    if text:
        try:
            obj = json.loads(text)
            records = obj if isinstance(obj, list) else ([obj] if isinstance(obj, dict) else [])
        except json.JSONDecodeError:
            for line in text.splitlines():
                try:
                    item = json.loads(line)
                    records.extend(item if isinstance(item, list) else [item] if isinstance(item, dict) else [])
                except json.JSONDecodeError:
                    continue
    events = []
    seen = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        message = str(r.get("eventMessage") or r.get("message") or r.get("composedMessage") or "")
        process = str(r.get("process") or r.get("processImagePath") or r.get("senderImagePath") or r.get("sender") or "")
        sender = Path(process).name if "/" in process else process
        combined = (message + " " + sender).lower()
        if not is_relevant_macos_security_event(message, sender):
            continue
        timestamp = r.get("timestamp") or r.get("date") or r.get("time") or iso_now()
        sev = "medium" if FAILED_LOGIN_RE.search(combined) else "info"
        category = "Authentication" if any(term in combined for term in ("login", "logon", "authentication", "password", "sshd")) else "Privilege / System"
        raw = {"timestamp": timestamp, "severity": sev, "title": f"macOS event ({sender or 'Unified Log'})", "category": category, "source": "macOS Unified Log", "device": platform.node(), "message": message[:6000], "process": sender}
        key = hashlib.sha256((str(timestamp) + sender + message).encode("utf-8", errors="replace")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        events.append(raw)
    result = ingest_raw(events, fallback_source="macOS Unified Log") if events else {"imported": 0, "duplicates": 0, "skipped": 0, "detections_created": 0}
    if events:
        if result.get("imported", 0) > 0:
            outcome = "matched_imported"
        else:
            outcome = "matched_no_new_import"
        status_message = (
            f"Focused macOS query completed: {len(records)} records examined, "
            f"{len(events)} authentication-failure records matched; "
            f"{result.get('imported', 0)} new events, "
            f"{result.get('duplicates', 0)} duplicates."
        )
    else:
        outcome = "no_match"
        status_message = (
            f"Focused macOS query completed: {len(records)} records examined; "
            "no matching authentication-failure records were found in the returned results. "
            "This does not prove that no security events occurred; "
            "macOS privacy settings may limit visibility."
        )
    _record_macos_attempt(None, result=outcome, message=status_message)
    return {"ok": True, **result, "raw_records": len(records), "matched_events": len(events), "message": status_message}


def row_to_public(row) -> dict:
    d = dict(row)
    d.pop("raw_json", None)
    d.pop("fingerprint", None)
    return d


def http_json(handler, obj, status=200):
    payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(payload)


class Handler(BaseHTTPRequestHandler):
    server_version = "PNDCC-SIEM-V3.4.3"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Keep logs concise and avoid dumping request bodies or credentials.
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")

    def _local_only(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError(f"Request body must be at most {MAX_BODY_BYTES // (1024*1024)} MB.")
        data = self.rfile.read(length) if length else b"{}"
        obj = json.loads(data.decode("utf-8-sig"))
        if not isinstance(obj, dict):
            raise ValueError("JSON request body must be an object.")
        return obj

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path
        if path == "/" or path == "/index.html":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body); return
        if path == "/favicon.ico":
            self.send_error(204); return
        if path == "/health":
            # Read-only liveness/readiness check. Do not expose local file paths or
            # event contents; report unhealthy if the SQLite store cannot be checked.
            try:
                with db_connect() as conn:
                    check = conn.execute("PRAGMA quick_check").fetchone()
                integrity = str(check[0]) if check else "unknown"
                healthy = integrity.lower() == "ok"
                http_json(self, {
                    "ok": healthy,
                    "status": "healthy" if healthy else "unhealthy",
                    "app": APP_NAME,
                    "version": APP_VERSION,
                    "database": "ok" if healthy else "check_failed",
                    "local_only": True,
                }, 200 if healthy else 503)
            except Exception:
                # Keep diagnostics generic to avoid exposing paths or DB internals.
                http_json(self, {
                    "ok": False,
                    "status": "unhealthy",
                    "app": APP_NAME,
                    "version": APP_VERSION,
                    "database": "unavailable",
                    "local_only": True,
                }, 503)
            return
        if path == "/api/status":
            try: http_json(self, status_data())
            except Exception as exc: http_json(self, {"error": str(exc)}, 500)
            return
        if path == "/api/events":
            qs = parse_qs(p.query); limit = qs.get("limit", ["1000"])[0]
            try: events = list_events(int(limit)); http_json(self, {"events": events, "count": len(events)})
            except Exception as exc: http_json(self, {"error": str(exc)}, 400)
            return
        if path == "/api/export":
            try:
                events = list_events(MAX_EVENTS)
                with db_connect() as conn:
                    rows = conn.execute("SELECT raw_json FROM events ORDER BY timestamp ASC,id ASC").fetchall()
                text = "\n".join(row[0] for row in rows) + ("\n" if rows else "")
                body = text.encode("utf-8")
                self.send_response(200); self.send_header("Content-Type", "application/x-ndjson; charset=utf-8"); self.send_header("Content-Disposition", 'attachment; filename="PNDCC_SIEM_V3_4_3_Export.jsonl"'); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            except Exception as exc: http_json(self, {"error": str(exc)}, 500)
            return
        if path == "/download/windows-collector.ps1":
            body = WINDOWS_COLLECTOR.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.send_header("Content-Disposition", 'attachment; filename="PNDCC_SIEM_Windows_Collector_V3_4_3.ps1"'); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        http_json(self, {"error": "Not found"}, 404)

    def do_POST(self):
        if not self._local_only():
            http_json(self, {"error": "Local-only endpoint."}, 403); return
        path = urlparse(self.path).path
        try:
            body = self._read_json()
            if path == "/api/import":
                filename = str(body.get("filename") or "import.json")[:200]
                content = body.get("content")
                if not isinstance(content, str): raise ValueError("content must be the text of a JSON/JSONL file.")
                raws = parse_import_content(content)
                if not raws: raise ValueError("No valid JSON records were found in that file.")
                result = ingest_raw(raws, fallback_source=filename)
                result["filename"] = filename
                http_json(self, result); return
            if path == "/api/ingest":
                # For future adapters: deliberately localhost-only until authenticated TLS transport is implemented.
                events = body.get("events", [])
                if not isinstance(events, list): raise ValueError("events must be a JSON array.")
                source = str(body.get("source") or "Local Adapter")[:160]
                result = ingest_raw(events, fallback_source=source)
                http_json(self, result); return
            if path == "/api/collect/macos":
                result = collect_macos_logs()
                http_json(self, result, 200 if result.get("ok") else 400); return
            if path == "/api/events/status":
                event_id = body.get("id")
                status = str(body.get("status") or "").lower()
                if status not in ("new", "acknowledged", "resolved"): raise ValueError("status must be new, acknowledged, or resolved.")
                try: eid = int(event_id)
                except Exception: raise ValueError("A numeric event id is required.")
                with LOCK, db_connect() as conn:
                    cur = conn.execute("UPDATE events SET status=? WHERE id=?", (status, eid))
                    conn.commit()
                if cur.rowcount == 0: http_json(self, {"error": "Event not found."}, 404)
                else: http_json(self, {"ok": True, "id": eid, "status": status})
                return
            http_json(self, {"error": "Not found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            http_json(self, {"error": str(exc)}, 400)
        except Exception as exc:
            http_json(self, {"error": f"Request failed: {exc}"}, 500)


def main():
    ensure_db()
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        print(f"Could not start PNDCC SIEM V3 on {HOST}:{PORT}: {exc}")
        print("If this port is already in use, stop the other SIEM trial or set PNDCC_SIEM_PORT to another local port.")
        raise SystemExit(2)
    server.daemon_threads = True
    print("=" * 64)
    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Dashboard: http://{HOST}:{PORT}")
    print(f"Local SQLite event store: {DB_PATH}")
    print(f"Retention cap: {MAX_EVENTS} records")
    print("Network binding: 127.0.0.1 only; event intake is not exposed to the LAN")
    print(f"Platform: {platform.platform()}")
    print("macOS collection: available only when running on macOS")
    print("Windows collection: downloadable PowerShell export; import JSONL on the Mac")
    print("Wazuh / cloud SIEM: not configured; no simulated live events")
    print("Simple is the best.")
    print("Developer: Saiful Quadir")
    print("Press Ctrl+C to stop this standalone trial.")
    print("=" * 64)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping PNDCC SIEM V3.4.3…")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
