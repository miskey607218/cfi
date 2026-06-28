#!/usr/bin/env python3
"""
server.py — CFI/DFI 动态可视化服务器
====================================
启动本地 Web 服务器，提供 REST API 和动态前端页面。
前端通过 fetch() 实时拉取数据，支持图表交互、过滤、自动刷新。

用法:
    cd final
    python3 src/server.py                    # 默认端口 8080
    python3 src/server.py -p 3000            # 自定义端口
    python3 src/server.py -d output          # 自定义数据目录

浏览器打开: http://localhost:8080
"""

import sys
import os
import csv
import json
import time
import argparse
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ============================================================
#  数据加载
# ============================================================

class DataStore:
    def __init__(self, output_dir, prefix='demo'):
        self.output_dir = output_dir
        self.prefix = prefix
        self.cfi_rows = []
        self.dfi_rows = []
        self.last_load = 0
        self.load_interval = 2  # 每2秒重新加载
        self._lock = threading.Lock()

    def _cfi_path(self):
        return os.path.join(self.output_dir, f'{self.prefix}_cfi_events.csv')

    def _dfi_path(self):
        return os.path.join(self.output_dir, f'{self.prefix}_dfi_layers.csv')

    def reload_if_needed(self):
        now = time.time()
        if now - self.last_load < self.load_interval:
            return
        self.last_load = now

        with self._lock:
            # 加载 CFI
            cfi = []
            cfi_path = self._cfi_path()
            if os.path.exists(cfi_path):
                with open(cfi_path, 'r', encoding='utf-8') as f:
                    for r in csv.DictReader(f):
                        r['jump_type'] = int(r['jump_type'])
                        r['is_correct'] = int(r['is_correct'])
                        r['timestamp_ns'] = int(r['timestamp_ns'])
                        cfi.append(r)

            if cfi:
                t0 = cfi[0]['timestamp_ns']
                for r in cfi:
                    r['elapsed_ms'] = round((r['timestamp_ns'] - t0) / 1_000_000, 3)
            self.cfi_rows = cfi

            # 加载 DFI
            dfi = []
            dfi_path = self._dfi_path()
            if os.path.exists(dfi_path):
                with open(dfi_path, 'r', encoding='utf-8') as f:
                    for r in csv.DictReader(f):
                        r['layer'] = int(r['layer'])
                        r['site_id'] = int(r['site_id'])
                        r['timestamp_ns'] = int(r['timestamp_ns'])
                        dfi.append(r)
            if dfi:
                t0 = dfi[0]['timestamp_ns']
                for r in dfi:
                    r['elapsed_ms'] = round((r['timestamp_ns'] - t0) / 1_000_000, 3)
            self.dfi_rows = dfi

    def get_summary(self):
        self.reload_if_needed()
        cfi = self.cfi_rows
        dfi = self.dfi_rows

        jt_names = {3: 'RET', 4: 'INDIRECT_CALL', 5: 'INDIRECT_JMP'}
        jt_dist = defaultdict(int)
        func_counts = defaultdict(int)
        violations = 0
        for r in cfi:
            jt_dist[jt_names.get(r['jump_type'], 'UNKNOWN')] += 1
            func_counts[r['src_func']] += 1
            if r['is_correct'] == 0:
                violations += 1

        funcs = sorted([{'name': n, 'count': c} for n, c in func_counts.items()],
                       key=lambda x: -x['count'])

        layer_dist = defaultdict(int)
        for r in dfi:
            layer_dist[f'L{r["layer"]}'] += 1

        # 构建 site 数据流链
        site_map = defaultdict(lambda: {'func': '', 'layers': {}})
        for r in dfi:
            sid = str(r['site_id'])
            site_map[sid]['func'] = r['func_name']
            site_map[sid]['layers'][str(r['layer'])] = {
                'reg_value': r['reg_value'],
                'target_addr': r['target_addr'],
                'instr_type': r['instr_type_name'],
                'inst_offset': r['inst_offset'],
                'elapsed_ms': r['elapsed_ms'],
            }

        return {
            'total_cfi': len(cfi),
            'total_dfi': len(dfi),
            'violations': violations,
            'correct_rate': round((1 - violations / len(cfi)) * 100, 1) if cfi else 0,
            'jt_dist': dict(jt_dist),
            'layer_dist': dict(layer_dist),
            'funcs': funcs[:30],
            'site_chains': {k: {'func': v['func'], 'layers': v['layers']}
                           for k, v in sorted(site_map.items(), key=lambda x: int(x[0]))},
            'max_time_ms': cfi[-1]['elapsed_ms'] if cfi else 0,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

    def get_cfi_events(self, offset=0, limit=200, jump_type=None, src_func=None,
                       is_correct=None, search=None):
        self.reload_if_needed()
        rows = self.cfi_rows

        if jump_type is not None:
            rows = [r for r in rows if r['jump_type'] == jump_type]
        if src_func:
            rows = [r for r in rows if r['src_func'] == src_func]
        if is_correct is not None:
            rows = [r for r in rows if r['is_correct'] == is_correct]
        if search:
            q = search.lower()
            rows = [r for r in rows if q in r['src_func'].lower() or
                    q in r.get('dst_func', '').lower()]

        total = len(rows)
        page = rows[offset:offset + limit]
        return {
            'total': total,
            'offset': offset,
            'limit': limit,
            'rows': page,
        }

    def get_dfi_events(self, offset=0, limit=200):
        self.reload_if_needed()
        rows = self.dfi_rows
        total = len(rows)
        page = rows[offset:offset + limit]
        return {'total': total, 'offset': offset, 'limit': limit, 'rows': page}


# ============================================================
#  HTTP 服务器
# ============================================================

store = None

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # 静默

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, code=200):
        body = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, content_type, code=200):
        body = STATIC_FILES.get(self.path, b'')
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        def p(key, default=None, cast=int):
            v = params.get(key, [None])[0]
            if v is None:
                return default
            try:
                return cast(v)
            except (ValueError, TypeError):
                return default

        if path == '/':
            self._send_html(FRONTEND_HTML)
        elif path == '/api/summary':
            self._send_json(store.get_summary())
        elif path == '/api/cfi_events':
            result = store.get_cfi_events(
                offset=p('offset', 0),
                limit=p('limit', 200),
                jump_type=p('jump_type', None),
                src_func=params.get('src_func', [None])[0],
                is_correct=p('is_correct', None),
                search=params.get('search', [None])[0],
            )
            self._send_json(result)
        elif path == '/api/dfi_events':
            result = store.get_dfi_events(
                offset=p('offset', 0),
                limit=p('limit', 200),
            )
            self._send_json(result)
        elif path == '/api/dfi_chains':
            summary = store.get_summary()
            self._send_json(summary.get('site_chains', {}))
        else:
            self.send_error(404)


# ============================================================
#  前端 HTML (内嵌)
# ============================================================

FRONTEND_HTML = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CFI/DFI 动态监控面板</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--bg-alt:#161b22;--bg-card:#1c2129;
  --border:#30363d;--fg:#c9d1d9;--fg-dim:#8b949e;
  --accent:#58a6ff;--accent2:#bc8cff;--good:#3fb950;
  --bad:#f85149;--warn:#d2991d;
  --radius:8px;--font:system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--fg);min-height:100vh}
.topbar{
  background:var(--bg-alt);border-bottom:1px solid var(--border);
  padding:12px 24px;display:flex;align-items:center;gap:20px;
  position:sticky;top:0;z-index:100;
}
.topbar h1{font-size:18px;font-weight:600}
.topbar .live-dot{
  width:10px;height:10px;background:var(--good);border-radius:50%;
  animation:pulse 2s infinite;
}
@keyframes pulse{50%{opacity:0.4}}
.topbar .status{font-size:12px;color:var(--fg-dim)}
.topbar .refresh-btn{
  margin-left:auto;padding:6px 14px;background:var(--accent);
  color:#fff;border:none;border-radius:var(--radius);cursor:pointer;
  font-size:12px;font-weight:600;
}
.topbar .refresh-btn:hover{opacity:0.85}

.main{padding:20px 24px;max-width:1400px;margin:0 auto}

/* Stats row */
.stats-row{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:14px;margin-bottom:20px;
}
.stat{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 18px;
}
.stat .label{font-size:11px;color:var(--fg-dim);text-transform:uppercase;letter-spacing:0.5px}
.stat .value{font-size:26px;font-weight:700;margin-top:4px}
.stat .sub{font-size:11px;color:var(--fg-dim);margin-top:2px}
.value.good{color:var(--good)}.value.warn{color:var(--warn)}.value.bad{color:var(--bad)}

/* Charts row */
.charts-row{
  display:grid;grid-template-columns:1fr 1fr;
  gap:14px;margin-bottom:20px;
}
@media(max-width:900px){.charts-row{grid-template-columns:1fr}}
.chart-card{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px;
}
.chart-card h3{font-size:13px;color:var(--fg-dim);margin-bottom:10px}
.chart-wrap{position:relative;height:260px}
.chart-wrap canvas{width:100%!important;height:100%!important}

/* Tabs */
.tabs{display:flex;gap:0;margin-bottom:0}
.tab-btn{
  padding:8px 18px;background:transparent;border:1px solid var(--border);
  border-bottom:none;color:var(--fg-dim);cursor:pointer;
  font-size:13px;border-radius:var(--radius) var(--radius) 0 0;
  margin-right:-1px;
}
.tab-btn.active{background:var(--bg-card);color:var(--fg);font-weight:600}
.tab-content{display:none}
.tab-content.active{
  display:block;background:var(--bg-card);border:1px solid var(--border);
  border-radius:0 var(--radius) var(--radius) var(--radius);padding:16px;
}

/* Table */
.toolbar{
  display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;align-items:center;
}
.toolbar input,.toolbar select{
  background:var(--bg);border:1px solid var(--border);color:var(--fg);
  padding:6px 10px;border-radius:4px;font-size:12px;
}
.toolbar input:focus,.toolbar select:focus{outline:none;border-color:var(--accent)}
.toolbar input{min-width:200px}
.table-wrap{overflow-x:auto;max-height:500px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{
  background:var(--bg-alt);color:var(--fg-dim);padding:7px 10px;
  text-align:left;font-weight:600;font-size:11px;
  text-transform:uppercase;position:sticky;top:0;z-index:1;
}
td{padding:5px 10px;border-bottom:1px solid rgba(48,54,61,0.5);color:var(--fg-dim)}
tr:hover td{background:rgba(88,166,255,0.04)}
.badge{
  display:inline-block;padding:2px 7px;border-radius:10px;
  font-size:10px;font-weight:600;
}
.badge.ret{background:rgba(88,166,255,0.15);color:var(--accent)}
.badge.call{background:rgba(188,140,255,0.15);color:var(--accent2)}
.badge.jmp{background:rgba(210,153,29,0.15);color:var(--warn)}
.badge.ok{background:rgba(63,185,80,0.15);color:var(--good)}
.badge.violation{background:rgba(248,81,73,0.15);color:var(--bad)}

/* DFI Chains */
.chain-grid{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));
  gap:12px;
}
.chain-card{
  background:var(--bg);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;
}
.chain-header{
  padding:8px 14px;background:rgba(88,166,255,0.06);
  border-bottom:1px solid var(--border);
  font-weight:600;font-size:13px;
}
.chain-row{
  display:flex;gap:10px;padding:6px 14px;
  border-bottom:1px solid rgba(48,54,61,0.3);
  font-family:monospace;font-size:11px;align-items:baseline;
}
.chain-row .lvl{color:var(--accent2);font-weight:700;min-width:20px}
.chain-row .addr{color:var(--fg-dim);min-width:90px}
.chain-row .val{color:var(--warn);word-break:break-all}

/* Pagination */
.pagination{
  display:flex;gap:6px;margin-top:12px;justify-content:center;align-items:center;
}
.pagination button{
  padding:4px 12px;background:var(--bg);border:1px solid var(--border);
  color:var(--fg);border-radius:4px;cursor:pointer;font-size:12px;
}
.pagination button:hover{background:var(--bg-alt)}
.pagination button:disabled{opacity:0.4;cursor:default}
.pagination span{font-size:12px;color:var(--fg-dim)}
</style>
</head>
<body>

<div class="topbar">
  <h1>CFI/DFI 动态监控面板</h1>
  <span class="status" id="status">加载中...</span>
  <button class="refresh-btn" onclick="refreshAll()">⟳ 刷新数据</button>
</div>

<div class="main">

  <div class="stats-row" id="stats-row"></div>

  <div class="charts-row">
    <div class="chart-card">
      <h3>跳转类型分布</h3>
      <div class="chart-wrap"><canvas id="chart-jt"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>DFI 层事件分布</h3>
      <div class="chart-wrap"><canvas id="chart-layer"></canvas></div>
    </div>
  </div>

  <div class="chart-card" style="margin-bottom:20px">
    <h3>CFI 事件正确率时间线（每50事件）</h3>
    <div class="chart-wrap"><canvas id="chart-timeline"></canvas></div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('cfi')">CFI 事件表</button>
    <button class="tab-btn" onclick="switchTab('dfi')">DFI 数据流链</button>
  </div>

  <div class="tab-content active" id="tab-cfi">
    <div class="toolbar">
      <input type="text" id="cfi-search" placeholder="搜索函数名..." oninput="loadCfiEvents()">
      <select id="cfi-type-filter" onchange="loadCfiEvents()">
        <option value="">全部类型</option>
        <option value="3">RET</option>
        <option value="4">INDIRECT_CALL</option>
        <option value="5">INDIRECT_JMP</option>
      </select>
      <select id="cfi-correct-filter" onchange="loadCfiEvents()">
        <option value="">全部</option>
        <option value="1">✓ 正确</option>
        <option value="0">✗ 违规</option>
      </select>
    </div>
    <div class="table-wrap"><table id="cfi-table"></table></div>
    <div class="pagination" id="cfi-pager"></div>
  </div>

  <div class="tab-content" id="tab-dfi">
    <div class="chain-grid" id="chain-grid"></div>
  </div>

</div>

<script>
let SUMMARY = {};
let cfiPage = 0, cfiTotal = 0;
const PAGE_SIZE = 100;

async function api(path) {
  const r = await fetch(path);
  return r.json();
}

async function refreshAll() {
  SUMMARY = await api('/api/summary');
  renderStats();
  renderCharts();
  await loadCfiEvents();
  await loadDfiChains();
  document.getElementById('status').textContent =
    `已更新 ${SUMMARY.timestamp}  |  ${SUMMARY.total_cfi} 事件  |  ${SUMMARY.total_dfi} DFI层`;
}

function renderStats() {
  const s = SUMMARY;
  const rate = s.correct_rate;
  document.getElementById('stats-row').innerHTML = `
    <div class="stat"><div class="label">CFI 事件</div><div class="value">${s.total_cfi}</div></div>
    <div class="stat"><div class="label">DFI 层事件</div><div class="value">${s.total_dfi}</div></div>
    <div class="stat"><div class="label">违规</div><div class="value ${s.violations>0?'bad':'good'}">${s.violations}</div></div>
    <div class="stat"><div class="label">正确率</div><div class="value ${rate>95?'good':rate>80?'warn':'bad'}">${rate}%</div></div>
    <div class="stat"><div class="label">时间跨度</div><div class="value" style="font-size:18px">${s.max_time_ms.toFixed(0)} ms</div></div>
  `;
}

let chartJT = null, chartLayer = null, chartTimeline = null;

function renderCharts() {
  const s = SUMMARY;

  // Jump type pie
  const ctx1 = document.getElementById('chart-jt').getContext('2d');
  if(chartJT) chartJT.destroy();
  const jt = s.jt_dist;
  chartJT = new Chart(ctx1, {
    type:'doughnut',
    data:{
      labels:Object.keys(jt),
      datasets:[{data:Object.values(jt),backgroundColor:['#58a6ff','#bc8cff','#d2991d']}]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b949e',font:{size:11}}}}}
  });

  // Layer bar
  const ctx2 = document.getElementById('chart-layer').getContext('2d');
  if(chartLayer) chartLayer.destroy();
  const ld = s.layer_dist;
  chartLayer = new Chart(ctx2, {
    type:'bar',
    data:{
      labels:Object.keys(ld).sort(),
      datasets:[{data:Object.values(ld).sort((a,b)=>a-b),
        backgroundColor:['#3fb950','#58a6ff','#bc8cff']}]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{y:{grid:{color:'#30363d'},ticks:{color:'#8b949e'}},
              x:{grid:{display:false},ticks:{color:'#8b949e'}}}}
  });

  // Correct rate timeline (compute locally from first load)
  fetch('/api/cfi_events?offset=0&limit=9999').then(r=>r.json()).then(data=>{
    const ctx3 = document.getElementById('chart-timeline').getContext('2d');
    if(chartTimeline) chartTimeline.destroy();
    const rows = data.rows;
    const bins = [];
    const binSize = 50;
    for(let i=0;i<rows.length;i+=binSize){
      const chunk = rows.slice(i,i+binSize);
      const ok = chunk.filter(r=>r.is_correct==1).length;
      bins.push({x:i+1,y:(ok/chunk.length*100)});
    }
    chartTimeline = new Chart(ctx3, {
      type:'line',
      data:{
        labels:bins.map(b=>b.x),
        datasets:[{
          label:'正确率 %',data:bins.map(b=>b.y.toFixed(1)),
          borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,0.1)',
          fill:true,tension:0.3,pointRadius:0
        }]
      },
      options:{responsive:true,maintainAspectRatio:false,
        plugins:{legend:{labels:{color:'#8b949e'}}},
        scales:{
          y:{min:0,max:100,grid:{color:'#30363d'},ticks:{color:'#8b949e',callback:v=>v+'%'}},
          x:{grid:{display:false},ticks:{color:'#8b949e'}}
        }
      }
    });
  });
}

// CFI Events table
async function loadCfiEvents(offset=0) {
  cfiPage = offset;
  const type = document.getElementById('cfi-type-filter')?.value || '';
  const correct = document.getElementById('cfi-correct-filter')?.value || '';
  const search = document.getElementById('cfi-search')?.value || '';

  let url = `/api/cfi_events?offset=${offset}&limit=${PAGE_SIZE}`;
  if(type) url += '&jump_type=' + type;
  if(correct) url += '&is_correct=' + correct;
  if(search) url += '&search=' + encodeURIComponent(search);

  const data = await api(url);
  cfiTotal = data.total;

  const jtNames = {3:'RET',4:'INDIRECT_CALL',5:'INDIRECT_JMP'};
  document.getElementById('cfi-table').innerHTML = `
    <thead><tr>
      <th>#</th><th>时间(ms)</th><th>类型</th><th>源函数</th>
      <th>RAX</th><th>ret_addr</th><th>RSP</th><th>RBP</th>
      <th>saved_rax</th><th>saved_rsp</th><th>CS哈希</th><th>结果</th>
    </tr></thead>
    <tbody>${data.rows.map(r=>`<tr>
      <td>${r.event_id}</td>
      <td style="color:var(--info)">${r.elapsed_ms}</td>
      <td><span class="badge ${r.jump_type==3?'ret':r.jump_type==4?'call':'jmp'}">${jtNames[r.jump_type]||r.jump_type}</span></td>
      <td>${r.src_func||'-'}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.reg_rax}">${(r.reg_rax||'0x0').slice(0,14)}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.ret_addr}">${(r.ret_addr||'-').slice(0,14)}</td>
      <td style="font-family:monospace;font-size:10px">${(r.reg_rsp||'0x0').slice(0,14)}</td>
      <td style="font-family:monospace;font-size:10px">${(r.reg_rbp||'0x0').slice(0,14)}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.saved_rax_val}">${(r.saved_rax_val||'0x0').slice(0,14)}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.saved_rsp_val}">${(r.saved_rsp_val||'0x0').slice(0,14)}</td>
      <td style="font-family:monospace;font-size:10px">${(r.call_stack_hash||'0x0').slice(0,14)}</td>
      <td><span class="badge ${r.is_correct?'ok':'violation'}">${r.is_correct?'✓':'✗'}</span></td>
    </tr>`).join('')}</tbody>`;

  // Pagination
  const totalPages = Math.ceil(cfiTotal / PAGE_SIZE);
  const curPage = Math.floor(offset / PAGE_SIZE) + 1;
  document.getElementById('cfi-pager').innerHTML = `
    <button ${offset==0?'disabled':''} onclick="loadCfiEvents(0)">««</button>
    <button ${offset==0?'disabled':''} onclick="loadCfiEvents(${Math.max(0,offset-PAGE_SIZE)})">«</button>
    <span>${curPage} / ${totalPages} (${cfiTotal} 条)</span>
    <button ${offset+PAGE_SIZE>=cfiTotal?'disabled':''} onclick="loadCfiEvents(${offset+PAGE_SIZE})">»</button>
    <button ${offset+PAGE_SIZE>=cfiTotal?'disabled':''} onclick="loadCfiEvents(${Math.max(0,cfiTotal-PAGE_SIZE)})">»»</button>
  `;
}

// DFI Chains
async function loadDfiChains() {
  const chains = await api('/api/dfi_chains');
  const entries = Object.entries(chains);
  document.getElementById('chain-grid').innerHTML = entries.map(([sid,ch])=>{
    const ly = ch.layers;
    return `<div class="chain-card">
      <div class="chain-header">Site #${sid} — ${ch.func||'?'}</div>
      ${[1,2,3].map(l=>{
        const v = ly[l];
        if(!v) return '';
        return `<div class="chain-row">
          <span class="lvl">L${l}</span>
          <span class="addr">${v.inst_offset||'?'}</span>
          <span style="color:var(--fg-dim);min-width:60px">${v.instr_type||'?'}</span>
          <span class="val">reg=${v.reg_value||'0x0'}</span>
          <span class="val">→ ${v.target_addr||'0x0'}</span>
        </div>`;
      }).join('')}
    </div>`;
  }).join('');
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
  document.querySelector(`[onclick="switchTab('${name}')"]`).classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}

// 页面加载时获取一次数据
refreshAll();
</script>
</body>
</html>'''


# ============================================================
#  主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='CFI/DFI 动态可视化服务器')
    parser.add_argument('-d', '--data-dir', default=None, help='数据目录')
    parser.add_argument('-P', '--prefix', default='demo', help='文件前缀 (默认: demo)')
    args = parser.parse_args()
    PORT = 8080

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.data_dir or os.path.join(script_dir, '..', 'output')
    output_dir = os.path.abspath(output_dir)

    global store
    store = DataStore(output_dir, args.prefix)

    # 获取本机 IP
    local_ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in ('127.0.0.1', '::1') and not ip.startswith('fe80:'):
                local_ips.append(ip)
        local_ips = list(dict.fromkeys(local_ips))  # 去重保序
    except Exception:
        pass

    print(f"""
╔══════════════════════════════════════════════╗
║   CFI/DFI 动态监控面板                        ║
╠══════════════════════════════════════════════╣
║  数据目录: {output_dir:<33s} ║
║  文件前缀: {args.prefix:<33s} ║
║                                            ║
║  访问地址:                                   ║""")
    print(f"║    http://localhost:{PORT:<36} ║")
    for ip in local_ips:
        print(f"║    http://{ip}:{PORT:<36} ║")
    print(f"""║                                            ║
║  按 Ctrl+C 停止服务器                         ║
╚══════════════════════════════════════════════╝
""")

    server = HTTPServer(('0.0.0.0', PORT), APIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        server.shutdown()


if __name__ == '__main__':
    main()
