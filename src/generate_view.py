#!/usr/bin/env python3
"""
generate_view.py — CFI/DFI 运行结果可视化生成器
===============================================
读取 output/ 下的 demo_cfi_events.csv + demo_dfi_layers.csv，
生成自包含交互式 HTML 页面。

用法:
    cd final
    python3 src/generate_view.py                          # 默认
    python3 src/generate_view.py -p demo                  # 指定前缀
    python3 src/generate_view.py -p demo -o my_view.html  # 指定输出
"""

import sys
import os
import csv
import json
import argparse
from collections import defaultdict

# ============================================================
#  1. CSV 读取
# ============================================================

def read_cfi_csv(filepath: str) -> list[dict]:
    rows = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            # 标准化时间（ns → ms, 相对起点）
            r['ts_ns'] = int(r['timestamp_ns'])
            r['jump_type'] = int(r['jump_type'])
            r['is_correct'] = int(r['is_correct'])
            rows.append(r)
    if not rows:
        print(f"警告: {filepath} 为空")
        return rows

    # 相对时间
    t0 = rows[0]['ts_ns']
    for r in rows:
        r['elapsed_ms'] = (r['ts_ns'] - t0) / 1_000_000
    return rows


def read_dfi_csv(filepath: str) -> list[dict]:
    rows = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            r['ts_ns'] = int(r['timestamp_ns'])
            r['layer'] = int(r['layer'])
            r['site_id'] = int(r['site_id'])
            rows.append(r)
    if not rows:
        return rows
    t0 = rows[0]['ts_ns']
    for r in rows:
        r['elapsed_ms'] = (r['ts_ns'] - t0) / 1_000_000
    return rows


# ============================================================
#  2. 分析
# ============================================================

def analyze(cfi_rows, dfi_rows):
    # 函数统计
    func_counts = defaultdict(int)
    for r in cfi_rows:
        func_counts[r['src_func']] += 1
    funcs = [{'name': n, 'count': c} for n, c in
             sorted(func_counts.items(), key=lambda x: -x[1])]
    for i, f in enumerate(funcs):
        hue = (i * 27 + 10) % 360
        f['color'] = f'hsl({hue}, 70%, 65%)'

    # 跳转类型分布
    jt_names = {3: 'RET', 4: 'INDIRECT_CALL', 5: 'INDIRECT_JMP'}
    jt_dist = defaultdict(int)
    for r in cfi_rows:
        jt_dist[jt_names.get(r['jump_type'], f"UNK({r['jump_type']})")] += 1

    # 违规统计
    violations = [r for r in cfi_rows if r['is_correct'] == 0]

    # DFI 层统计
    layer_dist = defaultdict(int)
    for r in dfi_rows:
        layer_dist[f"L{r['layer']}"] += 1

    # 站点-层 数据流链
    site_chains = defaultdict(lambda: {'func': '', 'layers': {}})
    for r in dfi_rows:
        sid = r['site_id']
        site_chains[sid]['func'] = r['func_name']
        site_chains[sid]['layers'][r['layer']] = {
            'reg_value': r['reg_value'],
            'target_addr': r['target_addr'],
            'instr_type': r['instr_type_name'],
            'inst_offset': r['inst_offset'],
        }

    return {
        'funcs': funcs,
        'jt_dist': dict(jt_dist),
        'violations': len(violations),
        'total_cfi': len(cfi_rows),
        'total_dfi': len(dfi_rows),
        'layer_dist': dict(layer_dist),
        'site_chains': {str(k): v for k, v in site_chains.items()},
        'max_time_ms': cfi_rows[-1]['elapsed_ms'] if cfi_rows else 0,
    }


# ============================================================
#  3. HTML 模板
# ============================================================

HTML = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CFI/DFI 运行结果 — 可视化</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#1a1b26;--bg-alt:#24253a;--bg-hover:#2f3150;
  --fg:#c0caf5;--fg-dim:#787c99;--fg-bright:#e0e2f8;
  --border:#3b3d5c;--accent:#7aa2f7;--accent2:#bb9af7;
  --warn:#e0af68;--good:#9ece6a;--bad:#f7768e;--info:#7dcfff;
  --radius:6px;
}
body{
  font-family:'Segoe UI',system-ui,sans-serif;
  background:var(--bg);color:var(--fg);
  padding:20px;max-width:1200px;margin:0 auto;
}
h1{font-size:18px;color:var(--fg-bright);margin-bottom:16px}
h2{font-size:15px;color:var(--accent);margin:20px 0 10px}
.stats{
  display:flex;gap:20px;flex-wrap:wrap;margin-bottom:16px;
}
.stat-card{
  background:var(--bg-alt);border:1px solid var(--border);
  border-radius:var(--radius);padding:12px 18px;min-width:140px;
}
.stat-card .label{font-size:11px;color:var(--fg-dim);text-transform:uppercase}
.stat-card .value{font-size:22px;font-weight:700;color:var(--fg-bright)}
.stat-card .value.good{color:var(--good)}
.stat-card .value.warn{color:var(--warn)}
table{
  width:100%;border-collapse:collapse;
  font-size:12px;margin:10px 0;
}
th{
  background:var(--bg-alt);color:var(--fg-dim);padding:6px 10px;
  text-align:left;font-weight:600;font-size:11px;
  text-transform:uppercase;border-bottom:2px solid var(--border);
}
td{
  padding:5px 10px;border-bottom:1px solid rgba(59,61,92,0.3);
  color:var(--fg-dim);
}
tr:hover td{background:var(--bg-hover)}
.badge{
  display:inline-block;padding:2px 8px;border-radius:10px;
  font-size:10px;font-weight:600;
}
.badge.ret{background:rgba(122,162,247,0.2);color:var(--accent)}
.badge.call{background:rgba(187,154,247,0.2);color:var(--accent2)}
.badge.ok{background:rgba(158,206,106,0.2);color:var(--good)}
.badge.bad{background:rgba(247,118,142,0.2);color:var(--bad)}

/* DFI 数据流链卡片 */
.chain-grid{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
  gap:12px;margin:10px 0;
}
.chain-card{
  background:var(--bg-alt);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;
}
.chain-card .header{
  padding:8px 14px;background:rgba(122,162,247,0.08);
  border-bottom:1px solid var(--border);
  font-weight:600;font-size:13px;
}
.chain-card .layer{
  padding:6px 14px;font-family:monospace;font-size:11px;
  border-bottom:1px solid rgba(59,61,92,0.2);
  display:flex;gap:12px;align-items:baseline;
}
.chain-card .layer .lvl{
  font-weight:700;min-width:22px;
  color:var(--accent2)
}
.chain-card .layer .val{color:var(--warn)}
.chain-card .layer .addr{color:var(--fg-dim);font-size:10px}

/* 进度条 */
.bar-container{
  background:var(--bg);border-radius:4px;height:20px;
  margin:4px 0;overflow:hidden;
}
.bar{
  height:100%;border-radius:4px;transition:width 0.3s;
  display:flex;align-items:center;justify-content:center;
  font-size:10px;font-weight:600;
}
.bar.good-bar{background:var(--good);color:#1a1b26}
.bar.bad-bar{background:var(--bad);color:#fff}

/* 时间线图 */
#timeline-canvas{
  width:100%;height:200px;
  border:1px solid var(--border);border-radius:var(--radius);
  background:var(--bg-alt);
}
</style>
</head>
<body>

<h1>📊 CFI/DFI 运行结果可视化</h1>

<div class="stats" id="stats"></div>

<h2>📋 CFI 事件概览</h2>
<div id="cfi-overview"></div>

<h2>🔍 三层 DFI 数据流链</h2>
<div class="chain-grid" id="dfi-chains"></div>

<h2>📈 CFI 事件时间线</h2>
<canvas id="timeline-canvas"></canvas>

<h2>📝 违规事件详情</h2>
<div id="violation-detail"></div>

<script>
const DATA = __DATA__;

// Stats
document.getElementById('stats').innerHTML = `
<div class="stat-card"><div class="label">CFI 事件</div><div class="value">${DATA.total_cfi}</div></div>
<div class="stat-card"><div class="label">DFI 层事件</div><div class="value">${DATA.total_dfi}</div></div>
<div class="stat-card"><div class="label">违规</div><div class="value ${DATA.violations>0?'warn':'good'}">${DATA.violations}</div></div>
<div class="stat-card"><div class="label">正确率</div><div class="value ${DATA.violations==0?'good':'warn'}">${((1-DATA.violations/DATA.total_cfi)*100).toFixed(1)}%</div></div>
<div class="stat-card"><div class="label">时间跨度</div><div class="value" style="font-size:16px">${DATA.max_time_ms.toFixed(0)} ms</div></div>
`;

// Jump type distribution bar
const jt = DATA.jt_dist;
const totalJt = Object.values(jt).reduce((a,b)=>a+b,0);
document.getElementById('cfi-overview').innerHTML = Object.entries(jt).map(([k,v])=>`
  <div style="margin:4px 0">
    <span style="font-size:12px">${k}</span>
    <span style="font-size:11px;color:var(--fg-dim);margin-left:8px">${v}</span>
    <div class="bar-container">
      <div class="bar good-bar" style="width:${(v/totalJt*100).toFixed(1)}%">${(v/totalJt*100).toFixed(1)}%</div>
    </div>
  </div>
`).join('');

// Violation rate bar
const vRate = DATA.total_cfi > 0 ? (DATA.violations/DATA.total_cfi*100) : 0;
document.getElementById('cfi-overview').innerHTML += `
  <div style="margin:8px 0">
    <span style="font-size:12px">校验通过率</span>
    <div class="bar-container">
      <div class="bar good-bar" style="width:${(100-vRate).toFixed(1)}%">${(100-vRate).toFixed(1)}%</div>
    </div>
  </div>
`;

// DFI chains
const chains = DATA.site_chains;
document.getElementById('dfi-chains').innerHTML = Object.entries(chains).map(([sid,ch])=>{
  const layers = ch.layers;
  return `<div class="chain-card">
    <div class="header">Site #${sid} — ${ch.func}</div>
    ${[1,2,3].map(l=>{
      const ly = layers[l];
      if(!ly) return '';
      return `<div class="layer">
        <span class="lvl">L${l}</span>
        <span>${ly.instr_type || '?'}</span>
        <span class="addr">${ly.inst_offset}</span>
        <span class="val">reg=${ly.reg_value}</span>
        <span class="val">→ ${ly.target_addr}</span>
      </div>`;
    }).join('')}
  </div>`;
}).join('');

// Timeline canvas
const canvas = document.getElementById('timeline-canvas');
const ctx = canvas.getContext('2d');
const W = canvas.parentElement.clientWidth - 42;
canvas.width = W;
const H = 200;
canvas.height = H;

// Category colors
const colors = {3:'#7aa2f7',4:'#bb9af7',5:'#e0af68'};

// Draw compact timeline
const rows = DATA._cfi_sample || [];
if(rows.length > 0) {
  const maxT = DATA.max_time_ms;
  const maxRows = Math.min(rows.length, W);
  const step = Math.max(1, Math.floor(rows.length / maxRows));
  const dotW = Math.max(1, W / Math.min(rows.length, W));

  for(let i=0; i<rows.length; i+=step) {
    const r = rows[i];
    const x = (r.elapsed_ms / maxT) * W;
    const c = colors[r.jump_type] || '#888';
    const isBad = r.is_correct === 0;

    if(isBad){
      ctx.fillStyle = '#f7768e';
      ctx.fillRect(x-1,0,3,H);
    }else{
      ctx.fillStyle = c;
      ctx.globalAlpha = 0.6;
      ctx.fillRect(x, H/2 - 1, dotW, 3);
      ctx.globalAlpha = 1;
    }
  }

  // Legend
  ctx.font = '10px monospace';
  ctx.fillStyle = 'var(--fg-dim)';
  ctx.fillText('RET',10,15);
  ctx.fillStyle = '#7aa2f7';ctx.fillRect(40,9,10,10);
  ctx.fillStyle = 'var(--fg-dim)';ctx.fillText('CALL',80,15);
  ctx.fillStyle = '#bb9af7';ctx.fillRect(115,9,10,10);
  ctx.fillStyle = '#f7768e';ctx.fillText('VIOLATION',20,35);
}

// Violation detail
const violRows = rows.filter(r=>r.is_correct===0).slice(0,20);
document.getElementById('violation-detail').innerHTML = violRows.length === 0
  ? '<p style="color:var(--good)">✅ 无违规事件</p>'
  : `<table><thead><tr><th>#</th><th>时间</th><th>类型</th><th>源函数</th><th>RAX</th><th>ret_addr</th></tr></thead><tbody>${
      violRows.map((r,i)=>`<tr>
        <td>${i+1}</td>
        <td>${r.elapsed_ms.toFixed(2)}ms</td>
        <td><span class="badge bad">${r.jump_type==3?'RET':r.jump_type==4?'CALL':'JMP'}</span></td>
        <td>${r.src_func}</td>
        <td style="font-family:monospace;font-size:11px">${r.reg_rax||'0x0'}</td>
        <td style="font-family:monospace;font-size:11px">${r.ret_addr||'-'}</td>
      </tr>`).join('')
    }</tbody></table>`;
</script>
</body>
</html>'''


# ============================================================
#  4. 主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='CFI/DFI 运行结果可视化')
    parser.add_argument('-p', '--prefix', default='demo',
                        help='输出文件前缀 (默认: demo)')
    parser.add_argument('-o', '--output', default=None,
                        help='输出 HTML 路径 (默认: output/{prefix}_viewer.html)')
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, '..', 'output')
    prefix = args.prefix

    cfi_path = os.path.join(output_dir, f'{prefix}_cfi_events.csv')
    dfi_path = os.path.join(output_dir, f'{prefix}_dfi_layers.csv')

    if not os.path.exists(cfi_path):
        print(f"错误: 找不到 {cfi_path}")
        print(f"请先运行 dfi_monitor.py 生成 CSV")
        sys.exit(1)

    print(f"[*] 读取 CFI 事件: {cfi_path}")
    cfi_rows = read_cfi_csv(cfi_path)
    print(f"    {len(cfi_rows)} 条事件")

    print(f"[*] 读取 DFI 层事件: {dfi_path}")
    dfi_rows = read_dfi_csv(dfi_path) if os.path.exists(dfi_path) else []
    print(f"    {len(dfi_rows)} 条事件")

    # 分析
    analysis = analyze(cfi_rows, dfi_rows)
    # 附加精简版 CFI 行供前端画时间线（每10条采样）
    sample = cfi_rows[::max(1, len(cfi_rows)//800)] if cfi_rows else []
    analysis['_cfi_sample'] = [{k: r[k] for k in
        ['elapsed_ms','jump_type','is_correct','src_func','reg_rax','ret_addr']}
        for r in sample]

    # 生成 HTML
    data_json = json.dumps(analysis, ensure_ascii=False, default=str)
    html = HTML.replace('__DATA__', data_json)

    out_path = args.output or os.path.join(output_dir, f'{prefix}_viewer.html')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n✅ 生成完成: {out_path}  ({os.path.getsize(out_path)/1024:.0f} KB)")
    print(f"   在浏览器打开该文件即可查看")


if __name__ == '__main__':
    main()
