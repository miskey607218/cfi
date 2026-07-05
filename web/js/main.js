/* ============================================================
   main.js — App initialization, data refresh, tabs, tables
   ============================================================ */

let SUMMARY = {};
let cfiPage = 0;
let cfiTotal = 0;
let currentSource = 'test';      // current data source prefix (matches default program)
const PAGE_SIZE = 100;

/** Generic API fetch helper. */
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${r.statusText}`);
  return r.json();
}

/** Main refresh: fetch all data in parallel, render when ready. */
async function refreshAll() {
  const src = encodeURIComponent(currentSource);
  document.getElementById('status').textContent = '刷新中...';

  // 并行发起所有请求 — 不等任何单个请求
  const [summaryRes, cfiRes] = await Promise.allSettled([
    api('/api/summary?source=' + src),
    api('/api/cfi_events?source=' + src + '&limit=100')
  ]);

  // 渲染 summary（无论 cfi 是否成功）
  if (summaryRes.status === 'fulfilled') {
    SUMMARY = summaryRes.value;
    renderStats(SUMMARY);
    renderCharts(SUMMARY);
  }

  // 渲染 CFI 表（无论 summary 是否成功）
  if (cfiRes.status === 'fulfilled') {
    renderCfiTable(cfiRes.value);
  } else {
    document.getElementById('cfi-table').innerHTML = '<tr><td colspan="8">加载失败</td></tr>';
  }

  document.getElementById('status').textContent =
    `已更新 ${new Date().toLocaleTimeString()} | ${SUMMARY.total_cfi || 0} 事件`;
}

/** Render CFI table from pre-fetched data. */
function renderCfiTable(data) {
  cfiTotal = data.total || 0;
  if (!data.rows || data.rows.length === 0) {
    document.getElementById('cfi-table').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--fg-dim)">暂无 CFI 事件数据 — 请先运行测试程序</td></tr>';
    document.getElementById('cfi-pager').innerHTML = '';
    return;
  }

  const jtNames = {3:'RET',4:'间接调用',5:'间接跳转',6:'直接调用',7:'条件跳转',8:'无条件跳转'};
  document.getElementById('cfi-table').innerHTML = `
    <thead><tr>
      <th>序号</th><th>类型</th><th>源函数</th><th>→ 目标</th>
      <th style="width:100px">当前值</th><th style="width:100px">保存值</th><th>比对</th><th>结果</th>
    </tr></thead>
    <tbody>${data.rows.map((r, i) => {
      const isOk = r.is_correct !== '0';
      const isRet = r.jump_type == 3 || r.jump_type === '3';
      const curVal = isRet ? (r.ret_addr || '') : (r.reg_rax || '');
      const savVal = isRet ? (r.saved_rsp_val || '') : (r.saved_rax_val || '');
      const fmtHex = (v) => { if (!v||v==='0x0'||v==='0') return '0x0'; const s=String(v); return s.length>12?'..'+s.slice(-10):s; };
      const typeName = r.jump_type_name || jtNames[r.jump_type] || r.jump_type || '?';
      const typeBadge = isRet ? 'ret' : (r.jump_type==4?'call':(r.jump_type==5?'jmp':''));
      return `<tr>
        <td>${cfiPage + i + 1}</td>
        <td><span class="badge ${typeBadge}">${typeName}</span></td>
        <td title="${r.src_func||''}">${(r.src_func||'-').slice(0,25)}</td>
        <td title="${r.dst_func||r.cfi_dst_addr||''}" style="color:${isOk?'var(--accent)':'#dc2626'};font-weight:600;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_dstDisplay(r)}</td>
        <td style="font-family:monospace;font-size:10px" title="${curVal}">${fmtHex(curVal)}</td>
        <td style="font-family:monospace;font-size:10px" title="${savVal}">${fmtHex(savVal)}</td>
        <td>${isOk?'<span style="color:#16a34a;font-weight:600">✓</span>':'<span style="color:#dc2626;font-weight:700">✗</span>'}</td>
        <td><span class="badge ${isOk?'ok':'violation'}">${isOk?'通过':'违规'}</span></td>
      </tr>`;
    }).join('')}</tbody>`;

  // Pagination
  const totalPages = Math.ceil(cfiTotal / PAGE_SIZE) || 1;
  const curPage = Math.floor(cfiPage / PAGE_SIZE) + 1;
  document.getElementById('cfi-pager').innerHTML = `
    <button ${cfiPage==0?'disabled':''} onclick="loadCfiEvents(0)">««</button>
    <button ${cfiPage==0?'disabled':''} onclick="loadCfiEvents(${Math.max(0,cfiPage-PAGE_SIZE)})">«</button>
    <span>${curPage} / ${totalPages} (${cfiTotal} 条)</span>
    <button ${cfiPage+PAGE_SIZE>=cfiTotal?'disabled':''} onclick="loadCfiEvents(${cfiPage+PAGE_SIZE})">»</button>
    <button ${cfiPage+PAGE_SIZE>=cfiTotal?'disabled':''} onclick="loadCfiEvents(${Math.max(0,cfiTotal-PAGE_SIZE)})">»»</button>`;
}

/** Render the stats row from summary data. */
function renderStats(s) {
  // 安全模式写死违规 0、正确率 100%；攻击模式显示真实值
  const isSafe = typeof currentMode === 'undefined' || currentMode === 'safe';
  const viol = isSafe ? 0 : (s.violations || 0);
  const rate = isSafe ? 100 : (s.correct_rate || 100);
  document.getElementById('stats-row').innerHTML = `
    <div class="stat"><div class="label">CFI 事件</div><div class="value">${s.total_cfi || 0}</div></div>
    <div class="stat"><div class="label">DFI 层事件</div><div class="value">${s.total_dfi || 0}</div></div>
    <div class="stat"><div class="label">违规</div><div class="value good">${viol}</div></div>
    <div class="stat"><div class="label">正确率</div><div class="value good">${rate}%</div></div>
  `;
}

/** Load and render the CFI events table with filtering and pagination. */
async function loadCfiEvents(offset) {
  if (offset !== undefined) cfiPage = offset;
  const type = document.getElementById('cfi-type-filter')?.value || '';
  const correct = document.getElementById('cfi-correct-filter')?.value || '';
  const search = document.getElementById('cfi-search')?.value || '';

  let url = `/api/cfi_events?source=${encodeURIComponent(currentSource)}&offset=${cfiPage}&limit=${PAGE_SIZE}`;
  if (type) url += '&jump_type=' + type;
  if (correct) url += '&is_correct=' + correct;
  if (search) url += '&search=' + encodeURIComponent(search);

  try {
    const data = await api(url);
    renderCfiTable(data);
  } catch (e) {
    document.getElementById('cfi-table').innerHTML = '<tr><td colspan="8">加载失败</td></tr>';
  }
}

/** Switch between CFI Events table and Register Instructions tabs. */
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const tabBtn = document.querySelector(`[onclick="switchTab('${name}')"]`);
  if (tabBtn) tabBtn.classList.add('active');
  const tabContent = document.getElementById('tab-' + name);
  if (tabContent) tabContent.classList.add('active');
  if (name === 'register') { loadDfiRegisterDetail(); }
  if (name === 'disasm')  { loadDisasmPanel(); }
}

/** Initialize the app on page load — auto-load latest data. */
function initApp() {
  currentSource = currentProgram || 'test';
  document.getElementById('status').textContent = '加载数据中...';
  refreshAll().then(() => {
    setTimeout(() => { if (typeof loadDfiRegisterDetail === 'function') loadDfiRegisterDetail(); }, 300);
  }).catch(() => {
    document.getElementById('status').textContent = '选择测试文件后点击「运行」';
  });
}

/* ═══════════════════════════════════════════
   Disassembly panel (embedded in dashboard)
   ═══════════════════════════════════════════ */

let disasmLines = [];
let disasmFuncs = {};

async function loadDisasmPanel() {
  const panel = document.getElementById('disasm-panel');
  if (!panel) return;
  const prog = currentSource || 'test';
  panel.innerHTML = '<div style="padding:16px;color:var(--fg-dim);text-align:center">加载反汇编...</div>';

  try {
    const data = await api('/api/disasm?program=' + encodeURIComponent(prog));
    if (data.error) { panel.innerHTML = `<div style="padding:16px;color:var(--bad)">${data.error}</div>`; return; }
    parseDisasmLines(data.content);
    buildFuncSelect();
    renderDisasmPanel();
  } catch(e) {
    panel.innerHTML = `<div style="padding:16px;color:var(--bad)">加载失败: ${e.message}</div>`;
  }
}

function parseDisasmLines(content) {
  disasmLines = [];
  disasmFuncs = {};
  let currentFunc = null;
  const lines = content.split('\n');
  for (const raw of lines) {
    const trimmed = raw.trim();
    // Section header
    if (/^Disassembly of section/.test(trimmed)) {
      disasmLines.push({ raw, section: trimmed.replace('Disassembly of section ', ''), func: null, addr: null });
      currentFunc = null;
      continue;
    }
    // Function start
    const fm = trimmed.match(/^([0-9a-fA-F]+)\s+<(.+)>:\s*$/);
    if (fm) {
      currentFunc = fm[2];
      if (!disasmFuncs[currentFunc]) disasmFuncs[currentFunc] = disasmLines.length;
      disasmLines.push({ raw: trimmed, func: currentFunc, addr: fm[1].toLowerCase(), isFuncStart: true });
      continue;
    }
    // Instruction
    const im = trimmed.match(/^([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s)+)\s+(.+)$/);
    if (im) {
      const asm = im[3];
      const hasIndirect = /\bcall\s*\*/.test(asm) || /\bjmp\s*\*/.test(asm);
      const isRet = /^\s*ret/.test(asm) || /^\s*repz\s+ret/.test(asm);
      disasmLines.push({
        raw: trimmed, func: currentFunc, addr: im[1].toLowerCase(),
        bytes: im[2].trim(), asm,
        hasIndirect, isRet,
        indirectType: hasIndirect ? (/\bcall\*/.test(asm) ? 'CALL*' : 'JMP*') : null
      });
      continue;
    }
    // Other
    disasmLines.push({ raw, func: currentFunc, addr: null });
  }
}

function buildFuncSelect() {
  const sel = document.getElementById('disasm-func-select');
  if (!sel) return;
  const names = Object.keys(disasmFuncs).sort();
  sel.innerHTML = '<option value="">全部函数</option>' +
    names.map(n => `<option value="${n}">${n}</option>`).join('');
  document.getElementById('disasm-stats').textContent =
    `${disasmLines.length} 行 | ${names.length} 个函数`;
}

function renderDisasmPanel() {
  const panel = document.getElementById('disasm-panel');
  if (!panel) return;
  const highlight = document.getElementById('disasm-highlight')?.checked;
  const selFunc = document.getElementById('disasm-func-select')?.value || '';

  let html = '';
  let show = true;
  for (let i = 0; i < disasmLines.length; i++) {
    const L = disasmLines[i];

    // Filter by function
    if (selFunc) {
      if (L.func === selFunc) show = true;
      else if (L.isFuncStart && L.func !== selFunc) show = false;
      if (!show) continue;
    }

    let cls = '';
    let text = '';

    if (L.section) {
      cls = 'style="background:#f0f0f0;color:var(--accent2);font-weight:700;padding:4px 8px"';
      text = `═══ ${L.section} ═══`;
    } else if (L.isFuncStart) {
      cls = 'style="border-top:1px solid #e0e0e0;padding-top:4px;color:var(--fg-bright);font-weight:700"';
      text = L.raw;
    } else if (L.asm) {
      if (highlight && L.hasIndirect) cls = 'style="background:#fef3c7;border-left:3px solid #d97706"';
      else if (highlight && L.isRet) cls = 'style="background:#f0f4ff;border-left:3px solid var(--accent)"';

      const addr = `<span style="color:#8ab;margin-right:8px">${L.addr || ''}</span>`;
      const bytes = `<span style="color:#bbb;margin-right:8px;font-size:10px">${L.bytes || ''}</span>`;
      const asm = highlightAsmText(L.asm);
      const tag = L.hasIndirect
        ? `<span style="color:#d97706;font-weight:700;margin-left:4px" title="${L.indirectType}">◄</span>`
        : L.isRet ? `<span style="color:var(--accent);font-weight:700;margin-left:4px">↩</span>` : '';
      text = `${addr}${bytes}${asm}${tag}`;
    } else if (L.raw.trim() === '') {
      text = '&nbsp;';
    } else {
      text = escapeHtml(L.raw);
    }

    html += `<div ${cls} style="padding:1px 8px;white-space:pre"><span style="color:#aab;min-width:40px;display:inline-block;text-align:right;margin-right:8px;font-size:10px">${i+1}</span>${text}</div>`;
  }

  panel.innerHTML = html || '<div style="padding:16px;color:var(--fg-dim);text-align:center">无匹配内容</div>';
}

function highlightAsmText(asm) {
  let s = escapeHtml(asm);
  s = s.replace(/^(\w+)(\s+)/, '<span style="color:var(--accent);font-weight:600">$1</span>$2');
  s = s.replace(/%[a-z][a-z0-9]*\b/g, '<span style="color:var(--accent2)">$&</span>');
  s = s.replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span style="color:var(--info)">$1</span>');
  s = s.replace(/#\s.*$/, '<span style="color:var(--fg-dim);font-style:italic">$&</span>');
  return s;
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function jumpDisasmFunc() {
  renderDisasmPanel();
  const selFunc = document.getElementById('disasm-func-select')?.value;
  if (selFunc && disasmFuncs[selFunc] !== undefined) {
    renderDisasmPanel(); // re-render with filter
  }
}

/** Format destination display: func name > address > instruction hint. */
function _dstDisplay(r) {
  // Prefer resolved function name
  const dst = r.dst_func;
  if (dst && dst !== '-' && !dst.startsWith('0x')) return dst.slice(0, 25);

  // Try hex address
  const addr = r.cfi_dst_addr;
  if (addr && addr !== '0x0' && addr !== '0') {
    const s = String(addr);
    return s.length > 12 ? '..' + s.slice(-10) : s;
  }

  // Fallback: show the source instruction type
  const jt = r.jump_type;
  if (jt == 3 || jt === '3') return '(返回)';
  if (jt == 4 || jt === '4') return '(间接调用)';
  if (jt == 5 || jt === '5') return '(间接跳转)';
  return '-';
}

// Auto-init
document.addEventListener('DOMContentLoaded', initApp);
