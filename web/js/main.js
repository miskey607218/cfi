/* ============================================================
   main.js — App initialization, data refresh, tabs, tables
   ============================================================ */

let SUMMARY = {};
let cfiPage = 0;
let cfiTotal = 0;
let currentSource = 'demo';      // current data source prefix
const PAGE_SIZE = 100;

/** Generic API fetch helper. */
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${r.statusText}`);
  return r.json();
}

/** Main refresh: fetch summary, render all components. */
async function refreshAll() {
  try {
    SUMMARY = await api('/api/summary?source=' + encodeURIComponent(currentSource));
  } catch (e) {
    document.getElementById('status').textContent = '连接服务器失败';
    return;
  }
  renderStats(SUMMARY);
  renderCharts(SUMMARY);
  await loadCfiEvents(0);
  await loadDfiChains();
  document.getElementById('status').textContent =
    `已更新 ${SUMMARY.timestamp}  |  ${SUMMARY.total_cfi} 事件  |  ${SUMMARY.total_dfi} DFI层`;
}

/** Render the stats row from summary data. */
function renderStats(s) {
  const rate = s.correct_rate;
  document.getElementById('stats-row').innerHTML = `
    <div class="stat"><div class="label">CFI 事件</div><div class="value">${s.total_cfi}</div></div>
    <div class="stat"><div class="label">DFI 层事件</div><div class="value">${s.total_dfi}</div></div>
    <div class="stat"><div class="label">违规</div><div class="value ${s.violations > 0 ? 'bad' : 'good'}">${s.violations}</div></div>
    <div class="stat"><div class="label">正确率</div><div class="value ${rate > 95 ? 'good' : rate > 80 ? 'warn' : 'bad'}">${rate}%</div></div>
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

  let data;
  try {
    data = await api(url);
  } catch (e) {
    document.getElementById('cfi-table').innerHTML = '<tr><td colspan="12">加载失败</td></tr>';
    return;
  }
  cfiTotal = data.total;

  const jtNames = { 3: 'RET', 4: 'INDIRECT_CALL', 5: 'INDIRECT_JMP' };
  document.getElementById('cfi-table').innerHTML = `
    <thead><tr>
      <th>#</th><th>时间(ms)</th><th>类型</th><th>源函数</th>
      <th>RAX</th><th>ret_addr</th><th>RSP</th><th>RBP</th>
      <th>saved_rax</th><th>saved_rsp</th><th>CS哈希</th><th>结果</th>
    </tr></thead>
    <tbody>${data.rows.map(r => `<tr>
      <td>${r.event_id}</td>
      <td style="color:var(--info)">${r.elapsed_ms}</td>
      <td><span class="badge ${r.jump_type == 3 ? 'ret' : r.jump_type == 4 ? 'call' : 'jmp'}">${jtNames[r.jump_type] || r.jump_type}</span></td>
      <td>${r.src_func || '-'}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.reg_rax}">${(r.reg_rax || '0x0').slice(0, 14)}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.ret_addr}">${(r.ret_addr || '-').slice(0, 14)}</td>
      <td style="font-family:monospace;font-size:10px">${(r.reg_rsp || '0x0').slice(0, 14)}</td>
      <td style="font-family:monospace;font-size:10px">${(r.reg_rbp || '0x0').slice(0, 14)}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.saved_rax_val}">${(r.saved_rax_val || '0x0').slice(0, 14)}</td>
      <td style="font-family:monospace;font-size:10px" title="${r.saved_rsp_val}">${(r.saved_rsp_val || '0x0').slice(0, 14)}</td>
      <td style="font-family:monospace;font-size:10px">${(r.call_stack_hash || '0x0').slice(0, 14)}</td>
      <td><span class="badge ${r.is_correct ? 'ok' : 'violation'}">${r.is_correct ? '✓' : '✗'}</span></td>
    </tr>`).join('')}</tbody>`;

  // Pagination
  const totalPages = Math.ceil(cfiTotal / PAGE_SIZE) || 1;
  const curPage = Math.floor(cfiPage / PAGE_SIZE) + 1;
  document.getElementById('cfi-pager').innerHTML = `
    <button ${cfiPage == 0 ? 'disabled' : ''} onclick="loadCfiEvents(0)">&laquo;&laquo;</button>
    <button ${cfiPage == 0 ? 'disabled' : ''} onclick="loadCfiEvents(${Math.max(0, cfiPage - PAGE_SIZE)})">&laquo;</button>
    <span>${curPage} / ${totalPages} (${cfiTotal} 条)</span>
    <button ${cfiPage + PAGE_SIZE >= cfiTotal ? 'disabled' : ''} onclick="loadCfiEvents(${cfiPage + PAGE_SIZE})">&raquo;</button>
    <button ${cfiPage + PAGE_SIZE >= cfiTotal ? 'disabled' : ''} onclick="loadCfiEvents(${Math.max(0, cfiTotal - PAGE_SIZE)})">&raquo;&raquo;</button>
  `;
}

/** Load and render the DFI dataflow chain cards. */
async function loadDfiChains() {
  let chains;
  try {
    chains = await api('/api/dfi_chains?source=' + encodeURIComponent(currentSource));
  } catch (e) {
    document.getElementById('chain-grid').innerHTML = '<p style="color:var(--fg-dim)">加载失败</p>';
    return;
  }
  const entries = Object.entries(chains);
  document.getElementById('chain-grid').innerHTML = entries.map(([sid, ch]) => {
    const ly = ch.layers;
    return `<div class="chain-card">
      <div class="chain-header">Site #${sid} — ${ch.func || '?'}</div>
      ${[1, 2, 3].map(l => {
        const v = ly[l];
        if (!v) return '';
        return `<div class="chain-row">
          <span class="lvl">L${l}</span>
          <span class="addr">${v.inst_offset || '?'}</span>
          <span style="color:var(--fg-dim);min-width:60px">${v.instr_type || '?'}</span>
          <span class="val">reg=${v.reg_value || '0x0'}</span>
          <span class="val">&rarr; ${v.target_addr || '0x0'}</span>
        </div>`;
      }).join('')}
    </div>`;
  }).join('');
}

/** Switch between CFI Events table and DFI Chains tabs. */
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const tabBtn = document.querySelector(`[onclick="switchTab('${name}')"]`);
  if (tabBtn) tabBtn.classList.add('active');
  const tabContent = document.getElementById('tab-' + name);
  if (tabContent) tabContent.classList.add('active');
  // 切换到寄存器 Tab 时自动加载
  if (name === 'register') { loadDfiRegisterDetail(); }
}

/** Initialize the app on page load — don't auto-load data. */
function initApp() {
  document.getElementById('status').textContent = '选择测试文件后点击「运行」';
}

// Auto-init
document.addEventListener('DOMContentLoaded', initApp);
