/* ============================================================
   charts.js — Chart.js rendering for CFI/DFI monitoring
   Handles: jump type pie, DFI layer bar
   ============================================================ */

let chartJT = null;
let chartLayer = null;

/**
 * Render jump type distribution as a doughnut chart.
 * @param {object} jtDist - {RET: n, INDIRECT_CALL: n, INDIRECT_JMP: n}
 */
function renderJumpTypeChart(jtDist) {
  const canvas = document.getElementById('chart-jt');
  const wrap = canvas ? canvas.parentElement : null;
  if (!canvas || !wrap) return;

  const keys = Object.keys(jtDist || {});
  const values = Object.values(jtDist || {});

  // Remove old overlay
  const old = wrap.querySelector('.chart-no-data');
  if (old) old.remove();

  if (keys.length === 0 || values.every(v => v === 0)) {
    if (chartJT) { chartJT.destroy(); chartJT = null; }
    canvas.style.display = 'none';
    const div = document.createElement('div');
    div.className = 'chart-no-data';
    div.style.cssText = 'display:flex;align-items:center;justify-content:center;height:260px;color:#8b949e;font-size:13px';
    div.textContent = '暂无跳转数据 — 请运行测试程序';
    wrap.appendChild(div);
    return;
  }

  // Restore canvas
  canvas.style.display = '';
  if (chartJT) chartJT.destroy();
  const ctxJT = canvas.getContext('2d');
  chartJT = new Chart(ctxJT, {
    type: 'doughnut',
    data: {
      labels: keys,
      datasets: [{
        data: values,
        backgroundColor: ['#58a6ff', '#bc8cff', '#d2991d']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#8b949e', font: { size: 11 } }
        }
      }
    }
  });
}

/**
 * Render DFI layer distribution as a bar chart.
 * @param {object} layerDist - {L1: n, L2: n, L3: n}
 */
function renderLayerBarChart(layerDist) {
  const canvas = document.getElementById('chart-layer');
  const wrap = canvas ? canvas.parentElement : null;
  if (!canvas || !wrap) return;

  const keys = Object.keys(layerDist || {}).sort();
  const values = keys.map(k => layerDist[k] || 0);

  // Remove old overlay
  const old = wrap.querySelector('.chart-no-data');
  if (old) old.remove();

  // If all zero, show overlay message instead of empty chart
  if (values.every(v => v === 0)) {
    if (chartLayer) { chartLayer.destroy(); chartLayer = null; }
    canvas.style.display = 'none';
    const div = document.createElement('div');
    div.className = 'chart-no-data';
    div.style.cssText = 'display:flex;align-items:center;justify-content:center;height:260px;color:#8b949e;font-size:13px';
    div.textContent = '暂无 DFI 数据 — 请运行测试程序';
    wrap.appendChild(div);
    return;
  }

  // Restore canvas
  canvas.style.display = '';
  if (chartLayer) chartLayer.destroy();
  const ctxLayer = canvas.getContext('2d');
  chartLayer = new Chart(ctxLayer, {
    type: 'bar',
    data: {
      labels: keys,
      datasets: [{
        data: values,
        backgroundColor: ['#3fb950', '#58a6ff', '#bc8cff']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: {
          grid: { color: '#30363d' },
          ticks: { color: '#8b949e' }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#8b949e' }
        }
      }
    }
  });
}

/**
 * Render all charts from summary data.
 * @param {object} summary - The /api/summary response
 */
function renderCharts(summary) {
  try {
    if (summary && summary.jt_dist) renderJumpTypeChart(summary.jt_dist);
  } catch(e) { console.error('jt chart:', e); }
  try {
    if (summary && summary.layer_dist) renderLayerBarChart(summary.layer_dist);
  } catch(e) { console.error('layer chart:', e); }
}
