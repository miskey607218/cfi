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
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (chartJT) chartJT.destroy();

  const keys = Object.keys(jtDist);
  const values = Object.values(jtDist);
  chartJT = new Chart(ctx, {
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
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (chartLayer) chartLayer.destroy();

  const keys = Object.keys(layerDist).sort();
  const values = keys.map(k => layerDist[k]);
  chartLayer = new Chart(ctx, {
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
  if (summary.jt_dist) renderJumpTypeChart(summary.jt_dist);
  if (summary.layer_dist) renderLayerBarChart(summary.layer_dist);
}
