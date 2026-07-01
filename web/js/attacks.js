/* attacks.js — 程序选择 + 攻击控制 */

let currentProgram = 'test';
let selectedAttackId = null;
let currentTaskId = null;
let pollTimer = null;

/* ═══════════════════════════════════════════
   ROP 攻击类型（来自 dfi_rop.py ATTACK_TYPES）
   ═══════════════════════════════════════════ */

const ROP_ATTACKS = [
  {id:'sh',             name:'/bin/sh shellcode',   desc:'pwntools 生成 execve("/bin/sh")'},
  {id:'exit0',          name:'安全退出',              desc:'执行 exit(0)，验证 CFI 不误报'},
  {id:'simplenop',      name:'NOP 滑板 + shellcode', desc:'32 字节 NOP + shellcode'},
  {id:'nonop',          name:'纯 shellcode (RIPE)',  desc:'RIPE 风格，无 NOP 滑板'},
  {id:'polynop',        name:'多态 NOP + shellcode', desc:'随机单字节指令 + shellcode'},
  {id:'createfile',     name:'创建文件攻击',          desc:'在 /tmp/rip-eval/ 下创建文件'},
  {id:'returnintolibc', name:'返回到 libc',          desc:'覆盖指针为 creat() / system() 地址'},
  {id:'rop',            name:'ROP 链 execve',        desc:'pop rdi; pop rsi; pop rdx; syscall'},
];

/* ═══════════════════════════════════════════
   Program Selector
   ═══════════════════════════════════════════ */

async function loadProgramList() {
  try {
    const data = await api('/api/programs');
    const sel = document.getElementById('program-select');
    sel.innerHTML = (data.programs || []).map(p =>
      `<option value="${p.id}">${p.name}</option>`
    ).join('');
  } catch (e) {
    const sel = document.getElementById('program-select');
    sel.innerHTML = `
      <option value="test">test.c</option>
      <option value="attack">attack.c</option>`;
  }
}

let currentMode = 'safe';

function onProgramChange() {
  currentProgram = document.getElementById('program-select').value;
  updateAttackListVisibility();
}

function onModeChange() {
  currentMode = document.querySelector('input[name="run-mode"]:checked')?.value || 'safe';
  const safeLbl = document.getElementById('mode-safe-label');
  const attackLbl = document.getElementById('mode-attack-label');
  if (currentMode === 'safe') {
    safeLbl.style.background = 'var(--good)'; safeLbl.style.color = '#fff';
    attackLbl.style.background = 'var(--border)'; attackLbl.style.color = 'var(--fg)';
  } else {
    attackLbl.style.background = '#dc2626'; attackLbl.style.color = '#fff';
    safeLbl.style.background = 'var(--border)'; safeLbl.style.color = 'var(--fg)';
  }
  updateAttackListVisibility();
}

function updateAttackListVisibility() {
  const show = currentMode === 'attack';
  document.getElementById('attack-list-container').style.display = show ? '' : 'none';
  if (show) renderAttackList();
  const btn = document.getElementById('run-btn');
  btn.textContent = show ? '⚡ 执行攻击' : '▶ 安全运行';
  btn.style.background = show ? '#dc2626' : 'var(--accent)';
}

function renderAttackList() {
  document.getElementById('attack-list').innerHTML = ROP_ATTACKS.map(a => `
    <div class="attack-item ${selectedAttackId===a.id?'selected':''}" onclick="selectAttack('${a.id}')">
      <input type="radio" name="attack" value="${a.id}" ${selectedAttackId===a.id?'checked':''}>
      <div class="attack-info">
        <div class="attack-name">${a.name}</div>
        <div class="attack-desc">${a.desc}</div>
      </div>
    </div>
  `).join('');
}

function selectAttack(id) { selectedAttackId = id; renderAttackList(); }

/* ═══════════════════════════════════════════
   Trigger Run
   ═══════════════════════════════════════════ */

async function triggerRun() {
  const btn = document.getElementById('run-btn');

  btn.disabled = true;
  btn.textContent = '⏳ 执行中...';
  setResultStatus('running', `运行 ${currentProgram}...`);

  try {
    // 攻击模式使用 dfi_rop.py
    let resp;
    if (currentMode === 'attack') {
      resp = await fetch('/api/rop_attack', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({attack_type: selectedAttackId || 'sh', target: 0, mode: 'enforce'})
      });
    } else {
      resp = await fetch('/api/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({program: currentProgram, mode: 'safe', attack_id: 0, iterations: 1})
      });
    }
    const task = await resp.json();
    currentTaskId = task.task_id;
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollResult, 1500);
  } catch (e) {
    setResultStatus('error', '请求失败: ' + e.message);
    resetBtn();
  }
}

async function pollResult() {
  if (!currentTaskId) { clearInterval(pollTimer); return; }
  try {
    const data = await api('/api/attack_result/' + currentTaskId);
    if (!data || data.status === 'queued' || data.status === 'running') {
      setResultStatus('running', '执行中...');
      return;
    }
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    resetBtn();

    if (data.status === 'error') {
      setResultStatus('error', '失败: ' + (data.error || '?'));
      return;
    }
    renderAttackResult(data);

    const newPrefix = (data || {}).prefix || '';
    if (newPrefix && typeof currentSource !== 'undefined') currentSource = newPrefix;
    const progEl = document.getElementById('program-name');
    if (progEl) progEl.textContent = (data.program || currentProgram) + (data.mode ? ' (' + data.mode + ')' : '');
    refreshAll();
    // 执行完成后自动刷新寄存器详情
    setTimeout(() => loadDfiRegisterDetail(), 500);
  } catch (e) {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    resetBtn();
  }
}

function resetBtn() {
  const btn = document.getElementById('run-btn');
  btn.disabled = false;
  btn.textContent = currentMode === 'attack' ? '⚡ 执行攻击' : '▶ 安全运行';
}

/* ═══════════════════════════════════════════
   Result Display
   ═══════════════════════════════════════════ */

function setResultStatus(s, m) {
  document.getElementById('attack-results').innerHTML = `<h3>执行状态</h3><div class="result-status ${s}">${m}</div>`;
}

function renderAttackResult(data) {
  const r = data.result || data;
  const s = r.summary || {};
  const viol = r.violations || [];
  const monitorNote = r.monitor_note || '';
  const monitorFailed = monitorNote && monitorNote.includes('失败');

  const monitorWarn = monitorFailed ? `
    <div style="margin-bottom:8px;padding:8px;border:2px solid #fca5a5;background:#fef2f2;border-radius:6px">
      <div style="color:#dc2626;font-weight:600">⚠ eBPF 监控失败</div>
      <div style="font-size:13px;color:#b91c1c">${monitorNote}</div>
    </div>` : '';

  const detected = viol.length > 0;
  document.getElementById('attack-results').innerHTML = monitorWarn + `
    <h3>执行结果</h3>
    <div class="result-status done" style="color:var(${detected?'--bad':'--good'})">${detected?`⚠ ${viol.length} 个违规`:'✅ 全部通过'}</div>
    <div class="result-summary">
      <div class="rs-item"><div class="rs-val">${s.total_cfi||0}</div><div class="rs-label">CFI 事件</div></div>
      <div class="rs-item"><div class="rs-val">${s.total_dfi||0}</div><div class="rs-label">DFI 事件</div></div>
      <div class="rs-item"><div class="rs-val" style="color:var(${detected?'--bad':'--good'})">${viol.length}</div><div class="rs-label">违规</div></div>
      <div class="rs-item"><div class="rs-val" style="color:var(${(s.correct_rate||100)>=95?'--good':'--bad'})">${(s.correct_rate||100).toFixed(1)}%</div><div class="rs-label">正确率</div></div>
    </div>
    ${viol.length>0?`<div class="result-vios">${viol.slice(0,10).map(v=>`<div class="vio-row">[<span>${v.jump_type_name||'?'}</span>] ${v.src_func||'?'} &rarr; ${v.dst_func||'?'}</div>`).join('')}</div>`:''}
    <div style="margin-top:6px;font-size:11px;color:var(--fg-dim)">模式:${r.mode||'?'} | ${r.elapsed_seconds||'?'}s ${monitorNote?'| '+monitorNote:''}</div>`;
}

/* ═══════════════════════════════════════════
   Import .c file
   ═══════════════════════════════════════════ */

let importTaskId = null, importTimer = null;

function handleImportFile(e) {
  const f = e.target.files[0];
  if (!f) return;
  document.getElementById('import-filename').textContent = '已选择: ' + f.name;
  uploadAndImport(f);
}

async function uploadAndImport(file) {
  const c = document.getElementById('import-results');
  c.innerHTML = '<div class="result-status running">上传分析中...</div>';
  const reader = new FileReader();
  reader.onload = async function() {
    try {
      const b64 = reader.result.split(',')[1];
      const resp = await fetch('/api/import', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({filename:file.name, data:b64})
      });
      const task = await resp.json();
      importTaskId = task.task_id;
      if (importTimer) clearInterval(importTimer);
      importTimer = setInterval(pollImport, 1500);
    } catch(e) { c.innerHTML = '<div class="result-status error">失败: '+e.message+'</div>'; }
  };
  reader.readAsDataURL(file);
}

async function pollImport() {
  if (!importTaskId) { clearInterval(importTimer); return; }
  const c = document.getElementById('import-results');
  try {
    const data = await api('/api/attack_result/'+importTaskId);
    if (!data||data.status==='queued'||data.status==='running') { c.innerHTML='<div class="result-status running">分析中...</div>'; return; }
    if (importTimer) { clearInterval(importTimer); importTimer=null; }
    if (data.status==='error') { c.innerHTML='<div class="result-status error">'+ (data.error||'?')+'</div>'; return; }
    const s = (data.result||data).summary||{};
    c.innerHTML = `<div class="result-status done">✅ 完成</div>
      <div class="result-summary"><div class="rs-item"><div class="rs-val">${s.total_cfi||0}</div><div class="rs-label">CFI</div></div>
      <div class="rs-item"><div class="rs-val">${s.total_dfi||0}</div><div class="rs-label">DFI</div></div>
      <div class="rs-item"><div class="rs-val">${(s.correct_rate||100).toFixed(1)}%</div><div class="rs-label">正确率</div></div></div>`;
    const program = (data.result && data.result.program) || data.program || '';
    const fname = program.startsWith('import/') ? program.split('/', 2)[1] : 'imported.c';
    const sel = document.getElementById('program-select');
    const opt = document.createElement('option');
    opt.value = 'import/' + fname;
    opt.textContent = fname + ' — 导入';
    sel.appendChild(opt);
    sel.value = 'import/' + fname;
    currentProgram = 'import/' + fname;
    setTimeout(()=>refreshAll(), 500);
  } catch(e) { if (importTimer) { clearInterval(importTimer); importTimer=null; } }
}

/* ═══════════════════════════════════════════
   寄存器详情 — 按寄存器展示数值变化过程
   ═══════════════════════════════════════════ */

const REG_LIST = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'];

async function loadDfiRegisterDetail() {
  const c = document.getElementById('register-detail');
  if (!c) return;
  c.innerHTML = '<p style="color:var(--fg-dim);font-size:12px">加载中...</p>';
  try {
    const source = (typeof currentSource !== 'undefined') ? currentSource : 'demo';
    const data = await api('/api/cfi_events?source=' + encodeURIComponent(source) + '&limit=200');
    const rows = data.rows || [];
    if (!rows.length) { c.innerHTML='<p style="color:var(--fg-dim);font-size:12px">暂无运行时数据 — 请先执行程序</p>'; return; }

    // 按每个寄存器收集值变化序列
    c.innerHTML = REG_LIST.map(reg => {
      const changes = [];
      let prevVal = null;
      for (let i = 0; i < rows.length; i++) {
        const val = rows[i]['reg_' + reg] || '0x0';
        if (val !== prevVal) {
          changes.push({ idx: i, val: val, row: rows[i] });
          prevVal = val;
        }
      }
      // 即使没变化也显示第一行
      if (!changes.length && rows.length > 0) {
        changes.push({ idx: 0, val: rows[0]['reg_' + reg] || '0x0', row: rows[0] });
      }

      return `<div class="chain-card" style="margin-bottom:8px;background:#fff">
        <div class="chain-header" style="font-size:13px;font-weight:700;padding:8px 12px;border-bottom:1px solid var(--border)">
          🔑 <span style="color:var(--accent)">${reg.toUpperCase()}</span>
          <span style="font-size:10px;color:var(--fg-dim);margin-left:8px">${changes.length} 次变化 / ${rows.length} 事件</span>
        </div>
        <div style="padding:4px 0">
          ${changes.map((chg, ci) => {
            const r = chg.row;
            const isViolation = parseInt(r.is_correct) === 0;
            const instr = r.src_instr || (r.jump_type_name || '?');
            const bg = isViolation ? 'background:#fef2f2' : '';
            return `<div style="display:flex;align-items:center;gap:8px;padding:3px 12px;font-size:11px;${bg}">
              <span style="color:var(--fg-dim);min-width:20px">#${chg.idx+1}</span>
              <code style="font-size:10px;background:#e8f0fe;padding:1px 5px;border-radius:3px;color:#1a73e8;font-weight:600;min-width:130px;text-align:center">${chg.val}</code>
              <span style="color:var(--fg-dim);font-size:10px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${instr}</span>
              <span style="font-size:10px;color:var(--info);white-space:nowrap">${r.src_func||'?'}</span>
              <span style="font-size:10px;color:var(--fg-dim)">→ ${r.dst_func||'?'}</span>
              ${isViolation ? '<span style="color:#dc2626;font-weight:700;font-size:10px">⚠违规</span>' : ''}
            </div>`;
          }).join('')}
        </div>
      </div>`;
    }).join('');
  } catch(e) { c.innerHTML = '<p style="color:var(--bad);font-size:12px">加载失败: ' + e.message + '</p>'; }
}

/* ═══════════════════════════════════════════
   Init
   ═══════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', ()=>{
  loadProgramList();
  renderAttackList();
});
