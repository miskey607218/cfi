/* attacks.js — 程序选择 + 攻击控制 */

let currentProgram = 'test';
let selectedAttackId = null;
let currentTaskId = null;
let pollTimer = null;
let pollCount = 0;
const POLL_TIMEOUT = 60;  // 最多轮询 60 次 (120 秒)

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
    // Set current program to first option
    if (data.programs && data.programs.length > 0 && !currentProgram) {
      currentProgram = data.programs[0].id;
    }
  } catch (e) {
    const sel = document.getElementById('program-select');
    sel.innerHTML = '<option value="test">test</option><option value="attack">attack</option>';
  }
}

let currentMode = 'safe';

function onProgramChange() {
  currentProgram = document.getElementById('program-select').value;
  currentSource = currentProgram;
  updateAttackListVisibility();
  // 刷新数据：尝试加载新程序的数据
  document.getElementById('program-name').textContent = currentProgram;
  refreshAll();
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
    // 安全模式: mode=train (不杀进程)
    // 攻击模式: mode=enforce (违规立即终止)
    const runMode = currentMode === 'attack' ? 'enforce' : 'train';
    const resp = await fetch('/api/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({program: currentProgram, mode: runMode, iterations: 1})
    });
    const task = await resp.json();
    currentTaskId = task.task_id;
    pollCount = 0;
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollResult, 2000);
  } catch (e) {
    setResultStatus('error', '请求失败: ' + e.message);
    resetBtn();
  }
}

async function pollResult() {
  if (!currentTaskId) { clearInterval(pollTimer); return; }
  pollCount++;
  try {
    const data = await api('/api/attack_result/' + currentTaskId);
    if (!data || data.status === 'queued' || data.status === 'running') {
      document.getElementById('status').textContent =
        `执行中... (${pollCount * 2}s)`;
      if (pollCount >= POLL_TIMEOUT) {
        clearInterval(pollTimer);
        pollTimer = null;
        document.getElementById('status').textContent = '执行超时 — 请检查终端';
        resetBtn();
      }
      return;
    }
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

    if (data.status === 'error') {
      document.getElementById('status').textContent = '执行失败: ' + (data.error || '?');
      resetBtn();
      return;
    }

    // 任务完成 — 更新数据源并刷新所有展示
    const progName = data.program || currentProgram;
    currentSource = progName;
    document.getElementById('program-name').textContent = progName + ' (' + (data.mode || 'train') + ')';

    const r = data.result || data;
    const violDetected = r.violations_detected || (r.violations && r.violations.length > 0);
    resetBtn(violDetected);
    renderAttackResult(data);

    // 强制刷新前端所有组件
    await refreshAll();
    // 延迟加载寄存器详情（依赖 refreshAll 的数据）
    setTimeout(() => { if (typeof loadDfiRegisterDetail === 'function') loadDfiRegisterDetail(); }, 500);

    document.getElementById('status').textContent =
      `完成 ${new Date().toLocaleTimeString()} | ${(r.summary || {}).total_cfi || 0} 事件`;
  } catch (e) {
    console.error('pollResult error:', e);
    document.getElementById('status').textContent = '轮询出错: ' + e.message;
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    resetBtn();
  }
}

function resetBtn(detectedViolations) {
  const btn = document.getElementById('run-btn');
  btn.disabled = false;
  if (detectedViolations) {
    btn.textContent = '🛡 攻击已拦截';
    btn.style.background = '#16a34a';
  } else if (currentMode === 'attack') {
    btn.textContent = '⚡ 执行攻击';
    btn.style.background = '#dc2626';
  } else {
    btn.textContent = '▶ 安全运行';
    btn.style.background = 'var(--accent)';
  }
}

/* ═══════════════════════════════════════════
   Result Display
   ═══════════════════════════════════════════ */

function setResultStatus(s, m) {
  const el = document.getElementById('attack-results');
  if (!el) return;
  el.innerHTML = `<h3>执行状态</h3><div class="result-status ${s}">${m}</div>`;
}

function renderAttackResult(data) {
  const r = data.result || data;
  const s = r.summary || {};
  const viol = r.violations || [];
  const isEnforce = r.mode === 'enforce' || r.mode === 'attack';
  const detected = viol.length > 0;

  // Show alert banner above stats cards
  const alertEl = document.getElementById('attack-alert');
  if (alertEl) {
    if (detected && isEnforce) {
      const violPreviews = viol.slice(0, 3).map(v => {
        const isRet = v.jump_type === '3' || v.jump_type === 3;
        const va = isRet ? (v.saved_rsp_val || '0x0') : (v.reg_rax || '0x0');
        const vb = isRet ? (v.ret_addr || '0x0') : (v.saved_rax_val || '0x0');
        const sval = (s) => String(s).length > 14 ? '..' + String(s).slice(-10) : String(s);
        return `${isRet ? 'saved_rsp' : 'RAX'}=${sval(va)} vs ${isRet ? 'ret_addr' : 'saved_rax'}=${sval(vb)}`;
      }).join(' | ');
      const attackName = r.attack_type || selectedAttackId || '未知攻击';
      alertEl.style.display = '';
      alertEl.style.background = '#dcfce7';
      alertEl.style.border = '2px solid #16a34a';
      alertEl.style.color = '#166534';
      alertEl.innerHTML = `<div style="font-weight:700;font-size:14px">🛡️ 攻击拦截成功 — ${attackName}</div>
        <div style="margin-top:4px;font-size:12px">eBPF 检测到 ${viol.length} 个违规，进程已强制终止</div>
        <div style="margin-top:4px;font-family:monospace;font-size:11px;color:#991b1b">${violPreviews}</div>
        ${viol.length > 3 ? `<div style="font-size:10px;opacity:0.7;margin-top:2px">... 共 ${viol.length} 个违规，详情见 CFI 事件表</div>` : ''}`;
    } else if (detected && !isEnforce) {
      alertEl.style.display = '';
      alertEl.style.background = '#fef2f2';
      alertEl.style.border = '2px solid #dc2626';
      alertEl.style.color = '#991b1b';
      alertEl.innerHTML = `<div style="font-weight:700">⚠️ 安全模式发现 ${viol.length} 个异常</div>`;
    } else if (!detected && isEnforce) {
      const attackName = r.attack_type || selectedAttackId || '未知攻击';
      alertEl.style.display = '';
      alertEl.style.background = '#fef2f2';
      alertEl.style.border = '2px solid #dc2626';
      alertEl.style.color = '#991b1b';
      alertEl.innerHTML = `<div style="font-weight:700;font-size:14px">❌ 攻击未被检测到 — ${attackName}</div>
        <div style="margin-top:4px;font-size:12px">CFI 系统可能已被绕过</div>`;
    } else {
      alertEl.style.display = 'none';
    }
  }
}

/* ═══════════════════════════════════════════
   Import .c file
   ═══════════════════════════════════════════ */

function handleImportFile(e) {
  const f = e.target.files[0];
  if (!f) return;
  document.getElementById('import-filename').textContent = '已选择: ' + f.name;
  uploadAndImport(f);
}

async function uploadAndImport(file) {
  const c = document.getElementById('import-results');
  c.innerHTML = '<div class="result-status running">上传中...</div>';
  const reader = new FileReader();
  reader.onload = async function() {
    try {
      const b64 = reader.result.split(',')[1];
      const resp = await fetch('/api/import', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({filename:file.name, data:b64})
      });
      const result = await resp.json();
      if (result.status === 'error') {
        c.innerHTML = '<div class="result-status error">'+ (result.error||'?')+'</div>';
        return;
      }
      c.innerHTML = '<div class="result-status done">✅ 已导入: ' + result.name + '.c</div>';
      // Add to program selector
      const sel = document.getElementById('program-select');
      const opt = document.createElement('option');
      opt.value = result.name;
      opt.textContent = result.name + '.c (导入)';
      sel.appendChild(opt);
      sel.value = result.name;
      currentProgram = result.name;
    } catch(e) { c.innerHTML = '<div class="result-status error">失败: '+e.message+'</div>'; }
  };
  reader.readAsDataURL(file);
}

/* ═══════════════════════════════════════════
   寄存器指令追踪 — 按寄存器展示所有修改/使用
   ═══════════════════════════════════════════ */

const REG_LIST = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'];

async function loadDfiRegisterDetail() {
  const c = document.getElementById('register-detail');
  if (!c) return;
  c.innerHTML = '<p style="color:var(--fg-dim);font-size:12px">加载中...</p>';
  try {
    const prog = (typeof currentSource !== 'undefined') ? currentSource : 'test';
    const data = await api('/api/register_instructions?program=' + encodeURIComponent(prog));
    const instrs = data.instructions || [];
    if (!instrs.length) {
      c.innerHTML = '<p style="color:var(--fg-dim);font-size:12px">暂无静态分析数据 — 请先运行测试程序</p>';
      return;
    }

    // 按寄存器分组：显示所有 USE 或 DEF 该寄存器的指令
    c.innerHTML = REG_LIST.map(reg => {
      // 筛选涉及该寄存器的所有指令
      const related = [];
      for (let i = 0; i < instrs.length; i++) {
        const ins = instrs[i];
        const uses = ins.src.includes(reg);       // 读寄存器
        const defs = ins.dst.includes(reg);        // 写寄存器
        if (uses || defs) {
          related.push({ idx: i, ins, uses, defs });
        }
      }

      if (!related.length) {
        return `<div class="chain-card" style="margin-bottom:6px;background:#fff">
          <div class="chain-header" style="font-size:12px;padding:6px 12px">
            🔑 <span style="color:var(--accent)">${reg.toUpperCase()}</span>
            <span style="font-size:10px;color:var(--fg-dim);margin-left:8px">未被使用</span>
          </div></div>`;
      }

      const useCount = related.filter(r => r.uses).length;
      const defCount = related.filter(r => r.defs).length;

      return `<div class="chain-card" style="margin-bottom:6px;background:#fff">
        <div class="chain-header" style="font-size:12px;font-weight:700;padding:6px 12px;border-bottom:1px solid var(--border)">
          🔑 <span style="color:var(--accent)">${reg.toUpperCase()}</span>
          <span style="font-size:10px;color:var(--fg-dim);margin-left:8px">读 ${useCount} 次 | 写 ${defCount} 次 | ${related.length} 条指令</span>
        </div>
        <div style="max-height:300px;overflow-y:auto">
          ${related.map(({idx, ins, uses, defs}) => {
            // 操作标记: 只标记读/写，不标记是否为间接跳转
            const tags = [];
            if (defs) tags.push('<span style="color:#16a34a;font-weight:600;font-size:9px">写入</span>');
            if (uses && !defs) tags.push('<span style="color:var(--accent);font-weight:600;font-size:9px">读取</span>');
            if (uses && defs)  tags.push('<span style="color:#7c3aed;font-weight:600;font-size:9px">读写</span>');

            return `<div style="display:flex;align-items:center;gap:6px;padding:2px 8px;font-size:10px">
              <span style="color:var(--fg-dim);min-width:28px;text-align:right;flex-shrink:0">#${idx+1}</span>
              <span style="color:var(--fg-dim);min-width:52px;font-family:monospace;flex-shrink:0">${ins.addr || '?'}</span>
              <code style="flex:1;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(ins.instr)}</code>
              <span style="color:var(--info);font-size:10px;min-width:100px;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0">${ins.func || '?'}</span>
              <span style="display:flex;gap:2px;flex-shrink:0">${tags.join('')}</span>
            </div>`;
          }).join('')}
        </div>
      </div>`;
    }).join('');

  } catch(e) { c.innerHTML = '<p style="color:var(--bad);font-size:12px">加载失败: ' + e.message + '</p>'; }
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ═══════════════════════════════════════════
   Init
   ═══════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', ()=>{
  loadProgramList();
  renderAttackList();
});
