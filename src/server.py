#!/usr/bin/env python3
"""
server.py — CFI/DFI Attack Monitor Server
==========================================
服务 web/ 静态文件，提供监控数据 REST API，
并管理攻击场景编译/执行/结果采集。

用法:
    cd final
    python3 src/server.py                    # 默认端口 8080
    python3 src/server.py -p 3000            # 自定义端口
    python3 src/server.py -d output -P demo  # 自定义数据目录和前缀

浏览器打开: http://localhost:8080
"""

import sys
import os
import csv
import json
import time
import base64
import argparse
import socket
import threading
import uuid
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ============================================================
#  路径配置
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, '..'))
WEB_DIR = os.path.join(PROJECT_DIR, 'web')
TEST_DIR = os.path.join(PROJECT_DIR, 'test')           # 源文件 (.c)
BUILD_DIR = os.path.join(PROJECT_DIR, 'build')         # 编译产物（按文件名分目录）
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'output')

MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css':   'text/css; charset=utf-8',
    '.js':    'application/javascript; charset=utf-8',
    '.json':  'application/json',
    '.png':   'image/png',
    '.svg':   'image/svg+xml',
    '.ico':   'image/x-icon',
}

# ============================================================
#  DataStore — 监控数据加载与缓存
# ============================================================

class DataStore:
    """加载 CFI/DFI CSV 数据，提供 summary / events / chains 查询。"""

    def __init__(self, output_dir=None, prefix='demo'):
        self.output_dir = output_dir or OUTPUT_DIR
        self.prefix = prefix
        self.cfi_rows = []
        self.dfi_rows = []
        self.last_load = 0
        self.load_interval = 2
        self._lock = threading.Lock()

    def set_source(self, prefix):
        """动态切换数据源前缀。"""
        self.prefix = prefix
        self.last_load = 0  # force reload

    def _cfi_path(self):
        return os.path.join(self.output_dir, f'{self.prefix}_cfi_events.csv')

    def _dfi_path(self):
        return os.path.join(self.output_dir, f'{self.prefix}_dfi_layers.csv')

    def reload_if_needed(self):
        now = time.time()
        if now - self.last_load < self.load_interval:
            return

        with self._lock:
            self.last_load = now
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
        return {'total': total, 'offset': offset, 'limit': limit, 'rows': page}

    def get_dfi_events(self, offset=0, limit=200):
        self.reload_if_needed()
        rows = self.dfi_rows
        total = len(rows)
        page = rows[offset:offset + limit]
        return {'total': total, 'offset': offset, 'limit': limit, 'rows': page}


# ============================================================
#  AttackManager — 攻击场景编译、执行、结果采集
# ============================================================

class AttackManager:
    """管理攻击场景列表、编译 attack.so、运行 monitor、解析结果。"""

    ATTACKS = [
        {'id':1,'name':'全局指针劫持','desc':'setup 设置合法指针 → ATTACK 篡改为 evil → call 时 saved≠rax','severity':'high','cfi_type':'INDIRECT_CALL'},
        {'id':2,'name':'双重指针劫持','desc':'通过二级指针间接修改最终调用目标','severity':'medium','cfi_type':'INDIRECT_CALL'},
        {'id':3,'name':'条件分支劫持','desc':'攻击者控制分支条件，走入持有非法指针的路径','severity':'medium','cfi_type':'INDIRECT_CALL'},
        {'id':4,'name':'结构体函数指针替换','desc':'模拟 vtable 破坏：结构体 action 成员被篡改','severity':'high','cfi_type':'INDIRECT_CALL'},
        {'id':5,'name':'返回指针劫持','desc':'函数返回合法指针后，攻击者替换再调用','severity':'high','cfi_type':'INDIRECT_CALL'},
        {'id':6,'name':'堆回调替换','desc':'malloc 后的函数指针被篡改','severity':'high','cfi_type':'INDIRECT_CALL'},
        {'id':7,'name':'函数指针表投毒','desc':'初始化表后篡改某一槽位','severity':'medium','cfi_type':'INDIRECT_CALL'},
    ]

    def __init__(self):
        self.tasks = {}       # task_id -> task dict
        self._lock = threading.Lock()

    def list_attacks(self):
        return self.ATTACKS

    def start_rop_attack(self, attack_type='sh', target=0, mode='enforce'):
        """启动 ROP 攻击检测（调用 dfi_rop.py）。"""
        task_id = uuid.uuid4().hex[:8]
        task = {
            'task_id': task_id,
            'attack_type': attack_type,
            'target': target,
            'mode': mode,
            'status': 'queued',
            'created_at': time.time(),
            'result': None,
        }
        with self._lock:
            self.tasks[task_id] = task
        t = threading.Thread(target=self._execute_rop, args=(task_id,), daemon=True)
        t.start()
        return task

    def _execute_rop(self, task_id):
        """后台执行 dfi_rop.py 进行 ROP 攻击检测。"""
        with self._lock:
            self.tasks[task_id]['status'] = 'running'
        task = self.tasks[task_id]
        attack_type = task['attack_type']
        target = task['target']
        mode = task['mode']
        start_time = time.time()

        try:
            rop_script = os.path.join(SCRIPT_DIR, 'dfi_rop.py')
            cmd = ['sudo', sys.executable, rop_script,
                   '-a', attack_type, '-t', str(target), '-m', mode]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = cp.stdout + '\n' + cp.stderr
            elapsed = round(time.time() - start_time, 1)

            violations_detected = 'VIOLATION' in output
            result = {
                'attack_type': attack_type,
                'target': target,
                'mode': mode,
                'elapsed_seconds': elapsed,
                'violations_detected': violations_detected,
                'output': output[-5000:],  # Truncate long output
            }
            with self._lock:
                self.tasks[task_id]['status'] = 'done'
                self.tasks[task_id]['result'] = result
        except subprocess.TimeoutExpired:
            with self._lock:
                self.tasks[task_id]['status'] = 'error'
                self.tasks[task_id]['error'] = 'ROP 攻击检测超时 (120s)'
        except Exception as e:
            with self._lock:
                self.tasks[task_id]['status'] = 'error'
                self.tasks[task_id]['error'] = str(e)

    def get_task(self, task_id):
        return self.tasks.get(task_id)

    def start_run(self, program, mode='safe', attack_id=0, iterations=3):
        """统一的执行入口。
        program: 'test' | 'attack' | 'import/filename.c'
        mode: 'safe' | 'attack'
        """
        task_id = uuid.uuid4().hex[:8]
        task = {
            'task_id': task_id,
            'program': program,
            'mode': mode,
            'attack_id': attack_id,
            'iterations': iterations,
            'status': 'queued',
            'created_at': time.time(),
            'result': None,
        }
        with self._lock:
            self.tasks[task_id] = task
        t = threading.Thread(target=self._execute_program, args=(task_id,), daemon=True)
        t.start()
        return task

    def start_import(self, file_data, filename):
        """保存上传的 .c 到 test/，然后统一执行。"""
        # Sanitize filename: reject path traversal and absolute paths
        if os.path.isabs(filename) or '..' in filename or '/' in filename or '\\' in filename:
            raise ValueError(f'Invalid filename: {filename}')
        if not filename.endswith('.c'):
            raise ValueError('Only .c source files are accepted')

        os.makedirs(TEST_DIR, exist_ok=True)
        save_path = os.path.join(TEST_DIR, filename)
        with open(save_path, 'wb') as f:
            f.write(file_data)
        # 委托给统一入口
        return self.start_run(f'import/{filename}', 'safe', 0, 3)

    def _execute_program(self, task_id):
        """统一执行流水线: 编译 → 静态分析 → eBPF 监控"""
        with self._lock:
            self.tasks[task_id]['status'] = 'running'
        t = self.tasks[task_id]
        program = t['program']
        mode = t['mode']
        attack_id = t['attack_id']
        iterations = t['iterations']
        start_time = time.time()

        try:
            # 通用路径解析：所有 .c 源文件均在 test/ 下
            if program.startswith('import/'):
                fname = program.split('/', 1)[1]
                src = os.path.join(TEST_DIR, fname)
                basename = os.path.splitext(fname)[0]
            else:
                src = os.path.join(TEST_DIR, f'{program}.c')
                basename = program

            if not os.path.exists(src):
                raise RuntimeError(f'源文件不存在: {src}')

            # Build output directory: build/<basename>/
            build_dir = os.path.join(BUILD_DIR, basename)
            os.makedirs(build_dir, exist_ok=True)

            # Intermediate files in build/<basename>/
            base = os.path.join(build_dir, basename)
            so_path = base + '.so'
            txt_path = base + '.txt'
            csv_path = base + '_jump_analysis.csv'
            dfi_prefix = base + '_register_dfi'

            # Compile
            cp = subprocess.run(['gcc', '-shared', '-fPIC', '-O0', '-o', so_path, src],
                                capture_output=True, text=True)
            if cp.returncode != 0:
                raise RuntimeError(f'编译失败:\n{cp.stderr}')

            # Auto-detect available symbols for entry function selection
            # 运行时输出前缀: output/{basename}/run_{task_id}
            output_subdir = os.path.join(OUTPUT_DIR, basename)
            os.makedirs(output_subdir, exist_ok=True)
            prefix = f'{basename}/run_{task_id}'

            nm = subprocess.run(['nm', '-D', so_path], capture_output=True, text=True)
            symbols = set()
            for line in nm.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ('T', 't'):
                    symbols.add(parts[2])
            if mode == 'attack' and 'run_attack' in symbols:
                entry = 'run_attack'; param = attack_id
            elif mode == 'safe' and 'run_safe' in symbols:
                entry = 'run_safe'; param = attack_id or 1
            elif 'test_all' in symbols:
                entry = 'test_all'; param = None
            elif 'main' in symbols:
                entry = 'main'; param = None
            elif 'run_attack' in symbols:
                entry = 'run_attack'; param = attack_id or 1
            else:
                raise RuntimeError(f'未找到入口函数 (run_attack/run_safe/test_all/main)')

            # Static analysis
            analysis = self._run_static_analysis(so_path, txt_path, csv_path, dfi_prefix)

            # eBPF monitor
            monitor_ok, monitor_msg = self._run_monitor(
                so_path, csv_path, entry, param, prefix, iterations)

            monitor_note = 'eBPF 监控完成' if monitor_ok == 0 else f'eBPF 监控失败 (rc={monitor_ok}): {monitor_msg}'
            result = self._parse_results(prefix, attack_id, mode, start_time)
            result['monitor_note'] = monitor_note
            result['program'] = program
            if analysis.get('dfi_register_detail'):
                result['dfi_register_detail'] = analysis['dfi_register_detail']

            with self._lock:
                self.tasks[task_id]['status'] = 'done'
                self.tasks[task_id]['result'] = result
        except Exception as e:
            with self._lock:
                self.tasks[task_id]['status'] = 'error'
                self.tasks[task_id]['error'] = str(e)

    def _run_static_analysis(self, so_path, txt_path, csv_path, dfi_prefix):
        """静态分析流水线: objdump → 跳转分析 → DFI 分析（无需 sudo）。"""
        outputs = {}
        # objdump
        with open(txt_path, 'w') as f:
            subprocess.run(['objdump', '-d', so_path], stdout=f, check=True)
        # 跳转分析
        subprocess.run([sys.executable,
            os.path.join(SCRIPT_DIR, 'transformToCsv.py'),
            '--input', txt_path, '--output', csv_path],
            check=True, capture_output=True)
        # DFI 数据流分析
        subprocess.run([sys.executable,
            os.path.join(SCRIPT_DIR, 'dataflow_analysis.py'),
            txt_path, dfi_prefix], check=True, capture_output=True)
        # 读取 DFI 寄存器详情
        dfi_detail = self._parse_dfi_register_detail(dfi_prefix)
        if dfi_detail:
            outputs['dfi_register_detail'] = dfi_detail
        return outputs

    def _run_monitor(self, so_path, csv_path, entry, param, prefix, iterations):
        """运行 eBPF monitor（server 以 root 运行，直接调用）。"""
        monitor_cmd = [sys.executable, os.path.join(SCRIPT_DIR, 'dfi_monitor.py'),
            '-m', 'train', '-o', prefix, '-n', str(iterations),
            '--so', so_path, '--entry', entry, '--csv', csv_path]
        if param is not None:
            monitor_cmd += ['--param', str(param)]

        print(f'[Monitor] Running: {" ".join(monitor_cmd)}', flush=True)
        try:
            cp = subprocess.run(monitor_cmd, capture_output=True, text=True, timeout=180)
            if cp.returncode != 0:
                print(f'[Monitor] FAIL (rc={cp.returncode}): {cp.stderr.strip()[:300]}', flush=True)
            else:
                # Verify output CSV exists
                csv_out = os.path.join(OUTPUT_DIR, f'{prefix}_cfi_events.csv')
                if os.path.exists(csv_out):
                    lines = sum(1 for _ in open(csv_out))
                    print(f'[Monitor] OK — {prefix}_cfi_events.csv ({lines} lines)', flush=True)
                else:
                    print(f'[Monitor] WARN — CSV not found: {csv_out}', flush=True)
            return (cp.returncode, cp.stderr.strip())
        except subprocess.TimeoutExpired:
            print('[Monitor] TIMEOUT', flush=True)
            return (-1, '监控超时')
        except Exception as e:
            print(f'[Monitor] EXCEPTION: {e}', flush=True)
            return (-1, str(e))

    def _parse_dfi_register_detail(self, dfi_prefix):
        """解析 DFI def-use 链，按寄存器展示值变化及对应指令。"""
        du_csv = dfi_prefix + '_def_use_chains.csv'

        result = {'registers': {}}
        if not os.path.exists(du_csv):
            return result

        # 读取 def-use 链
        chains_by_reg = defaultdict(list)
        with open(du_csv, 'r', encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                reg = row.get('reg', '?')
                chains_by_reg[reg].append({
                    'def_func': row.get('def_func', '?'),
                    'def_addr': row.get('def_addr', '0x0'),
                    'def_instr': row.get('def_instr', '?'),
                    'use_func': row.get('use_func', '?'),
                    'use_addr': row.get('use_addr', '0x0'),
                    'use_instr': row.get('use_instr', '?'),
                    'cross_func': row.get('cross_func', 'No'),
                    'violation': row.get('dfi_violation', 'OK'),
                    'def_source': row.get('def_source', '?'),
                    'indirect_type': row.get('indirect_type', ''),
                })

        # 按寄存器整理链
        for reg, chains in chains_by_reg.items():
            # 按 use_addr 排序
            chains.sort(key=lambda x: int(x['use_addr'], 16) if x['use_addr'].startswith('0x') else 0)
            result['registers'][reg] = {
                'chain_count': len(chains),
                'chains': chains[:20],  # 最多20条
            }

        return result

    def _parse_results(self, prefix, attack_id, mode, start_time):
        """从 output CSV 中提取违规摘要。"""
        cfi_path = os.path.join(OUTPUT_DIR, f'{prefix}_cfi_events.csv')
        dfi_path = os.path.join(OUTPUT_DIR, f'{prefix}_dfi_layers.csv')

        summary = {'total_cfi': 0, 'total_dfi': 0, 'correct_rate': 100}
        violations = []

        if os.path.exists(cfi_path):
            with open(cfi_path, 'r', encoding='utf-8') as f:
                rows = list(csv.DictReader(f))
            summary['total_cfi'] = len(rows)
            for r in rows:
                if int(r.get('is_correct', 1)) == 0:
                    violations.append({
                        'event_id': r.get('event_id', '?'),
                        'jump_type_name': r.get('jump_type_name', '?'),
                        'src_func': r.get('src_func', '?'),
                        'dst_func': r.get('dst_func', '?'),
                        'reg_rax': r.get('reg_rax', '0x0'),
                        'ret_addr': r.get('ret_addr', '0x0'),
                    })
            if rows:
                correct_count = sum(1 for r in rows if int(r.get('is_correct', 1)) == 1)
                summary['correct_rate'] = round(correct_count / len(rows) * 100, 1)

        if os.path.exists(dfi_path):
            with open(dfi_path, 'r', encoding='utf-8') as f:
                summary['total_dfi'] = sum(1 for _ in csv.DictReader(f))

        elapsed = round(time.time() - start_time, 1)

        return {
            'attack_id': attack_id,
            'mode': mode,
            'prefix': prefix,
            'elapsed_seconds': elapsed,
            'summary': summary,
            'violations': violations,
        }


# ============================================================
#  HTTP 服务器
# ============================================================

store = None
attack_manager = None

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # 静默 HTTP 日志（错误仍会输出到 stderr）
        pass

    # ── JSON / Static helpers ──

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path):
        """Serve a static file from web/ directory."""
        safe_path = os.path.normpath(os.path.join(WEB_DIR, rel_path))
        # Security: ensure path is within WEB_DIR
        if not safe_path.startswith(os.path.normpath(WEB_DIR)):
            self.send_error(403)
            return
        try:
            with open(safe_path, 'rb') as f:
                content = f.read()
            ext = os.path.splitext(safe_path)[1]
            mime = MIME_TYPES.get(ext, 'application/octet-stream')
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

    # ── Param parser ──

    def _params(self):
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _p(self, params, key, default=None, cast=str):
        v = params.get(key, [None])[0]
        if v is None:
            return default
        try:
            return cast(v)
        except (ValueError, TypeError):
            return default

    # ── GET ──

    def do_GET(self):
        path, params = self._params()

        # ---- Static files ----
        if path == '/':
            self._serve_static('index.html')
        elif path == '/dashboard':
            self._serve_static('dashboard.html')
        elif path.startswith('/css/') or path.startswith('/js/'):
            self._serve_static(path.lstrip('/'))
        # ---- Monitoring APIs ----
        elif path == '/api/summary':
            source = params.get('source', ['demo'])[0]
            if source != store.prefix:
                store.set_source(source)
            self._send_json(store.get_summary())
        elif path == '/api/cfi_events':
            source = params.get('source', ['demo'])[0]
            if source != store.prefix:
                store.set_source(source)
            result = store.get_cfi_events(
                offset=self._p(params, 'offset', 0, int),
                limit=self._p(params, 'limit', 200, int),
                jump_type=self._p(params, 'jump_type', None, int),
                src_func=params.get('src_func', [None])[0],
                is_correct=self._p(params, 'is_correct', None, int),
                search=params.get('search', [None])[0],
            )
            self._send_json(result)
        elif path == '/api/dfi_events':
            source = params.get('source', ['demo'])[0]
            if source != store.prefix:
                store.set_source(source)
            result = store.get_dfi_events(
                offset=self._p(params, 'offset', 0, int),
                limit=self._p(params, 'limit', 200, int),
            )
            self._send_json(result)
        elif path == '/api/dfi_chains':
            source = params.get('source', ['demo'])[0]
            if source != store.prefix:
                store.set_source(source)
            summary = store.get_summary()
            self._send_json(summary.get('site_chains', {}))
        # ---- Attack APIs ----
        # ---- Program list ----
        elif path == '/api/programs':
            # 自动扫描 test/*.c 生成程序列表
            BUILTIN_DESC = {
                'test.c': '17 种正常间接跳转场景',
                'attack.c': '7 种 CFI 违规攻击场景',
                'a.c': '17 正常场景 + 7 攻击场景（综合）',
            }
            programs = []
            if os.path.isdir(TEST_DIR):
                for f in sorted(os.listdir(TEST_DIR)):
                    if f.endswith('.c') and not f.startswith('.'):
                        basename = os.path.splitext(f)[0]
                        desc = BUILTIN_DESC.get(f, '用户文件')
                        ptype = 'builtin' if f in BUILTIN_DESC else 'import'
                        pid = basename if ptype == 'builtin' else f'import/{f}'
                        programs.append({'id': pid, 'name': f, 'desc': desc, 'type': ptype})
            self._send_json({'programs': programs})
        elif path == '/api/attacks':
            self._send_json({'attacks': attack_manager.list_attacks()})
        elif path.startswith('/api/attack_result/'):
            task_id = os.path.basename(path)
            task = attack_manager.get_task(task_id)
            if not task:
                self._send_json({'error': '任务不存在'}, 404)
            elif task['status'] == 'done':
                result = dict(task['result']) if task['result'] else {}
                result['status'] = 'done'
                result['task_id'] = task_id
                self._send_json(result)
            else:
                resp = {
                    'status': task['status'],
                    'task_id': task_id,
                }
                if task.get('error'):
                    resp['error'] = task['error']
                self._send_json(resp)
        elif path == '/api/attacks/history':
            self._send_json(list(attack_manager.tasks.values()))
        elif path == '/api/rop_attacks':
            self._send_json({
                'attack_types': [
                    {'id': 'sh', 'desc': 'pwntools /bin/sh shellcode'},
                    {'id': 'exit0', 'desc': '安全退出 exit(0)'},
                    {'id': 'simplenop', 'desc': 'NOP滑板 + shellcode'},
                    {'id': 'nonop', 'desc': '纯shellcode (RIPE 风格)'},
                    {'id': 'polynop', 'desc': '多态NOP + shellcode'},
                    {'id': 'createfile', 'desc': '创建文件攻击'},
                    {'id': 'returnintolibc', 'desc': '返回libc攻击'},
                    {'id': 'rop', 'desc': 'ROP链攻击'},
                ]
            })
        # ---- Safe Test (no attack selection) ----
        elif path == '/api/safe_test':
            iterations = self._p(params, 'n', 3, int)
            task = attack_manager.start_run('test', 'safe', 0, iterations)
            self._send_json(task, 202)
        # ---- DFI Register Detail ----
        elif path == '/api/dfi_detail':
            source = params.get('source', ['test'])[0]
            # Build path dynamically: build/<source>/<source>_register_dfi
            dfi_prefix = os.path.join(BUILD_DIR, source, f'{source}_register_dfi')
            detail = attack_manager._parse_dfi_register_detail(dfi_prefix)
            self._send_json(detail)
        else:
            self.send_error(404)

    # ── POST ──

    def do_POST(self):
        path, _ = self._params()
        content_length = int(self.headers.get('Content-Length', 0))

        if path == '/api/run':
            body = {}
            if content_length > 0:
                body = json.loads(self.rfile.read(content_length))
            program = body.get('program', 'test')
            mode = body.get('mode', 'safe')
            attack_id = body.get('attack_id', 0)
            iterations = body.get('iterations', 1)
            task = attack_manager.start_run(program, mode, attack_id, iterations)
            self._send_json(task, 202)

        elif path == '/api/rop_attack':
            body = {}
            if content_length > 0:
                body = json.loads(self.rfile.read(content_length))
            attack_type = body.get('attack_type', 'sh')
            target = body.get('target', 0)
            mode = body.get('mode', 'enforce')
            task = attack_manager.start_rop_attack(attack_type, target, mode)
            self._send_json(task, 202)

        elif path == '/api/run_attack':
            body = {}
            if content_length > 0:
                body = json.loads(self.rfile.read(content_length))
            attack_id = body.get('attack_id')
            mode = body.get('mode', 'attack')
            iterations = body.get('iterations', 3)
            if not attack_id:
                self._send_json({'error': '缺少 attack_id'}, 400)
                return
            task = attack_manager.start_run('attack', mode, attack_id, iterations)
            self._send_json(task, 202)

        elif path == '/api/import':
            # 处理 .c 文件上传 (base64 JSON)
            body = json.loads(self.rfile.read(content_length)) if content_length else {}
            filename = body.get('filename', 'uploaded.c')
            b64data = body.get('data', '')
            try:
                file_data = base64.b64decode(b64data)
            except Exception:
                self._send_json({'error': '文件数据解码失败'}, 400)
                return
            if not file_data:
                self._send_json({'error': '缺少文件数据'}, 400)
                return
            task = attack_manager.start_import(file_data, filename)
            self._send_json(task, 202)

        else:
            self.send_error(404)


# ============================================================
#  主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='CFI/DFI Attack Monitor 服务器')
    parser.add_argument('-p', '--port', type=int, default=8080, help='监听端口 (默认: 8080)')
    parser.add_argument('-d', '--data-dir', default=None, help='数据目录 (默认: output/)')
    parser.add_argument('-P', '--prefix', default='demo', help='文件前缀 (默认: demo)')
    args = parser.parse_args()

    output_dir = args.data_dir or OUTPUT_DIR
    output_dir = os.path.abspath(output_dir)

    global store, attack_manager
    store = DataStore(output_dir, args.prefix)
    attack_manager = AttackManager()

    # 获取本机 IP
    local_ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in ('127.0.0.1', '::1') and not ip.startswith('fe80:'):
                local_ips.append(ip)
        local_ips = list(dict.fromkeys(local_ips))
    except Exception:
        pass

    PORT = args.port

    # 检查 root 权限
    is_root = (os.geteuid() == 0)
    root_status = "✅ root — eBPF 监控可用" if is_root else "⚠ 非 root — eBPF 监控不可用"
    if not is_root:
        print("\n⚠ 警告: 未以 root 运行，eBPF 监控功能不可用。")
        print("  请用 sudo 启动:  sudo python3 src/server.py")
        print("  或运行:  ./start.sh\n")

    print(f"""
╔══════════════════════════════════════════════╗
║   CFI/DFI Attack Monitor 服务器              ║
╠══════════════════════════════════════════════╣
║  权限状态: {root_status:<31s} ║
║  数据目录: {output_dir:<33s} ║
║  文件前缀: {args.prefix:<33s} ║
║  攻击场景: {len(attack_manager.ATTACKS):<33} ║
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
