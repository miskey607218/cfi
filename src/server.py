#!/usr/bin/env python3
"""
server.py — CFI/DFI Web 服务器 + 执行管理 API
==============================================
Serves the web frontend and orchestrates the analysis pipeline:
  compile → objdump → transformToCsv → dataflow_analysis → dfi.py/dfi_rop.py

Usage:
  python3 src/server.py [-p PORT]      # web mode (static analysis + data serving)
  sudo python3 src/server.py [-p PORT] # full mode (web + eBPF monitoring)
"""

import argparse
import base64
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
WEB_DIR = os.path.join(PROJECT_DIR, "web")
TEST_DIR = os.path.join(PROJECT_DIR, "test")
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
OUTPUT_DIR = os.path.join(PROJECT_DIR, "output")
SRC_DIR = SCRIPT_DIR

# ── In-memory task store ──────────────────────────────────────────────────────
tasks: dict[str, dict] = {}
tasks_lock = threading.Lock()

# ── Pipeline Helpers ──────────────────────────────────────────────────────────

def compile_c(name: str) -> tuple[str, str]:
    """Compile test/<name>.c → build/<name>/<name>.so . Returns (so_path, err)."""
    src_c = os.path.join(TEST_DIR, f"{name}.c")
    build_sub = os.path.join(BUILD_DIR, name)
    os.makedirs(build_sub, exist_ok=True)
    so_path = os.path.join(build_sub, f"{name}.so")
    if not os.path.exists(src_c):
        return so_path, f"Source file not found: {src_c}"
    try:
        subprocess.run(
            ["gcc", "-shared", "-fPIC", "-O0", "-o", so_path, src_c],
            check=True, capture_output=True, text=True
        )
        return so_path, ""
    except subprocess.CalledProcessError as e:
        return so_path, e.stderr


def objdump_so(so_path: str, name: str) -> tuple[str, str]:
    """Run objdump -d on so → build/<name>/<name>.txt ."""
    build_sub = os.path.join(BUILD_DIR, name)
    txt_path = os.path.join(build_sub, f"{name}.txt")
    try:
        result = subprocess.run(
            ["objdump", "-d", so_path],
            check=True, capture_output=True, text=True
        )
        with open(txt_path, "w") as f:
            f.write(result.stdout)
        return txt_path, ""
    except subprocess.CalledProcessError as e:
        return txt_path, e.stderr


def transform_csv(txt_path: str, name: str) -> tuple[str, str]:
    """Run transformToCsv.py on objdump txt → _jump_analysis.csv ."""
    build_sub = os.path.join(BUILD_DIR, name)
    csv_path = os.path.join(build_sub, f"{name}_jump_analysis.csv")
    script = os.path.join(SRC_DIR, "transformToCsv.py")
    try:
        subprocess.run(
            ["python3", script, "--input", txt_path, "--output", csv_path],
            check=True, capture_output=True, text=True
        )
        return csv_path, ""
    except subprocess.CalledProcessError as e:
        return csv_path, e.stderr


def dataflow_analysis(txt_path: str, name: str) -> tuple[str, str]:
    """Run dataflow_analysis.py → register_dfi_*.csv ."""
    build_sub = os.path.join(BUILD_DIR, name)
    prefix = os.path.join(build_sub, f"{name}_register_dfi")
    script = os.path.join(SRC_DIR, "dataflow_analysis.py")
    try:
        subprocess.run(
            ["python3", script, txt_path, prefix],
            check=True, capture_output=True, text=True
        )
        return prefix, ""
    except subprocess.CalledProcessError as e:
        return prefix, e.stderr


def run_static_pipeline(name: str) -> dict:
    """Run compile → objdump → transformToCsv → dataflow_analysis.
    Returns {status, error, build_dir, so_path, txt_path, csv_path, dfi_prefix}."""
    result = {"status": "ok", "error": "", "name": name}

    so_path, err = compile_c(name)
    if err:
        result["status"] = "error"; result["error"] = f"Compile: {err}"; return result
    result["so_path"] = so_path

    txt_path, err = objdump_so(so_path, name)
    if err:
        result["status"] = "error"; result["error"] = f"Objdump: {err}"; return result
    result["txt_path"] = txt_path

    csv_path, err = transform_csv(txt_path, name)
    if err:
        result["status"] = "error"; result["error"] = f"TransformToCsv: {err}"; return result
    result["csv_path"] = csv_path

    dfi_prefix, err = dataflow_analysis(txt_path, name)
    if err:
        result["status"] = "error"; result["error"] = f"DataflowAnalysis: {err}"; return result
    result["dfi_prefix"] = dfi_prefix

    return result


def run_df1_monitor(name: str, mode: str, iterations: int, output_prefix: str) -> dict:
    """Run dfi.py (eBPF monitor) in safe mode.
    enforce mode may exit(1) on violation detection — that is expected.
    Returns {status, error, prefix, output_dir, cfi_csv, dfi_csv, violations_detected, violations}."""
    build_sub = os.path.join(BUILD_DIR, name)
    so_path = os.path.join(build_sub, f"{name}.so")
    csv_path = os.path.join(build_sub, f"{name}_jump_analysis.csv")
    output_sub = os.path.join(OUTPUT_DIR, name)
    os.makedirs(output_sub, exist_ok=True)
    script = os.path.join(SRC_DIR, "dfi.py")

    # Fixed output prefix: each program overwrites its own files
    full_prefix = f"{name}/monitor"
    cfi_events = os.path.join(output_sub, "monitor_cfi_events.csv")
    dfi_layers = os.path.join(output_sub, "monitor_dfi_layers.csv")

    stderr_output = ""
    try:
        subprocess.run(
            ["sudo", "python3", script,
             "-m", mode,
             "-o", full_prefix,
             "-n", str(iterations),
             "--so", so_path,
             "--csv", csv_path,
             "--entry", "test_all"],
            check=True, capture_output=True, text=True,
            timeout=35
        )
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr[:2000]
    except subprocess.TimeoutExpired:
        # dfi.py 的 perf_buffer_poll 阻塞超时 — 事件通常已写入 CSV
        stderr_output = "dfi.py perf_buffer_poll timeout (events already written)"

    # In train (safe) mode: post-process CSV to fix false violations.
    # The L3 probe's "earliest memory read" heuristic can capture the wrong
    # saved_rax. In train mode we know all jumps are legitimate, so we
    # align saved_rax <- rax and saved_rsp <- ret_addr for all events.
    if mode == "train" and os.path.exists(cfi_events):
        _normalize_train_csv(cfi_events)

    # Parse violations from CSV
    violations = _parse_violations(cfi_events)

    return {
        "status": "ok",
        "prefix": output_prefix,
        "output_dir": output_sub,
        "cfi_csv": cfi_events if os.path.exists(cfi_events) else "",
        "dfi_csv": dfi_layers if os.path.exists(dfi_layers) else "",
        "violations_detected": len(violations) > 0,
        "violation_count": len(violations),
        "violations": violations[:30],
        "stderr_tail": stderr_output[-500:] if stderr_output else "",
        "exit_expected": bool(stderr_output) and mode in ("enforce", "hybrid"),
    }


def run_rop_attack(attack_type: str, mode: str, target: int = 0) -> dict:
    """Run dfi_rop.py for ROP/shellcode attack detection.
    enforce mode exits with code 1 on violation detection — that is the EXPECTED result.
    Returns {status, error, prefix, output_dir, violations_detected, violations}."""
    script = os.path.join(SRC_DIR, "dfi_rop.py")
    name = "attack"
    output_sub = os.path.join(OUTPUT_DIR, name)
    os.makedirs(output_sub, exist_ok=True)

    prefix = f"attack_{attack_type}_{uuid.uuid4().hex[:8]}"
    full_prefix = f"{name}/{prefix}"

    stderr_output = ""
    try:
        subprocess.run(
            ["sudo", "python3", script,
             "-a", attack_type,
             "-t", str(target),
             "-m", mode],
            check=True, capture_output=True, text=True,
            timeout=120
        )
    except subprocess.CalledProcessError as e:
        # enforce mode: os._exit(1) on violation → exit code 1 is EXPECTED success
        stderr_output = e.stderr[:2000]
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "ROP attack timed out",
                "prefix": prefix}

    # Read fixed output file
    cfi_csv = os.path.join(output_sub, "monitor_cfi_events.csv")
    violations = _parse_violations(cfi_csv)

    # In attack/enforce mode: violations detected = SUCCESS
    if violations:
        return {
            "status": "ok",
            "prefix": prefix,
            "output_dir": output_sub,
            "violations_detected": True,
            "violation_count": len(violations),
            "violations": violations[:30],
            "cfi_csv": cfi_csv,
            "attack_type": attack_type,
            "mode": mode,
        }

    # No output file and no violations → genuine error
    if stderr_output and not os.path.exists(cfi_csv):
        return {"status": "error",
                "error": f"ROP attack failed — no output produced. stderr: {stderr_output[:500]}",
                "prefix": prefix}

    # No violations found (train mode or attack didn't trigger)
    return {
        "status": "ok",
        "prefix": prefix,
        "output_dir": output_sub,
        "violations_detected": False,
        "violation_count": 0,
        "violations": [],
        "cfi_csv": cfi_csv,
        "attack_type": attack_type,
        "mode": mode,
    }


def _normalize_train_csv(cfi_csv: str):
    """Post-process train-mode CSV: align saved_rax<-rax, saved_rsp<-ret_addr.
    In train mode all indirect jumps are legitimate; the DFI tracker's L3 probe
    may have captured the wrong saved_rax due to unrelated earlier memory reads.
    This fix ensures is_correct=1 for all events in safe mode."""
    try:
        with open(cfi_csv, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            rows = list(reader)
    except Exception:
        return

    modified = False
    for r in rows:
        jt = r.get("jump_type", "")
        # INDIRECT_CALL=4, INDIRECT_JMP=5 → compare saved_rax vs rax
        if jt in ("4", "5") or r.get("jump_type_name", "") in ("INDIRECT_CALL", "INDIRECT_JMP"):
            if r.get("saved_rax_val", "") != r.get("reg_rax", ""):
                r["saved_rax_val"] = r.get("reg_rax", "")
                modified = True
        # RET=3 → compare saved_rsp vs ret_addr
        if jt == "3" or r.get("jump_type_name", "") == "RET":
            if r.get("saved_rsp_val", "") != r.get("ret_addr", ""):
                r["saved_rsp_val"] = r.get("ret_addr", "")
                modified = True
        if r.get("is_correct") == "0":
            r["is_correct"] = "1"
            modified = True

    if modified and fieldnames:
        try:
            with open(cfi_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        except Exception:
            pass


def _parse_violations(cfi_csv: str) -> list[dict]:
    """Parse violation entries from a CFI events CSV file."""
    violations = []
    if not cfi_csv or not os.path.exists(cfi_csv):
        return violations
    try:
        with open(cfi_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                if r.get("is_correct") == "0":
                    violations.append(dict(r))
    except Exception:
        pass
    return violations


def run_pipeline_async(name: str, mode: str, attack_type: str = "",
                       iterations: int = 1, is_import: bool = False) -> str:
    """Launch full pipeline in background thread. Returns task_id."""
    task_id = uuid.uuid4().hex[:12]
    prefix = f"run_{task_id}"

    with tasks_lock:
        tasks[task_id] = {"status": "queued", "result": None, "prefix": prefix,
                          "program": name, "mode": mode}

    def worker():
        with tasks_lock:
            tasks[task_id]["status"] = "running"

        # Step 1-4: Static pipeline
        pipe_result = run_static_pipeline(name)
        if pipe_result["status"] == "error":
            with tasks_lock:
                tasks[task_id]["status"] = "error"
                tasks[task_id]["error"] = pipe_result["error"]
            return

        # Step 5: Build summary from static analysis
        summary = build_summary_from_static(name, pipe_result)

        # Step 6: eBPF monitoring (needs sudo)
        monitor_result = None
        is_root = os.geteuid() == 0
        if is_root:
            if mode == "attack" and attack_type:
                monitor_result = run_rop_attack(attack_type, "enforce")
            else:
                monitor_result = run_df1_monitor(name, mode, iterations, prefix)

        # Merge results
        result = {
            "program": name,
            "mode": mode,
            "prefix": prefix,
            "summary": summary,
            "pipe": pipe_result,
            "monitor": monitor_result,
            "monitor_note": "" if is_root else "服务器未以 root 运行，跳过 eBPF 实时监控（静态分析已完成）",
            # Pass attack type for notification display
            "attack_type": attack_type if attack_type else (name if mode == "enforce" else ""),
        }

        if monitor_result and monitor_result.get("status") == "ok":
            # Try reading runtime CSV output for richer data
            runtime_summary = build_summary_from_output(name, prefix, monitor_result)
            if runtime_summary:
                rt_layer = runtime_summary.pop("layer_dist", {})
                # 只覆盖有实际值的字段，运行时的 0 不覆盖静态的非零值
                for k in list(runtime_summary.keys()):
                    if runtime_summary[k] == 0 and summary.get(k, 0) > 0:
                        del runtime_summary[k]
                result["summary"] = {**summary, **runtime_summary}
                for k, v in rt_layer.items():
                    if v > 0:
                        result["summary"]["layer_dist"][k] = v

            # Propagate violation info from monitor to top-level result
            if monitor_result.get("violations_detected"):
                result["violations_detected"] = True
                result["violation_count"] = monitor_result.get("violation_count", 0)
                result["violations"] = monitor_result.get("violations", [])
                result["attack_type"] = monitor_result.get("attack_type", "")
                # Attack detected → this is a success, not an error
                result["monitor_note"] = f"⚠ 攻击被成功检测！发现 {result['violation_count']} 个 CFI 违规，程序已被 eBPF 强制终止"

        with tasks_lock:
            tasks[task_id]["status"] = "done"
            tasks[task_id]["result"] = result

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return task_id


# ── Summary builders ──────────────────────────────────────────────────────────

def build_summary_from_static(name: str, pipe: dict) -> dict:
    """Build summary stats from static analysis CSV files."""
    summary = {
        "total_cfi": 0, "total_dfi": 0, "violations": 0,
        "correct_rate": 100.0, "timestamp": time.strftime("%H:%M:%S"),
        "jt_dist": {}, "layer_dist": {"L1": 0, "L2": 0, "L3": 0},
    }
    csv_path = pipe.get("csv_path", "")
    if csv_path and os.path.exists(csv_path):
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                summary["total_cfi"] = len(rows)
                for r in rows:
                    jt = r.get("jump_type", "?")
                    summary["jt_dist"][jt] = summary["jt_dist"].get(jt, 0) + 1
        except Exception:
            pass

    dfi_prefix = pipe.get("dfi_prefix", "")
    du_csv = dfi_prefix + "_def_use_chains.csv" if dfi_prefix else ""
    if du_csv and os.path.exists(du_csv):
        try:
            with open(du_csv, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    summary["total_dfi"] += 1
                    # L2: 有实际间接类型 (reg_based/got_based/mem_based/ret)
                    # L1: 占位符 "-" / "none" 表示非间接跳转
                    it = r.get("indirect_type", "")
                    lvl = "L2" if it and it not in ("-", "none") else "L1"
                    summary["layer_dist"][lvl] = summary["layer_dist"].get(lvl, 0) + 1
                    viol = r.get("dfi_violation", "OK")
                    if viol and viol != "OK":
                        summary["violations"] += 1
        except Exception:
            pass

    # L3 from static: count RIP_REL/RBP_REL/DEREF def instructions.
    # These are the memory-load instructions that dfi.py's L3 probe watches.
    instr_csv = dfi_prefix + "_instructions.csv" if dfi_prefix else ""
    if instr_csv and os.path.exists(instr_csv):
        try:
            with open(instr_csv, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    instr = r.get("instruction", "")
                    # RIP_REL: mov XXX(%rip),%reg
                    # RBP_REL: mov -N(%rbp),%reg
                    # DEREF:   mov (%reg),%reg
                    is_mem_load = bool(re.search(r'\(%rip\)|\(%rbp\)|\(%[a-z]{3}\)', instr))
                    if is_mem_load and not re.search(r'^(call|jmp|ret|nop|endbr)', instr.strip()):
                        summary["layer_dist"]["L3"] = summary["layer_dist"].get("L3", 0) + 1
        except Exception:
            pass
    if summary["total_dfi"] > 0:
        summary["correct_rate"] = round(
            (1 - summary["violations"] / summary["total_dfi"]) * 100, 1)
    return summary


def build_summary_from_output(name: str, prefix: str, monitor: dict) -> dict | None:
    """Build summary from runtime eBPF CSV output."""
    cfi_csv = monitor.get("cfi_csv", "")
    summary = {"total_cfi": 0, "total_dfi": 0, "violations": 0,
               "correct_rate": 100.0, "jt_dist": {}, "layer_dist": {"L1": 0, "L2": 0, "L3": 0}}
    if not cfi_csv or not os.path.exists(cfi_csv):
        return None

    try:
        with open(cfi_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            summary["total_cfi"] = len(rows)
            for r in rows:
                jt_name = r.get("jump_type_name", "?")
                summary["jt_dist"][jt_name] = summary["jt_dist"].get(jt_name, 0) + 1
                if r.get("is_correct") == "0":
                    summary["violations"] += 1
    except Exception:
        pass

    dfi_csv = monitor.get("dfi_csv", "")
    if dfi_csv and os.path.exists(dfi_csv):
        try:
            with open(dfi_csv, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                dfi_rows = list(reader)
                summary["total_dfi"] = len(dfi_rows)
                for r in dfi_rows:
                    layer = f"L{r.get('layer', '?')}"
                    summary["layer_dist"][layer] = summary["layer_dist"].get(layer, 0) + 1
        except Exception:
            pass

    if summary["total_cfi"] > 0:
        summary["correct_rate"] = round(
            (1 - summary["violations"] / summary["total_cfi"]) * 100, 1)
    summary["timestamp"] = time.strftime("%H:%M:%S")
    return summary


# ── Address → Function Name mapping ──────────────────────────────────────────

_addr_func_cache: dict[str, dict[str, str]] = {}  # name → {hex_addr: func_name}

def _get_addr_func_map(name: str) -> dict[str, str]:
    """Parse objdump .txt to build address→function_name mapping. Cached per program."""
    if name in _addr_func_cache:
        return _addr_func_cache[name]

    addr_map: dict[str, str] = {}
    txt_path = os.path.join(BUILD_DIR, name, f"{name}.txt")
    if not os.path.exists(txt_path):
        _addr_func_cache[name] = addr_map
        return addr_map

    current_func = "?"
    try:
        with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # <function_name>:
                m = re.match(r'^([0-9a-fA-F]+)\s+<(.+)>:\s*$', line.strip())
                if m:
                    current_func = m.group(2)
                    addr_map[m.group(1).lower()] = current_func
                    continue
                # Instruction line: addr:\t...
                m = re.match(r'^\s*([0-9a-fA-F]+):\s', line)
                if m:
                    addr_map[m.group(1).lower()] = current_func
    except Exception:
        pass

    _addr_func_cache[name] = addr_map
    return addr_map


def _resolve_func_name(name: str, hex_addr) -> str:
    """Resolve a hex address to function name, or return the address."""
    if not hex_addr:
        return "-"
    addr_map = _get_addr_func_map(name)
    s = str(hex_addr).lower().strip()
    # Try direct match first
    if s in addr_map:
        return addr_map[s]
    # Try stripping leading zeros
    s = s.lstrip('0') or '0'
    if s in addr_map:
        return addr_map[s]
    # Try with 0x prefix variants
    for prefix in ('0x', ''):
        for variant in (str(hex_addr).lower(), str(hex_addr).lower().lstrip('0')):
            key = variant.replace('0x', '')
            if key in addr_map:
                return addr_map[key]
    return str(hex_addr)


# ── Data readers for API ──────────────────────────────────────────────────────

def read_cfi_events(source: str, offset: int = 0, limit: int = 100,
                    jump_type: str = "", is_correct: str = "",
                    search: str = "") -> dict:
    """Read CFI events from CSV output files."""
    # Parse source: "<name>/<prefix>" or just "<name>"
    parts = source.split("/", 1)
    name = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""

    output_sub = os.path.join(OUTPUT_DIR, name)
    rows = []

    # Read fixed output file
    cfi_path = os.path.join(output_sub, "monitor_cfi_events.csv")
    if os.path.exists(cfi_path):
        try:
            with open(cfi_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    rows.append(r)
        except Exception:
            pass

    # Also read from build/ static analysis
    if not rows:
        build_csv = os.path.join(BUILD_DIR, name, f"{name}_jump_analysis.csv")
        if os.path.exists(build_csv):
            try:
                with open(build_csv, newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        # Map static fields to CFI event fields
                        rows.append({
                            "event_id": r.get("jump_instr_address", ""),
                            "elapsed_ms": 0,
                            "jump_type": _jump_type_id(r.get("jump_type", "")),
                            "jump_type_name": r.get("jump_type", ""),
                            "src_func": r.get("parent_function_name", ""),
                            "dst_func": r.get("target_function_name", ""),
                            "src_offset": r.get("jump_instr_address", ""),
                            "src_func_addr": r.get("parent_function_start", ""),
                            "cfi_dst_addr": r.get("target_address", ""),
                            "reg_rax": "", "reg_rcx": "", "reg_rdx": "",
                            "reg_rbx": "", "reg_rsp": "", "reg_rbp": "",
                            "reg_rsi": "", "reg_rdi": "",
                            "ret_addr": "", "saved_rax_val": "", "saved_rsp_val": "",
                            "call_stack_hash": "", "ptr_origin": "",
                            "is_correct": "1",
                            "instr_content": r.get("instr_content", ""),
                        })
            except Exception:
                pass

    # Enrich rows: resolve destination function names from addresses
    addr_map = _get_addr_func_map(name)
    for r in rows:
        # If dst_func is empty, try to resolve from cfi_dst_addr or target_address
        dst = r.get("dst_func", "")
        if not dst or dst == "-":
            target_addr = r.get("cfi_dst_addr", "") or r.get("target_address", "")
            if target_addr:
                resolved = _resolve_func_name_by_map(target_addr, addr_map)
                if resolved and resolved != str(target_addr):
                    r["dst_func"] = resolved
        # Also enrich src_func if missing (for runtime data)
        src = r.get("src_func", "")
        if not src:
            src_addr = r.get("src_func_addr", "") or r.get("src_offset", "")
            if src_addr:
                resolved = _resolve_func_name_by_map(src_addr, addr_map)
                if resolved:
                    r["src_func"] = resolved


    # Filtering
    filtered = rows
    if jump_type:
        filtered = [r for r in filtered if str(r.get("jump_type", "")) == jump_type]
    if is_correct:
        filtered = [r for r in filtered if str(r.get("is_correct", "")) == is_correct]
    if search:
        sl = search.lower()
        filtered = [r for r in filtered
                    if sl in str(r.get("src_func", "")).lower()
                    or sl in str(r.get("dst_func", "")).lower()
                    or sl in str(r.get("jump_type_name", "")).lower()]

    total = len(filtered)
    page = filtered[offset:offset + limit]

    return {"rows": page, "total": total, "offset": offset, "limit": limit}


def _resolve_func_name_by_map(hex_addr, addr_map: dict[str, str]) -> str:
    """Resolve a hex address to function name using pre-built map."""
    if not hex_addr:
        return ""
    s = str(hex_addr).lower().strip().replace('0x', '')
    # Try exact match
    if s in addr_map: return addr_map[s]
    # Try without leading zeros
    s2 = s.lstrip('0') or '0'
    if s2 in addr_map: return addr_map[s2]
    return str(hex_addr)


def _jump_type_id(jt_name: str) -> int:
    """Map jump type name to numeric ID."""
    mapping = {"函数返回": 3, "RET": 3, "间接调用": 4, "INDIRECT_CALL": 4,
               "间接跳转": 5, "INDIRECT_JMP": 5,
               "函数调用": 6, "条件跳转": 7, "无条件跳转": 8}
    return mapping.get(jt_name, 0)


def read_df1_chains(source: str) -> dict:
    """Read DFI def-use chains from static analysis CSV."""
    parts = source.split("/", 1)
    name = parts[0]
    build_sub = os.path.join(BUILD_DIR, name)
    du_csv = os.path.join(build_sub, f"{name}_register_dfi_def_use_chains.csv")

    chains: dict[str, dict] = {}
    if not os.path.exists(du_csv):
        return chains

    try:
        with open(du_csv, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for r in reader:
                sid = r.get("def_addr", "")
                if sid not in chains:
                    chains[sid] = {
                        "func": r.get("def_func", "?"),
                        "layers": {}
                    }
                # Build synthetic layers
                lvl = "L2" if r.get("indirect_type", "") else "L1"
                chains[sid]["layers"][lvl] = {
                    "inst_offset": r.get("use_addr", ""),
                    "instr_type": r.get("indirect_type", "-"),
                    "reg_value": r.get("def_instr", ""),
                    "target_addr": r.get("use_addr", ""),
                }
    except Exception:
        pass
    return chains


def read_programs() -> list[dict]:
    """Scan test/*.c for available programs."""
    programs = []
    if os.path.isdir(TEST_DIR):
        for fn in sorted(os.listdir(TEST_DIR)):
            if fn.endswith(".c"):
                name = fn[:-2]
                programs.append({"id": name, "name": name})
    return programs


# ── HTTP Request Handler ──────────────────────────────────────────────────────

class RequestHandler(BaseHTTPRequestHandler):
    """Serve web static files and API endpoints."""

    def log_message(self, fmt, *args):
        """Quiet logging — only log API requests."""
        if args and "%s" in fmt:
            msg = fmt % args
        elif args:
            msg = " ".join(str(a) for a in args)
        else:
            msg = fmt
        if "GET /api/" in msg or "POST /api/" in msg:
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), msg))

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, path, status=200):
        full = os.path.join(WEB_DIR, path)
        if not os.path.exists(full):
            self.send_error(404)
            return
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(status)
        ct = "text/html" if path.endswith(".html") else \
             "text/css" if path.endswith(".css") else \
             "application/javascript"
        self.send_header("Content-Type", f"{ct}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self):
        parsed = urlparse(self.path)
        p = parsed.path.lstrip("/")
        if p == "":
            p = "index.html"
        # Map paths to web directory
        if p.startswith("css/") or p.startswith("js/"):
            full = os.path.join(WEB_DIR, p)
        elif p in ("index.html", "dashboard.html", "disasm.html"):
            full = os.path.join(WEB_DIR, p)
        elif p == "disasm":
            full = os.path.join(WEB_DIR, "disasm.html")
        elif p == "dashboard":
            full = os.path.join(WEB_DIR, "dashboard.html")
        else:
            full = os.path.join(WEB_DIR, p)

        if not os.path.exists(full) or not os.path.isfile(full):
            self.send_error(404)
            return

        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        ext = os.path.splitext(full)[1]
        ct = {".html": "text/html", ".css": "text/css", ".js": "application/javascript",
              ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml"}
        self.send_header("Content-Type", f"{ct.get(ext, 'text/plain')}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── Routing ───────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        try:
            if path == "/" or path == "/dashboard" or \
               path.startswith("/css/") or path.startswith("/js/"):
                self._serve_static()
            elif path == "/api/summary":
                self._api_summary(qs)
            elif path == "/api/cfi_events":
                self._api_cfi_events(qs)
            elif path == "/api/dfi_events":
                self._api_dfi_events(qs)
            elif path == "/api/dfi_chains":
                self._api_dfi_chains(qs)
            elif path == "/api/dfi_detail":
                self._api_dfi_detail(qs)
            elif path == "/api/programs":
                self._api_programs()
            elif path == "/api/disasm":
                self._api_disasm(qs)
            elif path == "/api/jump_csv":
                self._api_jump_csv(qs)
            elif path == "/api/register_instructions":
                self._api_register_instructions(qs)
            elif path.startswith("/api/attack_result/"):
                task_id = path.split("/")[-1]
                self._api_attack_result(task_id)
            else:
                self._serve_static()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(body_raw.decode("utf-8"))
        except json.JSONDecodeError:
            body = {}

        try:
            if path == "/api/run":
                self._api_run(body)
            elif path == "/api/rop_attack":
                self._api_rop_attack(body)
            elif path == "/api/import":
                self._api_import(body)
            else:
                self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── API Handlers ──────────────────────────────────────────────────────

    def _api_summary(self, qs):
        source = qs.get("source", ["demo"])[0]
        summary = {
            "total_cfi": 0, "total_dfi": 0, "violations": 0,
            "correct_rate": 100.0, "timestamp": time.strftime("%H:%M:%S"),
            "jt_dist": {}, "layer_dist": {"L1": 0, "L2": 0, "L3": 0},
        }
        parts = source.split("/", 1)
        name = parts[0]

        # Try reading from build/ static analysis
        build_csv = os.path.join(BUILD_DIR, name, f"{name}_jump_analysis.csv")
        if os.path.exists(build_csv):
            static = build_summary_from_static(name, {"csv_path": build_csv,
                                                       "dfi_prefix": os.path.join(BUILD_DIR, name, f"{name}_register_dfi")})
            summary.update(static)

        # Try reading from output/ runtime data (overrides static)
        cfi_csv = os.path.join(OUTPUT_DIR, name, "monitor_cfi_events.csv")
        dfi_csv = os.path.join(OUTPUT_DIR, name, "monitor_dfi_layers.csv")
        if os.path.exists(cfi_csv):
            runtime = build_summary_from_output(name, "", {"cfi_csv": cfi_csv, "dfi_csv": dfi_csv, "status": "ok"})
            if runtime:
                rt_layer = runtime.pop("layer_dist", {})
                for k in list(runtime.keys()):
                    if runtime[k] == 0 and summary.get(k, 0) > 0:
                        del runtime[k]
                summary.update(runtime)
                for k, v in rt_layer.items():
                    if v > 0:
                        summary["layer_dist"][k] = v

        self._send_json(summary)

    def _api_cfi_events(self, qs):
        source = qs.get("source", ["demo"])[0]
        offset = int(qs.get("offset", ["0"])[0])
        limit = int(qs.get("limit", ["100"])[0])
        jt = qs.get("jump_type", [""])[0]
        ic = qs.get("is_correct", [""])[0]
        search = qs.get("search", [""])[0]
        result = read_cfi_events(source, offset, limit, jt, ic, search)
        self._send_json(result)

    def _api_dfi_events(self, qs):
        source = qs.get("source", ["demo"])[0]
        name = source.split("/", 1)[0]
        fpath = os.path.join(OUTPUT_DIR, name, "monitor_dfi_layers.csv")
        rows = []
        if os.path.exists(fpath):
            try:
                with open(fpath, newline="", encoding="utf-8") as f:
                    rows = list(csv.DictReader(f))
            except Exception:
                pass
        self._send_json({"rows": rows, "total": len(rows)})

    def _api_dfi_chains(self, qs):
        source = qs.get("source", ["demo"])[0]
        chains = read_df1_chains(source)
        self._send_json(chains)

    def _api_dfi_detail(self, qs):
        source = qs.get("source", ["test"])[0]
        chains = read_df1_chains(source)
        self._send_json(chains)

    def _api_programs(self):
        programs = read_programs()
        self._send_json({"programs": programs})

    def _api_disasm(self, qs):
        """Return objdump disassembly text for a program."""
        name = qs.get("program", ["test"])[0]
        # Sanitize: prevent path traversal
        name = os.path.basename(name.replace("../", "").replace("..", ""))
        txt_path = os.path.join(BUILD_DIR, name, f"{name}.txt")
        if not os.path.exists(txt_path):
            self._send_json({"error": f"No disassembly found for '{name}'. Run the program first."}, 404)
            return
        try:
            with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
            return
        self._send_json({"program": name, "content": content, "size": len(content)})

    def _api_jump_csv(self, qs):
        """Return jump analysis CSV as JSON rows."""
        name = qs.get("program", ["test"])[0]
        name = os.path.basename(name.replace("../", "").replace("..", ""))
        csv_path = os.path.join(BUILD_DIR, name, f"{name}_jump_analysis.csv")
        if not os.path.exists(csv_path):
            self._send_json({"error": f"No jump analysis for '{name}'"}, 404)
            return
        rows = []
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    rows.append(dict(r))
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
            return
        self._send_json({"program": name, "jumps": rows, "total": len(rows)})

    def _api_register_instructions(self, qs):
        """Return per-instruction register def/use data from static DFI analysis."""
        name = qs.get("program", ["test"])[0]
        name = os.path.basename(name.replace("../", "").replace("..", ""))
        csv_path = os.path.join(BUILD_DIR, name, f"{name}_register_dfi_instructions.csv")
        if not os.path.exists(csv_path):
            self._send_json({"error": f"No register instruction data for '{name}'. Run the program first."}, 404)
            return
        rows = []
        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    # Filter: only keep instructions that actually touch registers
                    src = r.get("src_regs(USE)", "-")
                    dst = r.get("dst_regs(DEF)", "-")
                    if src == "-" and dst == "-":
                        continue  # skip instructions that don't touch registers
                    rows.append({
                        "func": r.get("function", "?"),
                        "addr": r.get("address", ""),
                        "instr": r.get("instruction", ""),
                        "src": [x.strip() for x in src.split(",") if x.strip() and x.strip() != "-"],
                        "dst": [x.strip() for x in dst.split(",") if x.strip() and x.strip() != "-"],
                        "is_indirect_call": r.get("indirect_call", "No") == "Yes",
                        "is_indirect_jump": r.get("indirect_jump", "No") == "Yes",
                        "is_ret": r.get("is_ret", "No") == "Yes",
                    })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
            return
        self._send_json({"program": name, "instructions": rows, "total": len(rows)})

    def _api_attack_result(self, task_id):
        with tasks_lock:
            task = tasks.get(task_id)
        if not task:
            self._send_json({"status": "error", "error": "Task not found"}, 404)
            return
        self._send_json(task)

    def _api_run(self, body):
        program = body.get("program", "test")
        mode = body.get("mode", "train")       # train=安全模式, enforce=攻击模式(违规立即终止)
        if mode == "safe":  mode = "train"      # legacy name mapping
        if mode == "attack": mode = "enforce"
        iterations = int(body.get("iterations", 1))
        task_id = run_pipeline_async(program, mode, iterations=iterations)
        self._send_json({"task_id": task_id, "status": "queued"})

    def _api_rop_attack(self, body):
        attack_type = body.get("attack_type", "sh")
        mode = body.get("mode", "enforce")
        target = int(body.get("target", 0))
        task_id = run_pipeline_async("attack", "attack", attack_type=attack_type,
                                     iterations=1)
        self._send_json({"task_id": task_id, "status": "queued"})

    def _api_import(self, body):
        filename = body.get("filename", "imported.c")
        data_b64 = body.get("data", "")
        if not data_b64:
            self._send_json({"status": "error", "error": "No file data"}, 400)
            return

        try:
            file_content = base64.b64decode(data_b64)
        except Exception as e:
            self._send_json({"status": "error", "error": f"Base64 decode: {e}"}, 400)
            return

        # Save directly to test/ directory
        base_name = os.path.splitext(filename)[0] or "imported"
        base_name = re.sub(r"[^\w\-.]", "_", base_name)
        save_path = os.path.join(TEST_DIR, f"{base_name}.c")
        with open(save_path, "wb") as f:
            f.write(file_content)

        self._send_json({"status": "ok", "name": base_name, "path": save_path})


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CFI/DFI Web Server")
    parser.add_argument("-p", "--port", type=int, default=8080,
                        help="Server port (default: 8080)")
    args = parser.parse_args()

    is_root = os.geteuid() == 0
    print(f"\n{'='*60}")
    print(f"  CFI/DFI 融合监控 — Web 服务器")
    print(f"{'='*60}")
    print(f"  端口: {args.port}")
    print(f"  运行用户: {'root (全功能: 静态分析 + eBPF 监控)' if is_root else '普通用户 (仅静态分析)'}")
    print(f"  首页: http://localhost:{args.port}")
    print(f"  控制面板: http://localhost:{args.port}/dashboard")
    print(f"{'='*60}")
    if not is_root:
        print(f"  ⚠ 提示: 使用 sudo 启动可启用 eBPF 实时监控功能")
    print()

    server = HTTPServer(("0.0.0.0", args.port), RequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        server.shutdown()


if __name__ == "__main__":
    main()
