#!/usr/bin/env python3
"""
RIPE Tester for test.so - 自动化攻击矩阵测试
基于 RIPE/ripe_tester.py 的完整移植，针对 test.so 的间接调用/跳转站点
"""
import os
import sys
import subprocess
import tempfile
import shutil
import time

ATTACK_EXEC = "./ripe_attack_runner"

ATTACK_TYPES = [
    "nonop", "simplenop", "polynop",
    "createfile", "returnintolibc", "rop"
]

CODE_PTRS = [
    "ret", "baseptr",
    "funcptrstackvar", "funcptrstackparam",
    "funcptrheap", "funcptrbss", "funcptrdata",
    "longjmpstackvar", "longjmpstackparam",
    "longjmpheap", "longjmpbss", "longjmpdata",
]

FUNCTIONS = [
    "memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
    "strcat", "strncat", "sscanf", "fscanf", "homebrew"
]

LOCATIONS = ["stack", "heap", "bss", "data"]

TARGET_SITES = [
    {"id": 0, "offset": "0x11d4", "name": "test_indirect_call",   "var": "indirect_call_ptr"},
    {"id": 1, "offset": "0x121b", "name": "test_indirect_jump",   "var": None},
    {"id": 2, "offset": "0x124a", "name": "test_ff_instructions", "var": None},
    {"id": 3, "offset": "0x1260", "name": "test_ff_instructions", "var": None},
    {"id": 4, "offset": "0x10ff", "name": "deregister_tm_clones", "var": None},
    {"id": 5, "offset": "0x1140", "name": "register_tm_clones",   "var": None},
]


def compile_runner():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(script_dir, "ripe_attack_runner.c")
    out = os.path.join(script_dir, "ripe_attack_runner")
    cmd = ["gcc", "-fno-stack-protector", "-no-pie", "-z", "execstack",
           "-ldl", src, "-o", out]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Compilation failed:\n{result.stderr}")
        sys.exit(1)
    print("[*] Compiled ripe_attack_runner successfully")


def run_attack(technique, target_id, attack_type, code_ptr, location, func):
    os.system("rm -f /tmp/ripe_log /tmp/rip-eval/f_xxxx")
    os.makedirs("/tmp/rip-eval", exist_ok=True)

    cmdline = (
        f"{ATTACK_EXEC} -t {technique} -s {target_id} "
        f"-i {attack_type} -c {code_ptr} -l {location} -f {func}"
    )
    try:
        result = subprocess.run(cmdline.split(), capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return "FAIL", cmdline + " (timeout)"

    log_content = result.stdout + result.stderr
    try:
        with open("/tmp/ripe_log", "w") as lf:
            lf.write(log_content)
    except Exception:
        pass

    if "IMPOSSIBLE" in log_content or "NOT_POSSIBLE" in log_content:
        return "NP", cmdline

    file_created = os.path.exists("/tmp/rip-eval/f_xxxx")
    attack_reported = "ATTACK_SUCCESS" in log_content

    if file_created:
        os.system("rm -f /tmp/rip-eval/f_xxxx")

    if file_created or attack_reported:
        return "OK", cmdline
    return "FAIL", cmdline


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} [direct|indirect|both] <repeat>")
        sys.exit(1)

    if sys.argv[1] == "both":
        techniques = ["direct", "indirect"]
    else:
        techniques = [sys.argv[1]]

    repeat_times = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    compile_runner()
    os.makedirs("/tmp/rip-eval", exist_ok=True)

    total_ok = 0
    total_fail = 0
    total_some = 0
    total_np = 0
    total_attacks = 0

    for target in TARGET_SITES:
        for attack_type in ATTACK_TYPES:
            for tech in techniques:
                for loc in LOCATIONS:
                    for ptr in CODE_PTRS:
                        for func in FUNCTIONS:
                            s_attempts = 0
                            attack_possible = True

                            for i in range(repeat_times):
                                try:
                                    result, cmd = run_attack(
                                        tech, target["id"], attack_type,
                                        ptr, loc, func
                                    )
                                except subprocess.TimeoutExpired:
                                    result, cmd = "FAIL", "timeout"

                                if result == "NP":
                                    attack_possible = False
                                    break
                                elif result == "OK":
                                    s_attempts += 1

                            if not attack_possible:
                                total_np += 1
                                print(f"{cmd}\t\tNOT POSSIBLE")
                                continue

                            if s_attempts == repeat_times:
                                total_ok += 1
                                print(f"{cmd}\t\tOK\t{s_attempts}/{repeat_times}")
                            elif s_attempts == 0:
                                total_fail += 1
                                print(f"{cmd}\t\tFAIL\t{s_attempts}/{repeat_times}")
                            else:
                                total_some += 1
                                print(f"{cmd}\t\tSOMETIMES\t{s_attempts}/{repeat_times}")

                            total_attacks += 1

    total = total_ok + total_some + total_fail + total_np
    print(f"\n||Summary|| OK: {total_ok} ,SOME: {total_some} ,FAIL: {total_fail}, "
          f"NP: {total_np} ,Total Attacks: {total}")


if __name__ == "__main__":
    main()
