#include <uapi/linux/ptrace.h>

struct cfi_entry {
    u64 src_addr;
    u64 src_func_addr;
    u64 dst_addr;
    u8 jump_type;
    u8 is_indirect;
    char src_func[64];
    char dst_func[64];
    u8 opcode;
};

struct jump_event {
    u64 src_offset;
    u64 dst_offset;
    u64 expected_dst;
    u8 jump_type;
    u8 is_indirect;
    u8 is_correct;
    char src_func[64];
    char dst_func[64];
    u64 src_addr;
    u64 src_func_addr;
    u64 cfi_dst_addr;
    u64 timestamp_ns;
    u32 cpu;
    u32 pid;
    u64 reg_rax;
    u64 reg_rcx;
    u64 reg_rdx;
    u64 reg_rbx;
    u64 reg_rsp;
    u64 reg_rbp;
    u64 reg_rsi;
    u64 reg_rdi;
    u8 insn_bytes[16];
    u64 real_target;
    u8 insn_len;
    u64 runtime_ip;
    u64 module_base_addr;
    u64 ret_addr;
    u64 saved_rax_val;           // 新增
    u64 saved_rsp_val;           // 新增
    u64 call_stack_hash;         // 调用栈哈希 (Call-Site Sensitivity)
    u64 ptr_origin;              // 函数指针起源指令偏移 (Origin Sensitivity)
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(saved_rax, u32, u64); // key = pid, value = rax
BPF_HASH(saved_rsp, u64, u64); // key = (pid<<32)|depth, value = saved return address
BPF_HASH(ret_depth, u32, u32); // key = pid, value = current call depth

// ---- Call-Site Sensitivity & Origin Sensitivity ----
BPF_HASH(ptr_origin_map, u64, u64);      // key=func_ptr_addr, value=origin_instr_offset
BPF_HASH(call_stack_hash_map, u32, u64); // key=pid, value=rolling call stack hash

// ===== Three-Layer DFI Protection =====
struct dfi_layer_meta {
    u32 site_id;
    u32 reg_sel;   // 0=rax,1=rcx,2=rdx,3=rbx,5=rbp,6=rsi,7=rdi,8=r8,9=r9
    u32 instr_type; // 0=direct, 1=deref, 2=rip_rel, 3=rbp_rel
    s32 extra;      // displacement for rip_rel / rbp_rel
    u32 instr_len;  // instruction length (for rip_rel addr calc)
    u32 need_deref; // for type 2/3: 1=double-deref needed, 0=value IS target
    u32 save_target_to_saved_rax; // 1=this is the "first read from data segment" layer: store computed target into saved_rax map
    u32 save_target_to_saved_rsp; // L2: 1=store computed target into saved_rsp map
    char func_name[64];
};

struct dfi_layer_event_t {
    u32 site_id;
    u32 layer;
    u64 reg_value;
    u64 target_addr;
    u64 inst_offset;
    u64 timestamp;
    u32 pid;
    u32 cpu;
    char func_name[64];
};

BPF_HASH(dfi_l1_cfg, u64, struct dfi_layer_meta);
BPF_HASH(dfi_l2_cfg, u64, struct dfi_layer_meta);
BPF_HASH(dfi_l3_cfg, u64, struct dfi_layer_meta);
BPF_HASH(dfi_layer_vals, u64, u64);
BPF_PERF_OUTPUT(dfi_layer_events);

// ---- unified layer probe: uses bpf_probe_read for ALL register/memory reads ----
static inline int dfi_do_probe(struct pt_regs *ctx, u32 layer,
                                struct dfi_layer_meta *meta, u64 offset) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ip = PT_REGS_IP(ctx);
    u64 reg_val = 0;
    u64 target = 0;

    switch (meta->instr_type) {
    case 0: // DIRECT: call/jmp *%reg  → reg_val IS the target
        {
            u64 tmp = 0;
            if (meta->reg_sel == 0) bpf_probe_read(&tmp, sizeof(tmp), &ctx->ax);
            else if (meta->reg_sel == 1) bpf_probe_read(&tmp, sizeof(tmp), &ctx->cx);
            else if (meta->reg_sel == 2) bpf_probe_read(&tmp, sizeof(tmp), &ctx->dx);
            else if (meta->reg_sel == 3) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bx);
            else if (meta->reg_sel == 4) bpf_probe_read(&tmp, sizeof(tmp), &ctx->sp);
            else if (meta->reg_sel == 5) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bp);
            else if (meta->reg_sel == 6) bpf_probe_read(&tmp, sizeof(tmp), &ctx->si);
            else if (meta->reg_sel == 7) bpf_probe_read(&tmp, sizeof(tmp), &ctx->di);
            else if (meta->reg_sel == 8) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r8);
            else if (meta->reg_sel == 9) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r9);
            reg_val = tmp;
            target = tmp;
        }
        break;

    case 1: // DEREF: mov (%reg),%reg → reg holds the pointer, *(reg) is target
        {
            u64 tmp = 0;
            if (meta->reg_sel == 0) bpf_probe_read(&tmp, sizeof(tmp), &ctx->ax);
            else if (meta->reg_sel == 1) bpf_probe_read(&tmp, sizeof(tmp), &ctx->cx);
            else if (meta->reg_sel == 2) bpf_probe_read(&tmp, sizeof(tmp), &ctx->dx);
            else if (meta->reg_sel == 3) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bx);
            else if (meta->reg_sel == 4) bpf_probe_read(&tmp, sizeof(tmp), &ctx->sp);
            else if (meta->reg_sel == 5) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bp);
            else if (meta->reg_sel == 6) bpf_probe_read(&tmp, sizeof(tmp), &ctx->si);
            else if (meta->reg_sel == 7) bpf_probe_read(&tmp, sizeof(tmp), &ctx->di);
            else if (meta->reg_sel == 8) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r8);
            else if (meta->reg_sel == 9) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r9);
            reg_val = tmp;
            if (reg_val != 0)
                bpf_probe_read_user(&target, sizeof(target), (void *)reg_val);
        }
        break;

    case 2: // RIP_REL: mov DISP(%rip),%reg → read ptr from ip+len+disp (memory)
        {
            u64 ptr_addr = ip + meta->instr_len + (s64)meta->extra;
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)ptr_addr) == 0) {
                if (reg_val != 0 && meta->need_deref)
                    bpf_probe_read_user(&target, sizeof(target), (void *)reg_val);
                else
                    target = reg_val;
            }
        }
        break;

    case 3: // RBP_REL: mov DISP(%rbp),%reg → read ptr from rbp+disp (memory)
        {
            u64 rbp_val = 0;
            bpf_probe_read(&rbp_val, sizeof(rbp_val), &ctx->bp);
            u64 ptr_addr = rbp_val + (s64)meta->extra;
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)ptr_addr) == 0) {
                if (reg_val != 0 && meta->need_deref)
                    bpf_probe_read_user(&target, sizeof(target), (void *)reg_val);
                else
                    target = reg_val;
            }
        }
        break;

    case 4: // RET: target = *(rsp) — return address on stack
        {
            u64 rsp_val = 0;
            bpf_probe_read(&rsp_val, sizeof(rsp_val), &ctx->sp);
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)rsp_val) == 0) {
                target = reg_val;  // return address IS the target
            }
        }
        break;
    }

    u64 key = ((u64)pid << 32) | ((u64)meta->site_id << 8) | layer;
    dfi_layer_vals.update(&key, &reg_val);

    // 在"首次从数据段/栈内存读取"的那一层（由 Python 端按 instr_type 选定并标记在
    // save_target_to_saved_rax 上）把计算出的正确目标存入 saved_rax，
    // 供 trace_all_jumps 在真正发生间接跳转时校验。注意这里不再硬编码 layer == 2,
    // 具体保存在哪一层由调用点的 meta 决定（哪一层先从内存读出指针，就在哪一层存）。
    if (meta->save_target_to_saved_rax && target != 0) {
        saved_rax.update(&pid, &target);
    }

    struct dfi_layer_event_t evt = {};
    evt.site_id = meta->site_id;
    evt.layer = layer;
    evt.reg_value = reg_val;
    evt.target_addr = target;
    evt.inst_offset = offset;
    evt.timestamp = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.cpu = bpf_get_smp_processor_id();
    bpf_probe_read(evt.func_name, sizeof(evt.func_name), meta->func_name);
    dfi_layer_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_ret_target(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 获取并递增当前 PID 的调用深度
    u32 *dp = ret_depth.lookup(&pid);
    u32 depth = dp ? (*dp + 1) : 1;
    ret_depth.update(&pid, &depth);

    // 读取函数入口处 *(rsp) = 返回地址（这是 ret 目标"第一次出现"的位置：函数刚被
    // call 进入时，返回地址就已经被压在栈顶，因此在函数开头存一次即可）
    u64 rsp;
    bpf_probe_read(&rsp, sizeof(rsp), &ctx->sp);
    u64 ret_addr = 0;
    if (bpf_probe_read_user(&ret_addr, sizeof(ret_addr), (void *)rsp) != 0) {
        bpf_send_signal(9);
        return 0;
    }

    // 存入 saved_rsp，key = (pid<<32) | depth
    u64 key = ((u64)pid << 32) | depth;
    saved_rsp.update(&key, &ret_addr);

    // Update rolling call stack hash for Call-Site Sensitivity
    // hash = old_hash * 1103515245 + ret_addr (truncated to 16-bit for mix)
    u64 *old_hash = call_stack_hash_map.lookup(&pid);
    u64 new_hash = old_hash ? (*old_hash * 1103515245 + (ret_addr & 0xFFFF)) : ret_addr;
    call_stack_hash_map.update(&pid, &new_hash);

    return 0;
}

int trace_df1_l1(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 offset = ip - *bp;
    struct dfi_layer_meta *meta = dfi_l1_cfg.lookup(&offset);
    if (!meta) return 0;
    return dfi_do_probe(ctx, 1, meta, offset);
}

int trace_df1_l2(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 offset = ip - *bp;
    struct dfi_layer_meta *meta = dfi_l2_cfg.lookup(&offset);
    if (!meta) return 0;
    return dfi_do_probe(ctx, 2, meta, offset);
}

int trace_df1_l3(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 offset = ip - *bp;
    struct dfi_layer_meta *meta = dfi_l3_cfg.lookup(&offset);
    if (!meta) return 0;
    return dfi_do_probe(ctx, 3, meta, offset);
}

int trace_ptr_store(struct pt_regs *ctx) {
    // Origin Sensitivity: record function pointer assignment
    // Attach to store instructions like mov [rax], rbx or mov %rax, -0x8(%rbp)
    // Records: func_ptr_addr -> origin_instr_offset
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 origin_offset = ip - *bp;

    // Read the destination address (ptr being written to) from rbx (or other src reg)
    // For simplicity, use rbx as the "pointer being stored" address
    u64 ptr_addr = 0;
    bpf_probe_read(&ptr_addr, sizeof(ptr_addr), &ctx->bx);

    // Read the value being stored (the function address) from rax
    u64 func_val = 0;
    bpf_probe_read(&func_val, sizeof(func_val), &ctx->ax);

    if (ptr_addr != 0 && func_val != 0) {
        // Store origin: pointer_address -> instruction offset where assigned
        ptr_origin_map.update(&ptr_addr, &origin_offset);
    }

    return 0;
}

int trace_all_jumps(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *base_ptr = module_base.lookup(&key);
    if (!base_ptr) return 0;
    u64 base = *base_ptr;

    u64 ip = PT_REGS_IP(ctx);
    if (ip < base) return 0;

    u64 offset = ip - base;

    struct cfi_entry *entry = cfi_map.lookup(&offset);
    if (!entry) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct jump_event event = {};
    event.runtime_ip = ip;
    event.module_base_addr = base;
    event.src_offset = offset;
    event.src_addr = entry->src_addr;
    event.cfi_dst_addr = entry->dst_addr;
    event.jump_type = entry->jump_type;
    event.is_indirect = entry->is_indirect;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.cpu = bpf_get_smp_processor_id();
    event.pid = pid;
    bpf_probe_read(&event.reg_rax, sizeof(event.reg_rax), &ctx->ax);
    bpf_probe_read(&event.reg_rcx, sizeof(event.reg_rcx), &ctx->cx);
    bpf_probe_read(&event.reg_rdx, sizeof(event.reg_rdx), &ctx->dx);
    bpf_probe_read(&event.reg_rbx, sizeof(event.reg_rbx), &ctx->bx);
    bpf_probe_read(&event.reg_rsp, sizeof(event.reg_rsp), &ctx->sp);
    bpf_probe_read(&event.reg_rbp, sizeof(event.reg_rbp), &ctx->bp);
    bpf_probe_read(&event.reg_rsi, sizeof(event.reg_rsi), &ctx->si);
    bpf_probe_read(&event.reg_rdi, sizeof(event.reg_rdi), &ctx->di);

    bpf_probe_read(event.insn_bytes, 16, (void*)ip);
    bpf_probe_read(event.src_func, 64, entry->src_func);
    bpf_probe_read(event.dst_func, 64, entry->dst_func);

    // ---- Call-Site Sensitivity: pass call stack hash ----
    u64 *csh = call_stack_hash_map.lookup(&pid);
    event.call_stack_hash = csh ? *csh : 0;

    // ---- Origin Sensitivity: check ptr origin ----
    event.ptr_origin = 0;
    if (entry->jump_type == 4 || entry->jump_type == 5) {
        // For indirect call/jump, try to find the origin of the function pointer
        // The function pointer is typically stored at a known location (e.g., indirect_call_ptr)
        // Look up ptr_origin for each of the register values that could be ptr addresses
        u64 *origin_ptr = ptr_origin_map.lookup(&event.reg_rbx);
        if (origin_ptr) {
            event.ptr_origin = *origin_ptr;
        } else {
            origin_ptr = ptr_origin_map.lookup(&event.reg_rax);
            if (origin_ptr) {
                event.ptr_origin = *origin_ptr;
            }
        }
    }

    // 从 saved_rax 中取出记录的 rax 值
    u64 *saved = saved_rax.lookup(&pid);
    if (saved) {
        event.saved_rax_val = *saved;          // 传递到用户态
        if (*saved == event.reg_rax) {
            event.is_correct = 1;
        } else {
            event.is_correct = 0;
        }
    } else {
        event.saved_rax_val = 0;
    }

    if (entry->jump_type == 3) {  // RET
        u64 sp;
        bpf_probe_read(&sp, sizeof(sp), &ctx->sp);
        bpf_probe_read(&event.ret_addr, sizeof(event.ret_addr), (void *)sp);

        u32 *dp = ret_depth.lookup(&pid);
        u32 depth = dp ? *dp : 0;
        u64 rkey = ((u64)pid << 32) | depth;
        u64 *saved = saved_rsp.lookup(&rkey);

        if (saved && *saved != 0) {
            event.saved_rsp_val = *saved;
            if (*saved == event.ret_addr) {
                event.is_correct = 1;
            } else {
                event.is_correct = 0;
            }
        } else {
            event.saved_rsp_val = 0;
        }

        // 递减深度 (出栈)
        if (depth > 0) {
            depth--;
            ret_depth.update(&pid, &depth);
        }

        // On RET, the hash is left as-is — it continues to accumulate over the
        // process lifetime. This still provides useful call-site sensitivity
        // because the hash at any given indirect call site reflects the full
        // call history up to that point. Reversal via multiplication is
        // mathematically incorrect (multiply is not its own inverse mod 2^64).
    }

    jump_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
