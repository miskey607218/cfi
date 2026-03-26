import gradio as gr
import pandas as pd
import subprocess
import os
import shutil
import sys
import threading
import queue
import html

# 解析命令行参数获取默认模块名
DEFAULT_MODULE = sys.argv[1] if len(sys.argv) > 1 else "e1000"

# 项目基础路径
BASE_DIR = "./data"
os.makedirs(BASE_DIR, exist_ok=True)

# 全局变量
output_queue = queue.Queue()
current_process = None
process_thread = None

# ========== 核心处理函数 ==========
def read_jump_analysis_csv(module_name):
    """读取模块的跳转分析CSV文件"""
    csv_path = os.path.join(BASE_DIR, f"csv/{module_name}_jump_analysis.csv")
    df = pd.read_csv(csv_path)
    return df

def read_disassembly_txt(module_name):
    """读取模块的反汇编TXT文件"""
    txt_path = os.path.join(BASE_DIR, f"txt/{module_name}_disassembly.txt")
    with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return content[:5000]

def stream_reader(pipe, queue, prefix=""):
    """从管道读取数据并放入队列"""
    for line in iter(pipe.readline, ''):
        if line:
            print(f"{prefix}{line}", end='')
            queue.put(line)
    pipe.close()

def run_cfi_analysis_thread(mount_mode: str, module_name: str):
    """在后台线程中运行CFI分析脚本（run_cfi.sh）"""
    global current_process, output_queue
    
    # 清空队列
    while not output_queue.empty():
        try:
            output_queue.get_nowait()
        except queue.Empty:
            break
    
    # 检查run_cfi.sh
    sh_path = "run_cfi.sh"
    if not os.path.exists(sh_path):
        sh_path = os.path.join(BASE_DIR, "sh/run_cfi.sh")
        if not os.path.exists(sh_path):
            output_queue.put(f"错误：未找到run_cfi.sh文件（查找路径：{sh_path}）\n")
            return
    
    # 检查KO文件是否存在
    ko_path = os.path.join(BASE_DIR, f"ko/{module_name}.ko")
    if not os.path.exists(ko_path):
        output_queue.put(f"错误：未找到{module_name}.ko文件（路径：{ko_path}）\n")
        output_queue.put("请先上传对应模块后再运行分析\n")
        return
    
    # 构建输出信息
    output_queue.put(f"=== CFI分析程序执行日志 ===\n")
    output_queue.put(f"时间：{pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    output_queue.put(f"模块名：{module_name}\n")
    output_queue.put(f"挂载模式：{mount_mode}\n")
    output_queue.put(f"KO文件路径：{ko_path}\n")
    output_queue.put(f"执行脚本：{sh_path}\n")
    output_queue.put("=" * 50 + "\n\n")
    
    # 运行run_cfi.sh - 传入模块名和挂载模式
    current_process = subprocess.Popen(
        ["sudo", "bash", sh_path, module_name, mount_mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
        env=os.environ.copy()
    )
    
    # 创建线程读取输出
    stdout_thread = threading.Thread(target=stream_reader, args=(current_process.stdout, output_queue, ""))
    stderr_thread = threading.Thread(target=stream_reader, args=(current_process.stderr, output_queue, "[ERROR] "))
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()
    
    # 等待进程完成（超时10分钟）
    return_code = current_process.wait(timeout=600)
    
    # 等待输出线程完成
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    
    output_queue.put("\n" + "=" * 50 + "\n")
    output_queue.put(f"执行完成，返回码：{return_code}\n")
    if return_code == 0:
        output_queue.put("✅ 分析成功！已生成CSV/TXT结果文件\n")
    else:
        output_queue.put("❌ 程序执行出错，请检查上面的错误信息\n")
    
    current_process = None

def start_cfi_analysis(mount_mode: str, module_name: str):
    """启动CFI分析（非阻塞）"""
    global process_thread, current_process
    
    if current_process and current_process.poll() is None:
        return "已有分析进程在运行，请先停止"
    
    process_thread = threading.Thread(target=run_cfi_analysis_thread, args=(mount_mode, module_name))
    process_thread.daemon = True
    process_thread.start()
    
    return f"CFI分析已启动，模块：{module_name}，挂载模式：{mount_mode}"

def stop_cfi_analysis():
    """停止CFI分析"""
    global current_process
    if current_process and current_process.poll() is None:
        current_process.terminate()
        try:
            current_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            current_process.kill()
        current_process = None
        return "CFI分析已停止"
    return "没有正在运行的分析进程"

def get_cfi_output():
    """获取CFI分析的输出"""
    lines = []
    try:
        while not output_queue.empty():
            line = output_queue.get_nowait()
            lines.append(html.escape(line))
    except queue.Empty:
        pass
    
    if lines:
        formatted = "<br>".join(lines)
        return f"<div class='output-box'>{formatted}</div>"
    return "<div class='output-box'>⚡ 等待启动分析...</div>"

def check_process_status():
    """检查进程状态"""
    if current_process and current_process.poll() is None:
        return "运行中"
    elif current_process:
        return f"已结束 (返回码: {current_process.returncode})"
    return "就绪"

def upload_ko_file(file_obj, module_name):
    """上传KO模块文件"""
    if file_obj is None:
        return f"未上传文件，模块名：{module_name}"
    
    target_path = os.path.join(BASE_DIR, f"ko/{module_name}.ko")
    shutil.copy(file_obj.name, target_path)
    os.chmod(target_path, 0o644)
    return f"✅ KO模块上传成功！保存路径：{target_path}"

def get_file_status(module_name):
    """获取当前核心文件状态"""
    return {
        f"{module_name}.ko": os.path.exists(os.path.join(BASE_DIR, f"ko/{module_name}.ko")),
        "run_cfi.sh": os.path.exists("run_cfi.sh") or os.path.exists(os.path.join(BASE_DIR, "sh/run_cfi.sh")),
        f"{module_name}_jump_analysis.csv": os.path.exists(os.path.join(BASE_DIR, f"csv/{module_name}_jump_analysis.csv")),
        f"{module_name}_disassembly.txt": os.path.exists(os.path.join(BASE_DIR, f"txt/{module_name}_disassembly.txt"))
    }

# ========== 构建前端界面 ==========
with gr.Blocks(
    title="CFI分析工具（内核模块）",
    theme=gr.themes.Monochrome(primary_hue="blue"),
    css="""
    .gr-button-primary {background-color: #2563eb;}
    .result-box {height: 400px; overflow-y: auto;}
    .output-box {
        height: 500px;
        overflow-y: auto;
        background-color: #1e1e1e;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        padding: 15px;
        border-radius: 5px;
        white-space: pre-wrap;
        word-wrap: break-word;
        font-size: 14px;
        line-height: 1.4;
    }
    .control-panel {
        background-color: #f5f5f5;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 15px;
    }
    .status-running { color: #00aa00; font-weight: bold; }
    .status-stopped { color: #aa0000; font-weight: bold; }
    """
) as demo:
    # 页面标题与说明
    gr.Markdown(f"""
    # CFI分析工具（内核模块）
    支持任意内核模块（如 e1000），通过 run_cfi.sh 自动完成分析。
    """)
    
    # 模块名称输入与上传
    with gr.Tab("文件管理"):
        gr.Markdown("### 选择模块并上传KO文件")
        module_input = gr.Textbox(
            label="模块名",
            value=DEFAULT_MODULE,
            placeholder="例如 e1000, nf_conntrack_netlink",
            info="模块名将用于文件命名和路径"
        )
        with gr.Row():
            ko_upload = gr.File(label="📌 上传 .ko 文件", file_types=[".ko"])
            ko_upload_btn = gr.Button("上传", variant="primary", size="lg")
        ko_upload_msg = gr.Textbox(label="上传结果", interactive=False)
        
        ko_upload_btn.click(
            fn=upload_ko_file,
            inputs=[ko_upload, module_input],
            outputs=ko_upload_msg
        )
    
    # 第二区域：CFI配置与运行
    with gr.Tab("CFI分析运行"):
        gr.Markdown("### CFI分析配置与实时监控")
        
        with gr.Row(elem_classes="control-panel"):
            with gr.Column(scale=1):
                mount_mode = gr.Radio(
                    label="CFI挂载位置",
                    choices=["函数入口", "跳转指令处"],
                    value="函数入口",
                    info="选择CFI检测点的挂载位置"
                )
            with gr.Column(scale=1):
                with gr.Row():
                    start_btn = gr.Button("🚀 启动分析", variant="primary", size="lg")
                    stop_btn = gr.Button("🛑 停止分析", variant="stop", size="lg")
                status = gr.Textbox(label="运行状态", value="就绪", interactive=False)
        
        gr.Markdown("#### 实时控制台输出")
        output_display = gr.HTML(
            value="<div class='output-box'>⚡ 等待启动分析...</div>",
            label="实时输出"
        )
        
        with gr.Row():
            refresh_btn = gr.Button("🔄 刷新输出", variant="secondary", size="sm")
            clear_btn = gr.Button("🗑️ 清空输出", variant="secondary", size="sm")
            check_status_btn = gr.Button("📊 检查状态", variant="secondary", size="sm")
        
        with gr.Row():
            file_status = gr.JSON(label="核心文件状态", value={})
        
        # 事件绑定
        start_btn.click(
            fn=start_cfi_analysis,
            inputs=[mount_mode, module_input],
            outputs=[status]
        )
        stop_btn.click(
            fn=stop_cfi_analysis,
            inputs=[],
            outputs=[status]
        )
        refresh_btn.click(
            fn=get_cfi_output,
            inputs=[],
            outputs=[output_display]
        )
        clear_btn.click(
            fn=lambda: "<div class='output-box'>输出已清空</div>",
            inputs=[],
            outputs=[output_display]
        )
        check_status_btn.click(
            fn=check_process_status,
            inputs=[],
            outputs=[status]
        )
        
        # 刷新文件状态
        gr.Button("🔍 刷新文件状态").click(
            fn=get_file_status,
            inputs=[module_input],
            outputs=[file_status]
        )
    
    # 第三区域：结果查看
    with gr.Tab("结果查看"):
        with gr.Row():
            with gr.Column(scale=1):
                csv_refresh_btn = gr.Button("刷新CSV数据", variant="secondary")
                csv_table = gr.Dataframe(
                    label="跳转分析CSV",
                    elem_classes="result-box"
                )
            with gr.Column(scale=1):
                txt_refresh_btn = gr.Button("刷新反汇编内容", variant="secondary")
                txt_content = gr.Textbox(
                    label="反汇编内容（前5000字符）",
                    lines=20,
                    max_lines=30,
                    elem_classes="result-box",
                    interactive=False
                )
        
        csv_refresh_btn.click(
            fn=read_jump_analysis_csv,
            inputs=[module_input],
            outputs=csv_table
        )
        txt_refresh_btn.click(
            fn=read_disassembly_txt,
            inputs=[module_input],
            outputs=txt_content
        )
    
    # 初始化加载数据（基于默认模块）
    demo.load(
        fn=lambda: (read_jump_analysis_csv(DEFAULT_MODULE), read_disassembly_txt(DEFAULT_MODULE)),
        inputs=[],
        outputs=[csv_table, txt_content]
    )

# ========== 启动应用 ==========
if __name__ == "__main__":
    print("=" * 60)
    print(f"启动CFI分析工具，默认模块: {DEFAULT_MODULE}")
    print(f"当前工作目录: {os.getcwd()}")
    print(f"BASE_DIR: {BASE_DIR}")
    print("=" * 60)
    
    # 检查必要文件
    sh_path = "run_cfi.sh" if os.path.exists("run_cfi.sh") else os.path.join(BASE_DIR, "sh/run_cfi.sh")
    if not os.path.exists(sh_path):
        print(f"⚠️ 警告: 未找到 run_cfi.sh（查找路径：{sh_path}）")
    else:
        print(f"✅ 找到 run_cfi.sh: {sh_path}")
    
    ko_path = os.path.join(BASE_DIR, f"ko/{DEFAULT_MODULE}.ko")
    if not os.path.exists(ko_path):
        print(f"⚠️ 警告: 未找到 {DEFAULT_MODULE}.ko（路径：{ko_path}），请先上传")
    else:
        print(f"✅ 找到 {DEFAULT_MODULE}.ko: {ko_path}")
    
    print("\n🌐 访问地址: http://localhost:7860")
    print("=" * 60)
    
    demo.launch(
        server_port=7860,
        share=False,
        server_name="0.0.0.0",
        quiet=True
    )