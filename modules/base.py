import os
import subprocess

from config import OUTPUT_DIR


class BaseRunner:
    def __init__(self, config, tool_name):
        self.config = config
        self.output_dir = OUTPUT_DIR
        self.tool_name = tool_name

    def _build_output_file(self, domain):
        return os.path.join(self.output_dir, f"{domain}_{self.tool_name}.txt")

    def _read_results(self, output_file):
        if not os.path.exists(output_file):
            return []

        with open(output_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _execute(self, cmd, domain):
        try:
            print(f"[*] 正在使用 {self.tool_name} 扫描域名: {domain} ...")
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.config.get("process_timeout"),
            )
            return True
        except FileNotFoundError:
            print(f"[!] 未找到工具: {self.config['path']}，请先安装并加入环境变量")
            return False
        except subprocess.TimeoutExpired:
            print(f"[!] {domain} 扫描超时，已停止 {self.tool_name} 任务")
            return False
        except subprocess.CalledProcessError as e:
            error_msg = (e.stderr or e.stdout or str(e)).strip()
            print(f"[!] {domain} 扫描失败: {error_msg}")
            return False
