import os
import shutil
import subprocess
import tempfile

from config import OUTPUT_DIR


class BaseRunner:
    def __init__(self, config, tool_name):
        self.config = config
        self.output_dir = OUTPUT_DIR
        self.tool_name = tool_name
        self.category = config.get("category", "subdomain")

    def _build_output_file(self, domain):
        return os.path.join(self.output_dir, f"{domain}_{self.tool_name}.txt")

    def _read_results(self, output_file):
        if not os.path.exists(output_file):
            return []

        with open(output_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _resolve_command(self, cmd):
        executable = cmd[0]
        resolved = shutil.which(executable) if not os.path.isabs(executable) else executable
        if not resolved:
            raise FileNotFoundError(executable)

        if resolved.lower().endswith((".cmd", ".bat")):
            comspec = os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe")
            return [comspec, "/c", resolved] + cmd[1:]

        return [resolved] + cmd[1:]

    def _execute(self, cmd, domain):
        try:
            print(f"[*] 正在使用 {self.tool_name} 扫描域名: {domain} ...")
            run_cmd = self._resolve_command(cmd)
            subprocess.run(
                run_cmd,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.config.get("process_timeout"),
            )
            return True
        except FileNotFoundError:
            print(f"[!] 未找到工具 {self.config['path']}，请先安装并加入环境变量")
            return False
        except subprocess.TimeoutExpired:
            print(f"[!] {domain} 扫描超时，已停止 {self.tool_name} 任务")
            return False
        except subprocess.CalledProcessError as e:
            error_msg = (e.stderr or e.stdout or str(e)).strip()
            print(f"[!] {domain} 扫描失败: {error_msg}")
            return False

    def _execute_stdout(self, cmd, domain, output_file):
        try:
            print(f"[*] 正在使用 {self.tool_name} 扫描目标: {domain} ...")
            run_cmd = self._resolve_command(cmd)
            completed = subprocess.run(
                run_cmd,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.config.get("process_timeout"),
            )
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(completed.stdout or "")
            return True
        except FileNotFoundError:
            print(f"[!] 未找到工具 {self.config['path']}，请先安装并加入环境变量")
            return False
        except subprocess.TimeoutExpired:
            print(f"[!] {domain} 扫描超时，已停止 {self.tool_name} 任务")
            return False
        except subprocess.CalledProcessError as e:
            error_msg = (e.stderr or e.stdout or str(e)).strip()
            print(f"[!] {domain} 扫描失败: {error_msg}")
            return False

    def _write_input_file(self, domain, values, suffix=None):
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=suffix or f"_{domain}_{self.tool_name}_input.txt",
            dir=OUTPUT_DIR,
            delete=False,
        )
        try:
            temp_file.write("\n".join(values))
            temp_file.write("\n")
        finally:
            temp_file.close()
        return temp_file.name
