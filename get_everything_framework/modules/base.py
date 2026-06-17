"""
工具运行器基类模块。

提供 BaseRunner 基类，封装了所有扫描器运行器的通用功能，
包括命令行解析、子进程执行、结果文件读写、临时输入文件创建等。
子类只需实现 run_scan() 方法即可集成新的安全扫描工具。
"""

import hashlib
import os
import shutil
import subprocess
import tempfile

from config import OUTPUT_DIR


class BaseRunner:
    """
    扫描器运行器基类。

    封装了外部安全工具调用的通用流程：
    - 命令行解析与可执行文件定位（_resolve_command）
    - 子进程执行与错误处理（_execute / _execute_stdout）
    - 结果文件的构建与读取（_build_output_file / _read_results）
    - 临时输入文件的创建（_write_input_file）

    子类需要：
    1. 在 __init__ 中调用 super().__init__(config, tool_name) 传入工具配置
    2. 实现 run_scan(domain) 方法，定义具体的扫描逻辑
    """

    def __init__(self, config, tool_name):
        """
        初始化运行器。

        Args:
            config: 工具配置字典，包含 path、category、timeout 等参数
            tool_name: 工具名称字符串，用于标识和输出文件命名
        """
        self.config = config
        self.output_dir = OUTPUT_DIR
        self.tool_name = tool_name
        self.category = config.get("category", "subdomain")

    def _build_output_file(self, domain):
        """
        根据域名构建输出文件路径。

        使用域名的 MD5 哈希前缀 + 工具名作为文件名，
        避免特殊字符导致文件系统问题。

        Args:
            domain: 目标域名字符串

        Returns:
            输出文件的完整路径
        """
        safe = hashlib.md5(domain.encode("utf-8")).hexdigest()[:12]
        return os.path.join(self.output_dir, f"{safe}_{self.tool_name}.txt")

    def _read_results(self, output_file):
        """
        从输出文件中读取扫描结果。

        返回去重后的非空行列表。如果文件不存在则返回空列表。

        Args:
            output_file: 输出文件路径

        Returns:
            字符串列表，每行为一条结果
        """
        if not os.path.exists(output_file):
            return []

        with open(output_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _resolve_command(self, cmd):
        """
        解析并规范化命令行参数。

        处理以下场景：
        - 相对路径：通过 PATH 环境变量查找可执行文件
        - 绝对路径：直接使用
        - Windows .bat/.cmd 文件：通过 ComSpec (cmd.exe) 调用

        Args:
            cmd: 命令行参数列表，cmd[0] 为可执行文件路径

        Returns:
            解析后的完整命令行参数列表

        Raises:
            FileNotFoundError: 如果无法找到可执行文件
        """
        executable = cmd[0]
        resolved = shutil.which(executable) if not os.path.isabs(executable) else executable
        if not resolved:
            raise FileNotFoundError(executable)

        if resolved.lower().endswith((".cmd", ".bat")):
            comspec = os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe")
            return [comspec, "/c", resolved] + cmd[1:]

        return [resolved] + cmd[1:]

    def _execute(self, cmd, domain):
        """
        执行命令行工具并将输出写入文件（工具自身通过 -o 参数输出到文件）。

        适用于支持 -o 输出文件参数的工具（如 subfinder、naabu 等）。

        Args:
            cmd: 完整的命令行参数列表
            domain: 目标域名（用于日志输出）

        Returns:
            True 表示执行成功，False 表示执行失败
        """
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
        """
        执行命令行工具并将标准输出重定向到文件。

        适用于不支持 -o 参数、结果输出到 stdout 的工具（如 assetfinder、oneforall）。

        Args:
            cmd: 完整的命令行参数列表
            domain: 目标域名（用于日志输出）
            output_file: 结果输出文件路径

        Returns:
            True 表示执行成功，False 表示执行失败
        """
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
        """
        创建临时输入文件并写入数据。

        用于将子域名候选列表写入临时文件，供工具通过 -l 参数读取。
        调用方负责在使用后删除临时文件。

        Args:
            domain: 目标域名（用于文件名标识）
            values: 要写入的字符串列表
            suffix: 自定义文件名后缀，默认使用域名和工具名生成

        Returns:
            临时文件的完整路径
        """
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
