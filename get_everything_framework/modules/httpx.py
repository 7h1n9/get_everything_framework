"""
Httpx HTTP 探测工具运行器。

Httpx 是 ProjectDiscovery 开发的高性能 HTTP 探针工具，
支持同时对大量子域名进行 HTTP/HTTPS 请求探测，
获取响应状态码、页面标题、Web 服务器类型、CDN 信息、
技术栈检测等丰富的 HTTP 响应元数据。
"""

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from config import HTTPX_CONFIG, OUTPUT_DIR
from storage import ScanResultStore

from .base import BaseRunner


class HttpxRunner(BaseRunner):
    """
    Httpx 运行器，对子域名进行 HTTP/HTTPS 存活探测和指纹识别。

    工作流程：
    1. 从 ScanResultStore 或外部传入加载子域名候选列表
    2. 将候选人列表写入临时输入文件
    3. 调用 Httpx 工具进行 HTTP 探测，输出 JSON 格式结果
    4. 解析 JSON 结果，提取 URL、状态码、标题、Web 服务器、技术栈等字段
    5. 清理临时输入文件

    Httpx 输出的是 JSONL 格式（每行一个 JSON 对象），支持以下探测功能：
    - 标题提取 (-title)
    - 状态码记录 (-status-code)
    - Web 服务器识别 (-web-server)
    - CDN 检测 (-cdn)
    - 技术栈检测 (-tech-detect)

    示例配置 (HTTPX_CONFIG):
        {
            "path": "httpx",
            "threads": 50,
            "timeout": 10,
            "silent": True,
            "tech_detect": False,
            "follow_redirects": False,
            "extra_args": [],
            "category": "http"
        }
    """

    def __init__(self):
        """初始化 Httpx 运行器，加载 HTTPX_CONFIG 配置并创建存储实例。"""
        super().__init__(HTTPX_CONFIG, "httpx")
        self.store = ScanResultStore()

    def _load_candidates(self, domain: str) -> List[str]:
        """
        从 ScanResultStore 加载已有子域名候选列表。

        Args:
            domain: 目标域名字符串

        Returns:
            去重后的子域名候选列表
        """
        rows = self.store.get_results_by_domain(domain)
        return list(dict.fromkeys(subdomain for subdomain, _, _ in rows))

    def _write_input_file(self, domain: str, candidates: List[str]) -> str:
        """
        创建 Httpx 临时输入文件。

        将子域名候选列表写入临时文件，供 Httpx 通过 -l 参数批量读取。

        Args:
            domain: 目标域名（用于文件名标识）
            candidates: 子域名候选字符串列表

        Returns:
            临时文件的完整路径
        """
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=f"_{domain}_httpx_input.txt",
            dir=OUTPUT_DIR,
            delete=False,
        )
        try:
            temp_file.write("\n".join(candidates))
            temp_file.write("\n")
        finally:
            temp_file.close()
        return temp_file.name

    def _build_json_output_file(self, domain: str) -> str:
        """
        构建 JSON 格式输出文件路径。

        Httpx 使用 -json 参数输出 JSONL 格式，与文本格式使用不同的输出文件。

        Args:
            domain: 目标域名字符串

        Returns:
            JSON 输出文件的完整路径
        """
        return os.path.join(self.output_dir, f"{domain}_{self.tool_name}.jsonl")

    def _read_json_results(self, output_file: str) -> List[Dict[str, Any]]:
        """
        从 JSONL 文件中解析 Httpx 扫描结果。

        每行是一个 JSON 对象，包含 HTTP 响应的元数据。
        提取以下字段：
        - url: 完整的请求 URL
        - status_code: HTTP 状态码
        - title: 页面标题
        - webserver: Web 服务器类型
        - tech: 检测到的技术栈列表
        - cdn: CDN 信息
        - input: 原始输入值

        Args:
            output_file: JSONL 格式的输出文件路径

        Returns:
            解析后的 HTTP 探测结果字典列表
        """
        if not os.path.exists(output_file):
            return []

        items: List[Dict[str, Any]] = []
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                items.append(
                    {
                        "url": raw.get("url"),
                        "status_code": raw.get("status_code"),
                        "title": raw.get("title"),
                        "webserver": raw.get("webserver") or raw.get("web_server"),
                        "tech": raw.get("tech") or [],
                        "cdn": raw.get("cdn"),
                        "input": raw.get("input"),
                    }
                )
        return items

    def run_scan(self, domain: str, candidates: Optional[List[str]] = None, tech_detect: bool = False) -> List[Dict[str, Any]]:
        """
        执行 Httpx HTTP 存活探测。

        构建命令行：httpx -l <input_file> -o <output_file> -json -threads <N> [options] [extra_args]
        始终启用 -title、-status-code、-web-server、-cdn 探测。

        Args:
            domain: 目标域名字符串
            candidates: 可选的子域名候选列表，不传则从 ScanResultStore 加载
            tech_detect: 是否启用技术栈检测（-tech-detect）

        Returns:
            HTTP 探测结果字典列表

        Raises:
            RuntimeError: 当没有可用探测目标或扫描失败时抛出
        """
        targets = list(dict.fromkeys(candidates or self._load_candidates(domain)))
        if not targets:
            raise RuntimeError(f"没有可供 httpx 探测的目标: {domain}")

        output_file = self._build_json_output_file(domain)
        input_file = self._write_input_file(domain, targets)
        cmd = [
            self.config["path"],
            "-l",
            input_file,
            "-o",
            output_file,
            "-json",
            "-threads",
            str(self.config["threads"]),
        ]

        timeout = self.config.get("timeout")
        if timeout:
            cmd.extend(["-timeout", str(timeout)])

        if self.config.get("silent", False):
            cmd.append("-silent")

        cmd.extend(["-title", "-status-code", "-web-server", "-cdn"])

        if tech_detect or self.config.get("tech_detect", False):
            cmd.append("-tech-detect")

        if self.config.get("follow_redirects", False):
            cmd.append("-follow-redirects")

        cmd.extend(self.config.get("extra_args", []))

        try:
            if not self._execute(cmd, domain):
                raise RuntimeError("httpx 扫描失败，请检查 httpx 可执行文件和当前 PATH。")
            return self._read_json_results(output_file)
        finally:
            if os.path.exists(input_file):
                os.remove(input_file)
