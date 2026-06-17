"""
Subfinder 子域名发现工具运行器。

Subfinder 是一款基于被动源的子域名枚举工具，通过调用多个 API
接口（如 SecurityTrails、Censys、Shodan 等）收集目标域名的子域名信息。
"""

from config import SUBFINDER_CONFIG

from .base import BaseRunner


class SubfinderRunner(BaseRunner):
    """
    Subfinder 运行器，通过被动源 API 收集子域名。

    使用 Subfinder 工具对目标域名执行子域名枚举，
    支持多线程和超时配置，结果直接输出到文件后读取。

    示例配置 (SUBFINDER_CONFIG):
        {
            "path": "subfinder",
            "threads": 10,
            "timeout": 30,
            "silent": True,
            "category": "subdomain"
        }
    """

    def __init__(self):
        """初始化 Subfinder 运行器，加载 SUBFINDER_CONFIG 配置。"""
        super().__init__(SUBFINDER_CONFIG, "subfinder")

    def run_scan(self, domain):
        """
        执行 Subfinder 子域名扫描。

        构建 Subfinder 命令行：subfinder -d <domain> -t <threads> -o <output_file>
        可选参数包括 -timeout 和 -silent。

        Args:
            domain: 目标域名字符串

        Returns:
            发现的子域名列表，扫描失败时返回空列表
        """
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-d",
            domain,
            "-t",
            str(self.config["threads"]),
            "-o",
            output_file,
        ]

        timeout = self.config.get("timeout")
        if timeout:
            cmd.extend(["-timeout", str(timeout)])

        if self.config.get("silent", False):
            cmd.append("-silent")

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)
