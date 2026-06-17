"""
Shuffledns DNS 暴力枚举工具运行器。

Shuffledns 是 ProjectDiscovery 开发的高性能 DNS 子域名暴力枚举工具，
通过字典文件和自定义 DNS 解析器列表进行大规模的 DNS A 记录查询，
从而发现目标域名的子域名。
"""

from config import SHUFFLEDNS_CONFIG

from .base import BaseRunner


class ShufflednsRunner(BaseRunner):
    """
    Shuffledns 运行器，基于字典进行 DNS 子域名暴力枚举。

    需要预先配置：
    - wordlist: 子域名字典文件路径
    - resolver_file: DNS 解析器列表文件路径

    示例配置 (SHUFFLEDNS_CONFIG):
        {
            "path": "shuffledns",
            "wordlist": "/path/to/subdomains.txt",
            "resolver_file": "/path/to/resolvers.txt",
            "extra_args": [],
            "category": "subdomain"
        }
    """

    def __init__(self):
        """初始化 Shuffledns 运行器，加载 SHUFFLEDNS_CONFIG 配置。"""
        super().__init__(SHUFFLEDNS_CONFIG, "shuffledns")

    def run_scan(self, domain):
        """
        执行 Shuffledns DNS 暴力枚举。

        构建命令行：shuffledns -d <domain> -w <wordlist> -r <resolver_file> -o <output_file> [extra_args]

        Args:
            domain: 目标域名字符串

        Returns:
            通过 DNS 解析验证的存活子域名列表；
            如果缺少 wordlist 或 resolver_file 配置则返回空列表
        """
        wordlist = self.config.get("wordlist")
        resolver_file = self.config.get("resolver_file")
        if not wordlist or not resolver_file:
            print("[!] shuffledns 需要在 config.py 中配置 wordlist 和 resolver_file")
            return []

        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-d",
            domain,
            "-w",
            wordlist,
            "-r",
            resolver_file,
            "-o",
            output_file,
        ]
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)
