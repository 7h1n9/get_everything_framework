import os
import tempfile

from config import HTTPX_CONFIG, OUTPUT_DIR
from storage import ScanResultStore

from .base import BaseRunner


class HttpxRunner(BaseRunner):
    def __init__(self):
        super().__init__(HTTPX_CONFIG, "httpx")
        self.store = ScanResultStore()

    def _load_candidates(self, domain):
        rows = self.store.get_results_by_domain(domain)
        return list(dict.fromkeys(subdomain for subdomain, _, _ in rows))

    def _write_input_file(self, domain, candidates):
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

    def run_scan(self, domain):
        candidates = self._load_candidates(domain)
        if not candidates:
            print(f"[!] 数据库中未找到 {domain} 的子域名记录，无法执行 httpx 探测")
            return []

        output_file = self._build_output_file(domain)
        input_file = self._write_input_file(domain, candidates)
        cmd = [
            self.config["path"],
            "-l",
            input_file,
            "-o",
            output_file,
            "-threads",
            str(self.config["threads"]),
        ]

        timeout = self.config.get("timeout")
        if timeout:
            cmd.extend(["-timeout", str(timeout)])

        if self.config.get("silent", False):
            cmd.append("-silent")

        if self.config.get("title", False):
            cmd.append("-title")

        if self.config.get("status_code", False):
            cmd.append("-status-code")

        if self.config.get("tech_detect", False):
            cmd.append("-tech-detect")

        if self.config.get("follow_redirects", False):
            cmd.append("-follow-redirects")

        cmd.extend(self.config.get("extra_args", []))

        try:
            if not self._execute(cmd, domain):
                return []
            return self._read_results(output_file)
        finally:
            if os.path.exists(input_file):
                os.remove(input_file)
