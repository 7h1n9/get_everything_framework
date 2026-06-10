import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from config import HTTPX_CONFIG, OUTPUT_DIR
from storage import ScanResultStore

from .base import BaseRunner


class HttpxRunner(BaseRunner):
    def __init__(self):
        super().__init__(HTTPX_CONFIG, "httpx")
        self.store = ScanResultStore()

    def _load_candidates(self, domain: str) -> List[str]:
        rows = self.store.get_results_by_domain(domain)
        return list(dict.fromkeys(subdomain for subdomain, _, _ in rows))

    def _write_input_file(self, domain: str, candidates: List[str]) -> str:
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
        return os.path.join(self.output_dir, f"{domain}_{self.tool_name}.jsonl")

    def _read_json_results(self, output_file: str) -> List[Dict[str, Any]]:
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
