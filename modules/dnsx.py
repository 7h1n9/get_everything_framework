import os
import tempfile

from config import DNSX_CONFIG, OUTPUT_DIR
from storage import ScanResultStore

from .base import BaseRunner


class DnsxRunner(BaseRunner):
    def __init__(self):
        super().__init__(DNSX_CONFIG, "dnsx")
        self.store = ScanResultStore()

    def _load_candidates(self, domain):
        rows = self.store.get_results_by_domain(domain)
        candidates = list(dict.fromkeys(subdomain for subdomain, _, _ in rows))
        if not candidates:
            return [domain]
        return candidates

    def _write_input_file(self, domain, candidates):
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=f"_{domain}_dnsx_input.txt",
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
        output_file = self._build_output_file(domain)
        candidates = self._load_candidates(domain)
        input_file = self._write_input_file(domain, candidates)

        cmd = [
            self.config["path"],
            "-l",
            input_file,
            "-o",
            output_file,
            "-t",
            str(self.config["threads"]),
        ]

        if self.config.get("silent", False):
            cmd.append("-silent")

        if self.config.get("resp_only", False):
            cmd.append("-resp-only")

        cmd.extend(self.config.get("extra_args", []))

        try:
            if not self._execute(cmd, domain):
                return []
            return self._read_results(output_file)
        finally:
            if os.path.exists(input_file):
                os.remove(input_file)
