import os

from config import ALTERX_CONFIG
from storage import ScanResultStore

from .base import BaseRunner


class AlterxRunner(BaseRunner):
    def __init__(self):
        super().__init__(ALTERX_CONFIG, "alterx")
        self.store = ScanResultStore()

    def _load_candidates(self, domain):
        rows = self.store.get_results_by_domain(domain)
        candidates = list(dict.fromkeys(subdomain for subdomain, _, _ in rows))
        if not candidates:
            return [domain]
        return candidates

    def run_scan(self, domain):
        candidates = self._load_candidates(domain)
        input_file = self._write_input_file(domain, candidates)
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-l",
            input_file,
            "-o",
            output_file,
        ]
        cmd.extend(self.config.get("extra_args", []))

        try:
            if not self._execute(cmd, domain):
                return []
            return self._read_results(output_file)
        finally:
            if os.path.exists(input_file):
                os.remove(input_file)
