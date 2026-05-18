import re

from config import ASSETFINDER_CONFIG

from .base import BaseRunner


class AssetfinderRunner(BaseRunner):
    def __init__(self):
        super().__init__(ASSETFINDER_CONFIG, "assetfinder")

    def _normalize_results(self, results, domain):
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_-])([A-Za-z0-9._-]+\.{re.escape(domain)})\b"
        )
        normalized = []
        seen = set()
        for line in results:
            for match in pattern.findall(line):
                value = match.lower().rstrip(".")
                if value in seen:
                    continue
                normalized.append(value)
                seen.add(value)
        return normalized

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [self.config["path"]]
        if self.config.get("subs_only", True):
            cmd.append("--subs-only")
        cmd.append(domain)
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute_stdout(cmd, domain, output_file):
            return []

        return self._normalize_results(self._read_results(output_file), domain)
