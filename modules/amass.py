import re

from config import AMASS_CONFIG

from .base import BaseRunner


class AmassRunner(BaseRunner):
    def __init__(self):
        super().__init__(AMASS_CONFIG, "amass")

    def _normalize_results(self, results, domain):
        normalized_results = []
        seen = set()
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_-])([A-Za-z0-9._-]+\.{re.escape(domain)})\b"
        )

        for line in results:
            for match in pattern.findall(line):
                value = match.lower().rstrip(".")
                if value in seen:
                    continue
                normalized_results.append(value)
                seen.add(value)

        return normalized_results

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "enum",
            "-d",
            domain,
            "-o",
            output_file,
        ]

        if self.config.get("passive", False):
            cmd.append("-passive")

        if self.config.get("brute", False):
            cmd.append("-brute")

        timeout = self.config.get("timeout")
        if timeout:
            cmd.extend(["-timeout", str(timeout)])

        if self.config.get("silent", False):
            cmd.append("-silent")

        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._normalize_results(self._read_results(output_file), domain)
