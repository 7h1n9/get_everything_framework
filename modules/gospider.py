from config import GOSPIDER_CONFIG

from .base import BaseRunner


def build_url(domain):
    if domain.startswith(("http://", "https://")):
        return domain
    return f"https://{domain}"


class GospiderRunner(BaseRunner):
    def __init__(self):
        super().__init__(GOSPIDER_CONFIG, "gospider")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-s",
            build_url(domain),
            "-d",
            str(self.config.get("depth", 2)),
            "-q",
        ]
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute_stdout(cmd, domain, output_file):
            return []

        return self._read_results(output_file)


__all__ = ["GospiderRunner"]
