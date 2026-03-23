from config import SUBFINDER_CONFIG

from .base import BaseRunner


class SubfinderRunner(BaseRunner):
    def __init__(self):
        super().__init__(SUBFINDER_CONFIG, "subfinder")

    def run_scan(self, domain):
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
