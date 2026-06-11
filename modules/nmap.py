from config import NMAP_CONFIG

from .base import BaseRunner


class NmapRunner(BaseRunner):
    def __init__(self):
        super().__init__(NMAP_CONFIG, "nmap")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [self.config["path"]]

        ports = self.config.get("ports")
        if ports:
            cmd.extend(["-p", str(ports)])

        cmd.extend(["-oN", output_file, domain])
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)


__all__ = ["NmapRunner"]
