from config import NAABU_CONFIG

from .base import BaseRunner


class NaabuRunner(BaseRunner):
    def __init__(self):
        super().__init__(NAABU_CONFIG, "naabu")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-host",
            domain,
            "-o",
            output_file,
        ]

        ports = self.config.get("ports")
        if ports:
            cmd.extend(["-p", str(ports)])

        if self.config.get("silent", True):
            cmd.append("-silent")

        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)


__all__ = ["NaabuRunner"]
