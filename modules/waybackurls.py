from config import WAYBACKURLS_CONFIG

from .base import BaseRunner


class WaybackurlsRunner(BaseRunner):
    def __init__(self):
        super().__init__(WAYBACKURLS_CONFIG, "waybackurls")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [self.config["path"], domain]
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute_stdout(cmd, domain, output_file):
            return []

        return self._read_results(output_file)


__all__ = ["WaybackurlsRunner"]
