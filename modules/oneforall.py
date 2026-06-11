from config import ONEFORALL_CONFIG

from .base import BaseRunner


class OneForAllRunner(BaseRunner):
    def __init__(self):
        super().__init__(ONEFORALL_CONFIG, "oneforall")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            self.config.get("target_flag", "--target"),
            domain,
        ]
        cmd.extend(self.config.get("run_args", ["run"]))
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute_stdout(cmd, domain, output_file):
            return []

        return self._read_results(output_file)
