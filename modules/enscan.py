from config import ENSCAN_CONFIG

from .base import BaseRunner


class ENScanRunner(BaseRunner):
    def __init__(self):
        super().__init__(ENSCAN_CONFIG, "enscan")

    def run_scan(self, keyword):
        output_file = self._build_output_file(keyword)
        cmd = [
            self.config["path"],
            self.config.get("keyword_flag", "-k"),
            keyword,
        ]
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute_stdout(cmd, keyword, output_file):
            return []

        return self._read_results(output_file)
