from config import ENSCAN_CONFIG
from config import OUTPUT_DIR

from .base import BaseRunner


class ENScanRunner(BaseRunner):
    def __init__(self):
        super().__init__(ENSCAN_CONFIG, "enscan")

    def run_scan(self, keyword):
        output_file = self._build_output_file(keyword)
        cmd = [
            self.config["path"],
            self.config.get("keyword_flag", "-n"),
            keyword,
        ]

        out_dir_flag = self.config.get("out_dir_flag")
        if out_dir_flag:
            cmd.extend([out_dir_flag, OUTPUT_DIR])

        if self.config.get("json_output", False):
            cmd.append("-json")

        output_type = self.config.get("output_type")
        if output_type:
            cmd.extend(["-out-type", str(output_type)])

        cmd.extend(self.config.get("extra_args", []))

        if not self._execute_stdout(cmd, keyword, output_file):
            return []

        return self._read_results(output_file)
