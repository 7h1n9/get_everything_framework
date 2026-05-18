from config import SHUFFLEDNS_CONFIG

from .base import BaseRunner


class ShufflednsRunner(BaseRunner):
    def __init__(self):
        super().__init__(SHUFFLEDNS_CONFIG, "shuffledns")

    def run_scan(self, domain):
        wordlist = self.config.get("wordlist")
        resolver_file = self.config.get("resolver_file")
        if not wordlist or not resolver_file:
            print("[!] shuffledns 需要在 config.py 中配置 wordlist 和 resolver_file")
            return []

        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-d",
            domain,
            "-w",
            wordlist,
            "-r",
            resolver_file,
            "-o",
            output_file,
        ]
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)
