from config import DIRSEARCH_CONFIG

from .base import BaseRunner


def build_url(domain):
    if domain.startswith(("http://", "https://")):
        return domain
    return f"https://{domain}"


class DirsearchRunner(BaseRunner):
    def __init__(self):
        super().__init__(DIRSEARCH_CONFIG, "dirsearch")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-u",
            build_url(domain),
            "-o",
            output_file,
            "-q",
            "--full-url",
        ]

        if self.config.get("json_output", False):
            cmd.extend(["-O", "json"])
        else:
            cmd.extend(["-O", "plain"])

        wordlist = self.config.get("wordlist")
        if wordlist:
            cmd.extend(["-w", wordlist])

        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)


__all__ = ["DirsearchRunner"]
