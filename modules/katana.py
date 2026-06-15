from config import KATANA_CONFIG

from .base import BaseRunner


def build_url(domain):
    if domain.startswith(("http://", "https://")):
        return domain
    return f"https://{domain}"


class KatanaRunner(BaseRunner):
    def __init__(self):
        super().__init__(KATANA_CONFIG, "katana")

    def run_scan(self, domain):
        output_file = self._build_output_file(domain)
        cmd = [
            self.config["path"],
            "-u",
            build_url(domain),
            "-d",
            str(self.config.get("depth", 2)),
            "-o",
            output_file,
            "-silent",
        ]
        cmd.extend(self.config.get("extra_args", []))

        if not self._execute(cmd, domain):
            return []

        return self._read_results(output_file)


__all__ = ["KatanaRunner"]
