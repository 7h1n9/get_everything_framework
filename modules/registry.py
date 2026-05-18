#工具的注册表
from .alterx import AlterxRunner
from .amass import AmassRunner
from .assetfinder import AssetfinderRunner
from .dnsx import DnsxRunner
from .httpx import HttpxRunner
from .port_tools import NaabuRunner, NmapRunner
from .shuffledns import ShufflednsRunner
from .subfinder import SubfinderRunner
from .url_tools import (
    DirsearchRunner,
    FeroxbusterRunner,
    GospiderRunner,
    KatanaRunner,
    WaybackurlsRunner,
)


RUNNER_REGISTRY = {
    "alterx": AlterxRunner,
    "amass": AmassRunner,
    "assetfinder": AssetfinderRunner,
    "dirsearch": DirsearchRunner,
    "dnsx": DnsxRunner,
    "feroxbuster": FeroxbusterRunner,
    "gospider": GospiderRunner,
    "katana": KatanaRunner,
    "naabu": NaabuRunner,
    "nmap": NmapRunner,
    "shuffledns": ShufflednsRunner,
    "subfinder": SubfinderRunner,
    "httpx": HttpxRunner,
    "waybackurls": WaybackurlsRunner,
}


def get_supported_runners():
    return sorted(RUNNER_REGISTRY.keys())


def build_runner(tool_name):
    runner_cls = RUNNER_REGISTRY.get(tool_name)
    if not runner_cls:
        raise ValueError(f"不支持的收集器: {tool_name}")
    return runner_cls()
