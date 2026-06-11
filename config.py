import os


OUTPUT_DIR = "results"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

UPLOAD_DIR = "uploads"
EXPORT_DIR = "exports"

MAX_UPLOAD_SIZE = 2 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".csv"}

SQLITE_CONFIG = {
    "path": os.path.join(OUTPUT_DIR, "scan_results.db"),
}

GO_BIN_WINDOWS = os.path.join(os.path.expanduser("~"), "go", "bin")
GO_BIN_POSIX = os.path.join(os.path.expanduser("~"), "go", "bin")

TARGET_CONFIG = {
    "domains": [
        "nfl.com",
    ],
    "domain_file": None,
}

SCAN_CONFIG = {
    "enabled_runners": ["amass"],
}


def build_tool_config(path, category, **kwargs):
    config = {
        "path": path,
        "category": category,
        "process_timeout": 300,
        "extra_args": [],
    }
    config.update(kwargs)
    return config


AMASS_CONFIG = {
    "path": "amass",
    "category": "subdomain",
    "timeout": 30,
    "passive": True,
    "silent": True,
    "extra_args": [],
}

SUBFINDER_CONFIG = {
    "path": "subfinder",
    "category": "subdomain",
    "threads": 50,
    "timeout": 10,
    "silent": True,
}

DNSX_CONFIG = {
    "path": "dnsx",
    "category": "alive",
    "threads": 50,
    "silent": True,
    "resp_only": True,
    "extra_args": [],
}

HTTPX_CONFIG = {
    "path": os.getenv("HTTPX_PATH", "http-x"),
    "category": "web",
    "threads": 50,
    "silent": True,
    "title": True,
    "status_code": True,
    "tech_detect": False,
    "follow_redirects": False,
    "timeout": 10,
    "process_timeout": 300,
    "extra_args": [],
}

ASSETFINDER_CONFIG = build_tool_config("assetfinder", "subdomain", subs_only=True)
SHUFFLEDNS_CONFIG = build_tool_config("shuffledns", "subdomain", wordlist=None, resolver_file=None)
ALTERX_CONFIG = build_tool_config("alterx", "subdomain")

GOSPIDER_CONFIG = build_tool_config("gospider", "url", depth=2)
KATANA_CONFIG = build_tool_config("katana", "url", depth=2)
WAYBACKURLS_CONFIG = build_tool_config("waybackurls", "url")

FEROXBUSTER_CONFIG = build_tool_config(
    "feroxbuster",
    "content_discovery",
    wordlist=None,
    json_output=True,
)

DIRSEARCH_CONFIG = build_tool_config(
    "dirsearch",
    "content_discovery",
    wordlist=None,
    json_output=True,
)

NAABU_CONFIG = build_tool_config("naabu", "port", silent=True)
NMAP_CONFIG = build_tool_config("nmap", "port", ports=None)

ONEFORALL_CONFIG = build_tool_config(
    "oneforall",
    "subdomain",
    target_flag="--target",
    run_args=["run"],
)

ENSCAN_CONFIG = build_tool_config(
    "enscan",
    "org_info",
    keyword_flag="-k",
)

TOOL_COMMANDS = {
    "subfinder": "subfinder",
    "dnsx": "dnsx",
    "httpx": os.getenv("HTTPX_PATH", "http-x"),
    "naabu": "naabu",
    "nmap": "nmap",
    "katana": "katana",
    "gospider": "gospider",
    "waybackurls": "waybackurls",
    "feroxbuster": "feroxbuster",
    "dirsearch": "dirsearch",
    "oneforall": "oneforall",
    "enscan": "enscan",
}

TOOL_CATEGORIES = {
    "subfinder": "subdomain",
    "oneforall": "subdomain",
    "dnsx": "alive",
    "httpx": "web_probe",
    "naabu": "port_scan",
    "nmap": "port_scan",
    "katana": "url_discovery",
    "gospider": "url_discovery",
    "waybackurls": "url_discovery",
    "feroxbuster": "content_discovery",
    "dirsearch": "content_discovery",
    "enscan": "org_info",
}

DEFAULT_PASSIVE_TOOLS = ["enscan", "oneforall"]
DEFAULT_SUBDOMAIN_TOOLS = ["subfinder", "oneforall"]
DEFAULT_WEB_PROBE_TOOLS = ["httpx"]
DEFAULT_CONTENT_DISCOVERY_TOOLS = ["dirsearch", "feroxbuster"]
DEFAULT_PORT_SCAN_TOOLS = ["naabu"]
