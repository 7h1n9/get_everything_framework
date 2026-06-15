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


AMASS_CONFIG = build_tool_config(
    "amass",
    "subdomain",
    enum_subcommand="enum",
    domain_flag="-d",
    output_flag="-o",
    passive=True,
    passive_flag="-passive",
    brute=False,
    brute_flag="-brute",
    timeout=30,
    timeout_flag="-timeout",
    silent=True,
    silent_flag="-silent",
)

SUBFINDER_CONFIG = build_tool_config(
    "subfinder",
    "subdomain",
    domain_flag="-d",
    list_flag="-dL",
    output_flag="-o",
    threads=50,
    threads_flag="-t",
    timeout=10,
    timeout_flag="-timeout",
    silent=True,
    silent_flag="-silent",
)

ASSETFINDER_CONFIG = build_tool_config(
    "assetfinder",
    "subdomain",
    subs_only=True,
    subs_only_flag="--subs-only",
)

SHUFFLEDNS_CONFIG = build_tool_config(
    "shuffledns",
    "subdomain",
    domain_flag="-d",
    input_flag="-l",
    wordlist_flag="-w",
    resolver_flag="-r",
    output_flag="-o",
    mode="bruteforce",
    mode_flag="-mode",
    silent=True,
    silent_flag="-silent",
    wordlist=None,
    resolver_file=None,
)

ALTERX_CONFIG = build_tool_config(
    "alterx",
    "subdomain",
    input_flag="-l",
    output_flag="-o",
    mode="default",
    mode_flag="-m",
)

ONEFORALL_CONFIG = build_tool_config(
    "oneforall",
    "subdomain",
    target_flag="--target",
    targets_flag="--targets",
    run_args=["run"],
    result_format="csv",
    result_format_flag="--fmt",
    result_path_flag="--path",
)

DNSX_CONFIG = build_tool_config(
    "dnsx",
    "alive",
    input_flag="-l",
    output_flag="-o",
    threads=50,
    threads_flag="-t",
    silent=True,
    silent_flag="-silent",
    resp_only=True,
    resp_only_flag="-resp-only",
)

HTTPX_CONFIG = build_tool_config(
    os.getenv("HTTPX_PATH", "http-x"),
    "web",
    input_flag="-l",
    target_flag="-u",
    output_flag="-o",
    json_output=True,
    json_flag="-json",
    threads=50,
    threads_flag="-threads",
    timeout=10,
    timeout_flag="-timeout",
    silent=True,
    silent_flag="-silent",
    title=True,
    title_flag="-title",
    status_code=True,
    status_code_flag="-status-code",
    web_server=True,
    web_server_flag="-web-server",
    cdn=True,
    cdn_flag="-cdn",
    tech_detect=False,
    tech_detect_flag="-tech-detect",
    follow_redirects=False,
    follow_redirects_flag="-follow-redirects",
)

NAABU_CONFIG = build_tool_config(
    "naabu",
    "port",
    host_flag="-host",
    list_flag="-list",
    output_flag="-o",
    ports=None,
    ports_flag="-p",
    silent=True,
    silent_flag="-silent",
)

NMAP_CONFIG = build_tool_config(
    "nmap",
    "port",
    output_flag="-oN",
    ports=None,
    ports_flag="-p",
)

KATANA_CONFIG = build_tool_config(
    "katana",
    "url",
    target_flag="-u",
    depth=2,
    depth_flag="-d",
    output_flag="-o",
    silent=True,
    silent_flag="-silent",
    tech_detect=False,
    tech_detect_flag="-td",
)

GOSPIDER_CONFIG = build_tool_config(
    "gospider",
    "url",
    site_flag="-s",
    depth=2,
    depth_flag="-d",
    quiet=True,
    quiet_flag="-q",
)

WAYBACKURLS_CONFIG = build_tool_config(
    "waybackurls",
    "url",
    no_subs=False,
    no_subs_flag="-no-subs",
    dates=False,
    dates_flag="-dates",
)

FEROXBUSTER_CONFIG = build_tool_config(
    "feroxbuster",
    "url",
    url_flag="-u",
    output_flag="-o",
    wordlist=None,
    wordlist_flag="-w",
    json_output=True,
    json_flag="--json",
    quiet=True,
    quiet_flag="--quiet",
    silent=True,
    silent_flag="--silent",
)

DIRSEARCH_CONFIG = build_tool_config(
    "dirsearch",
    "url",
    url_flag="-u",
    output_flag="-o",
    output_format="json",
    output_format_flag="-O",
    wordlist=None,
    wordlist_flag="-w",
    quiet=True,
    quiet_flag="-q",
    full_url=True,
    full_url_flag="--full-url",
)

ENSCAN_CONFIG = build_tool_config(
    "enscan",
    "org_info",
    keyword_flag="-n",
    file_flag="-f",
    query_type="aqc",
    query_type_flag="-type",
    field=None,
    field_flag="-field",
    out_dir_flag="-out-dir",
    json_output=True,
    json_flag="-json",
    output_type="json",
    output_type_flag="-out-type",
    timeout=1,
    timeout_flag="-timeout",
)

TOOL_COMMANDS = {
    "amass": "amass",
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "shuffledns": "shuffledns",
    "alterx": "alterx",
    "oneforall": "oneforall",
    "dnsx": "dnsx",
    "httpx": os.getenv("HTTPX_PATH", "http-x"),
    "naabu": "naabu",
    "nmap": "nmap",
    "katana": "katana",
    "gospider": "gospider",
    "waybackurls": "waybackurls",
    "feroxbuster": "feroxbuster",
    "dirsearch": "dirsearch",
    "enscan": "enscan",
}

TOOL_CATEGORIES = {
    "amass": "subdomain",
    "subfinder": "subdomain",
    "assetfinder": "subdomain",
    "shuffledns": "subdomain",
    "alterx": "subdomain",
    "oneforall": "subdomain",
    "dnsx": "alive",
    "httpx": "web",
    "naabu": "port",
    "nmap": "port",
    "katana": "url",
    "gospider": "url",
    "waybackurls": "url",
    "feroxbuster": "url",
    "dirsearch": "url",
    "enscan": "org_info",
}

DEFAULT_PASSIVE_TOOLS = ["enscan", "subfinder", "assetfinder", "waybackurls", "oneforall"]
DEFAULT_SUBDOMAIN_TOOLS = ["subfinder", "oneforall", "assetfinder", "amass"]
DEFAULT_ALIVE_TOOLS = ["dnsx"]
DEFAULT_WEB_PROBE_TOOLS = ["httpx"]
DEFAULT_URL_TOOLS = ["katana", "gospider", "waybackurls"]
DEFAULT_CONTENT_DISCOVERY_TOOLS = ["dirsearch", "feroxbuster"]
DEFAULT_PORT_SCAN_TOOLS = ["naabu", "nmap"]
