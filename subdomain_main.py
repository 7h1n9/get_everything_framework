import argparse
import sys

from database_viewer import show_database_list, show_database_results
from modules import get_supported_runners
from tool_runner import run_tools


STARTUP_BANNER = (
    "   ______     __      _____     _____           _______   ___           \n"
    "  / ____/__  / /_    |__  /   _|__  /_______  _/__  / /_ <  /___  ____ _\n"
    " / / __/ _ \\/ __/     /_ < | / //_ </ ___/ / / / / / __ \\/ / __ \\/ __ `/\n"
    "/ /_/ /  __/ /_     ___/ / |/ /__/ / /  / /_/ / / / / / / / / / / /_/ / \n"
    "\\____/\\___/\\__/____/____/|___/____/_/   \\__, / /_/_/ /_/ /_/ /_/\\__, /  \n"
    "             /_____/                   /____/        /____/    /____/    "
)
STARTUP_SUBTITLE = "Get_3v3ry7h1ng_Fr4mw0rk - 自动化信息收集工具"


def print_startup_banner(stream=None):
    stream = stream or sys.stdout
    if getattr(stream, "isatty", lambda: False)():
        stream.write(f"\033[92m{STARTUP_BANNER}\n\n{STARTUP_SUBTITLE}\033[0m\n\n")
        return

    stream.write(f"{STARTUP_BANNER}\n\n{STARTUP_SUBTITLE}\n\n")


def normalize_query_value(value):
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        return None

    return normalized


def build_parser():
    parser = argparse.ArgumentParser(description="自动化信息收集工具")
    parser.add_argument("-d", "--domain", help="要运行工具的目标域名或 URL")
    parser.add_argument("-f", "--file", help="包含目标列表的文本文件")
    parser.add_argument(
        "-l",
        "--list-tools",
        action="store_true",
        help="查看当前已集成的工具模块",
    )
    parser.add_argument(
        "-t",
        "--tools",
        nargs="+",
        choices=get_supported_runners(),
        required=False,
        help="选择一个或多个要运行的工具",
    )
    parser.add_argument(
        "--list-databases",
        action="store_true",
        help="查看当前所有工具专用数据库",
    )
    parser.add_argument(
        "--database",
        metavar="TOOL",
        choices=get_supported_runners(),
        help="查看指定工具专用数据库中的结果",
    )
    parser.add_argument(
        "--database-domain",
        metavar="DOMAIN",
        help="查看工具专用数据库时按域名筛选",
    )
    parser.add_argument(
        "--database-limit",
        type=int,
        default=100,
        help="查看工具专用数据库时最多显示多少条，默认 100",
    )
    return parser


def print_usage_hint():
    print("--- 工具运行入口 ---")
    print("当前未检测到明确操作，已停止自动扫描。")
    print("你可以先选择一个功能：")
    print("- 查看工具: python subdomain_main.py -l")
    print("- 运行单个工具: python subdomain_main.py -d example.com -t subfinder")
    print("- 运行多个工具: python subdomain_main.py -d example.com -t subfinder dnsx httpx")
    print("- 查看数据库清单: python subdomain_main.py --list-databases")
    print("- 查看工具数据库: python subdomain_main.py --database katana --database-limit 20")


def main(argv=None):
    print_startup_banner()
    parser = build_parser()
    args = parser.parse_args(argv)
    database_domain = normalize_query_value(args.database_domain)

    has_scan_request = any(
        [
            args.domain,
            args.file,
            args.tools,
        ]
    )
    has_query_request = any(
        [
            args.list_tools,
            args.list_databases,
            args.database is not None,
        ]
    )

    if not has_scan_request and not has_query_request:
        print_usage_hint()
        return 0

    if args.list_tools:
        print("--- 当前已集成的工具模块 ---")
        for tool in get_supported_runners():
            print(f"- {tool}")
        return 0

    if args.list_databases:
        show_database_list()
        return 0

    if args.database:
        limit = max(1, min(args.database_limit, 1000))
        show_database_results(args.database, domain=database_domain, limit=limit)
        return 0

    if not args.tools:
        print("[!] 请通过 -t/--tools 指定要运行的工具")
        print_usage_hint()
        return 0

    run_tools(
        domain=args.domain,
        file_path=args.file,
        tools=args.tools,
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
