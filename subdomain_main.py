import argparse

from modules import get_supported_runners
from modules.httpx import HttpxRunner
from subdomain_collection import run_subdomain_collection
from summary import show_summary
from viewer import show_alive, show_view


def normalize_query_value(value):
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        return None

    return normalized


def build_parser():
    parser = argparse.ArgumentParser(description="自动化子域名收集工具")
    parser.add_argument("-d", "--domain", help="要扫描的目标域名")
    parser.add_argument("-f", "--file", help="包含域名列表的文本文件")
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
        help="选择一个或多个子域名收集工具",
    )
    parser.add_argument(
        "-s",
        metavar="DOMAIN",
        help="查看指定域名在数据库中的汇总信息",
    )
    parser.add_argument(
        "-v",
        metavar="DOMAIN",
        help="查看指定域名在数据库中的所有子域名信息",
    )
    parser.add_argument(
        "-a",
        metavar="DOMAIN",
        help="查看指定域名在数据库中的存活目标信息",
    )
    parser.add_argument(
        "--httpx",
        metavar="DOMAIN",
        help="对数据库中指定域名的子域名执行 httpx Web 探测并打印结果",
    )
    return parser


def print_subdomain_usage_hint():
    print("--- 子域名收集模块 ---")
    print("当前未检测到明确操作，已停止自动扫描。")
    print("你可以先选择一个功能：")
    print("- 查看工具: python subdomain_main.py -l")
    print("- 执行扫描: python subdomain_main.py -d example.com -t subfinder")
    print("- 查看汇总: python subdomain_main.py -s example.com")
    print("- 查看明细: python subdomain_main.py -v example.com")
    print("- 查看存活: python subdomain_main.py -a example.com")
    print("- Web 探测: python subdomain_main.py --httpx example.com")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    summary_domain = normalize_query_value(args.s)
    view_domain = normalize_query_value(args.v)
    alive_domain = normalize_query_value(args.a)
    httpx_domain = normalize_query_value(args.httpx)

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
            args.s is not None,
            args.v is not None,
            args.a is not None,
            args.httpx is not None,
        ]
    )

    if not has_scan_request and not has_query_request:
        print_subdomain_usage_hint()
        return 0

    if args.list_tools:
        print("--- 当前已集成的工具模块 ---")
        for tool in get_supported_runners():
            print(f"- {tool}")
        print("- httpx (独立 Web 探测命令: --httpx DOMAIN)")
        return 0

    if args.s is not None and summary_domain is None:
        return 0

    if summary_domain:
        show_summary(summary_domain)
        return 0

    if args.v is not None and view_domain is None:
        return 0

    if view_domain:
        show_view(domain=view_domain)
        return 0

    if args.a is not None and alive_domain is None:
        return 0

    if alive_domain:
        show_alive(alive_domain)
        return 0

    if args.httpx is not None and httpx_domain is None:
        return 0

    if httpx_domain:
        results = HttpxRunner().run_scan(httpx_domain)
        print(f"--- httpx 探测结果: {httpx_domain} ---")
        if not results:
            print("暂无结果")
            return 0
        for item in results:
            print(f"- {item}")
        return 0

    run_subdomain_collection(
        domain=args.domain,
        file_path=args.file,
        tools=args.tools,
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
