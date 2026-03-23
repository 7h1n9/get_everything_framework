import argparse
import sys
from config import SCAN_CONFIG, TARGET_CONFIG
from modules import build_runner, get_supported_runners
from storage import ScanResultStore
from summary import show_summary
from viewer import show_alive, show_view


def load_targets(domain=None, file_path=None):
    targets = []

    if domain:
        targets.append(domain.strip())

    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not targets:
        targets.extend(TARGET_CONFIG.get("domains", []))

        config_file = TARGET_CONFIG.get("domain_file")
        if config_file:
            with open(config_file, "r", encoding="utf-8") as f:
                targets.extend([line.strip() for line in f if line.strip()])

    # 去重并保留顺序
    unique_targets = []
    seen = set()
    for target in targets:
        if target not in seen:
            unique_targets.append(target)
            seen.add(target)

    return unique_targets


def load_tools(cli_tools=None):
    tools = cli_tools or SCAN_CONFIG.get("enabled_runners", [])
    supported_tools = set(get_supported_runners())
    invalid_tools = [tool for tool in tools if tool not in supported_tools]
    if invalid_tools:
        raise ValueError(f"存在不支持的收集器: {', '.join(invalid_tools)}")
    return tools


def main():
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

    args = parser.parse_args()

    if args.list_tools:
        print("--- 当前已集成的工具模块 ---")
        for tool in get_supported_runners():
            print(f"- {tool}")
        return

    if args.s:
        show_summary(args.s)
        return

    if args.v:
        show_view(domain=args.v)
        return

    if args.a:
        show_alive(args.a)
        return

    targets = load_targets(args.domain, args.file)
    if not targets:
        parser.print_help()
        print("\n[!] 未提供目标域名，且 config.py 中 TARGET_CONFIG 也为空")
        sys.exit(1)

    try:
        tools = load_tools(args.tools)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if not tools:
        print("[!] 未配置任何收集器，请检查 config.py 中 SCAN_CONFIG['enabled_runners']")
        sys.exit(1)

    store = ScanResultStore()
    print(f"--- 任务开始，工具: {', '.join(tools)}，共 {len(targets)} 个目标 ---")
    total_found = 0
    total_inserted = 0
    for tool in tools:
        scanner = build_runner(tool)
        tool_total = 0
        tool_inserted = 0
        print(f"\n=== 开始执行模块: {tool} ===")
        for target in targets:
            results = scanner.run_scan(target)
            save_summary = store.save_results(target, tool, results)
            print(
                f"[+] [{tool}] {target} 扫描完成，发现 {len(results)} 个子域名，"
                f"新增入库 {save_summary['inserted_count']} 条"
            )
            tool_total += len(results)
            tool_inserted += save_summary["inserted_count"]
        total_found += tool_total
        total_inserted += tool_inserted
        print(
            f"=== 模块 {tool} 执行完成，累计发现 {tool_total} 个结果，"
            f"新增入库 {tool_inserted} 条 ==="
        )

    print(
        f"--- 所有任务已完成，累计发现 {total_found} 个子域名，"
        f"新增入库 {total_inserted} 条 ---"
    )


if __name__ == "__main__":
    main()
