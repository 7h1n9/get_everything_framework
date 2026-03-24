from config import SCAN_CONFIG, TARGET_CONFIG
from modules import build_runner, get_supported_runners
from storage import ScanResultStore


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


def run_subdomain_collection(domain=None, file_path=None, tools=None, store=None):
    targets = load_targets(domain, file_path)
    if not targets:
        print("\n[!] 未提供目标域名，且 config.py 中 TARGET_CONFIG 也为空")
        raise SystemExit(1)

    try:
        selected_tools = load_tools(tools)
    except ValueError as exc:
        print(f"[!] {exc}")
        raise SystemExit(1) from exc

    if not selected_tools:
        print("[!] 未配置任何收集器，请检查 config.py 中 SCAN_CONFIG['enabled_runners']")
        raise SystemExit(1)

    store = store or ScanResultStore()
    print(f"--- 任务开始，工具: {', '.join(selected_tools)}，共 {len(targets)} 个目标 ---")
    total_found = 0
    total_inserted = 0
    run_details = []

    for tool in selected_tools:
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
            run_details.append(
                {
                    "domain": target,
                    "tool_name": tool,
                    "found_count": len(results),
                    "inserted_count": save_summary["inserted_count"],
                    "run_id": save_summary["run_id"],
                }
            )

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

    return {
        "targets": targets,
        "tools": selected_tools,
        "total_found": total_found,
        "total_inserted": total_inserted,
        "runs": run_details,
    }
