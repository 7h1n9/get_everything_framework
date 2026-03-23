from storage import ScanResultStore


def print_global_summary(store):
    summary = store.get_global_summary()

    print("--- 数据库汇总 ---")
    print(f"扫描记录数: {summary['total_runs']}")
    print(f"目标域名数: {summary['total_domains']}")
    print(f"唯一子域名数: {summary['total_subdomains']}")

    print("\n--- 工具统计 ---")
    if not summary["tool_stats"]:
        print("暂无数据")
    else:
        for tool_name, total_count in summary["tool_stats"]:
            print(f"- {tool_name}: {total_count}")

    print("\n--- 最近 10 次扫描 ---")
    if not summary["recent_runs"]:
        print("暂无数据")
    else:
        for domain, tool_name, result_count, created_at in summary["recent_runs"]:
            print(
                f"- 域名: {domain} | 工具: {tool_name} | "
                f"结果数: {result_count} | 时间: {created_at}"
            )


def print_domain_summary(store, domain):
    summary = store.get_domain_summary(domain)

    print(f"--- 域名汇总: {domain} ---")
    print(f"唯一子域名数: {summary['total_subdomains']}")
    print(f"最近扫描时间: {summary['last_scan_at'] or '暂无'}")

    print("\n--- 工具统计 ---")
    if not summary["tool_stats"]:
        print("暂无数据")
    else:
        for tool_name, total_count in summary["tool_stats"]:
            print(f"- {tool_name}: {total_count}")


def show_summary(domain=None):
    store = ScanResultStore()
    if domain:
        print_domain_summary(store, domain)
        return
    print_global_summary(store)
