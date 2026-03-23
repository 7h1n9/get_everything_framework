from storage import ScanResultStore


def print_view_results(store, domain=None, tool_name=None):
    overview = store.get_view_overview(domain=domain, tool_name=tool_name)
    results = store.get_view_results(domain=domain, tool_name=tool_name)

    print("--- 扫描内容查看 ---")
    print(f"筛选域名: {domain or '全部'}")
    print(f"筛选工具: {tool_name or '全部'}")

    print("\n--- 结果概览 ---")
    if not overview:
        print("暂无数据")
    else:
        for item_domain, item_tool, total_count, last_scan_at in overview:
            print(
                f"- 域名: {item_domain} | 工具: {item_tool} | "
                f"子域名数: {total_count} | 最近时间: {last_scan_at}"
            )

    print("\n--- 扫描明细 ---")
    if not results:
        print("暂无数据")
    else:
        for item_domain, subdomain, item_tool, created_at in results:
            print(
                f"- 域名: {item_domain} | 子域名: {subdomain} | "
                f"工具: {item_tool} | 时间: {created_at}"
            )


def show_view(domain=None, tool_name=None):
    store = ScanResultStore()
    print_view_results(store, domain=domain, tool_name=tool_name)


def print_alive_results(store, domain=None):
    overview = store.get_alive_overview(domain=domain)
    results = store.get_alive_results(domain=domain)

    print("--- 存活目标查看 ---")
    print(f"筛选域名: {domain or '全部'}")

    print("\n--- 存活概览 ---")
    if not overview:
        print("暂无数据")
    else:
        for item_domain, item_tool, total_count, last_scan_at in overview:
            print(
                f"- 域名: {item_domain} | 工具: {item_tool} | "
                f"存活数: {total_count} | 最近时间: {last_scan_at}"
            )

    print("\n--- 存活明细 ---")
    if not results:
        print("暂无数据")
    else:
        for item_domain, hostname, item_tool, created_at in results:
            print(
                f"- 域名: {item_domain} | 主机: {hostname} | "
                f"工具: {item_tool} | 时间: {created_at}"
            )


def show_alive(domain=None):
    store = ScanResultStore()
    print_alive_results(store, domain=domain)
