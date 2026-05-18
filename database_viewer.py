from storage import ScanResultStore


def print_database_list(store):
    databases = store.get_tool_database_overview()

    print("--- 工具数据库清单 ---")
    if not databases:
        print("暂无工具数据库")
        return

    for item in databases:
        print(
            f"- 工具: {item['tool_name']} | 表名: {item['table']} | "
            f"类型: {item['category']} | 字段: {item['result_column']} | "
            f"记录数: {item['total_count']} | 域名数: {item['domain_count']} | "
            f"最近时间: {item['last_scan_at'] or '暂无'}"
        )


def print_database_results(store, tool_name, domain=None, limit=100):
    databases = {
        item["tool_name"]: item
        for item in store.get_tool_databases()
    }
    database = databases.get(tool_name)
    if not database:
        print(f"[!] 不支持的工具数据库: {tool_name}")
        print("可用数据库:")
        for item in store.get_tool_databases():
            print(f"- {item['tool_name']} ({item['table']})")
        return

    results = store.get_dedicated_results(tool_name, domain=domain, limit=limit)

    print(f"--- 工具数据库查看: {tool_name} ---")
    print(f"表名: {database['table']}")
    print(f"类型: {database['category']}")
    print(f"结果字段: {database['result_column']}")
    print(f"筛选域名: {domain or '全部'}")
    print(f"显示数量: {limit}")

    print("\n--- 数据明细 ---")
    if not results:
        print("暂无数据")
        return

    for item in results:
        print(
            f"- 域名: {item['domain']} | "
            f"{item['result_column']}: {item['value']} | "
            f"时间: {item['created_at']}"
        )


def show_database_list():
    store = ScanResultStore()
    print_database_list(store)


def show_database_results(tool_name, domain=None, limit=100):
    store = ScanResultStore()
    print_database_results(store, tool_name, domain=domain, limit=limit)
