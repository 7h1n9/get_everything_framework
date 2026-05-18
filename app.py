from flask import Flask, jsonify, render_template, request

from modules import build_runner, get_supported_runners
from storage import ScanResultStore
from tool_runner import load_tools, run_single_tool, run_tools


app = Flask(__name__, template_folder="web/templates")


def normalize_domain(value):
    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None

    return normalized


def build_page_context(store, domain=None, scan_message=None, scan_error=None, scan_report=None):
    summary = store.get_global_summary()
    domain_results = store.get_results_by_domain(domain) if domain else []
    domain_summary = store.get_domain_summary(domain) if domain else None

    return {
        "current_domain": domain or "",
        "scan_message": scan_message,
        "scan_error": scan_error,
        "scan_report": scan_report,
        "summary": summary,
        "domain_summary": domain_summary,
        "domain_results": domain_results,
    }


def build_tool_payload(tool_name):
    runner = build_runner(tool_name)
    return {
        "name": tool_name,
        "category": getattr(runner, "category", "subdomain"),
    }


@app.route("/", methods=["GET", "POST"])
def index():
    store = ScanResultStore()
    domain = normalize_domain(request.values.get("domain"))
    scan_message = None
    scan_error = None
    scan_report = None

    if request.method == "POST":
        if not domain:
            scan_error = "请输入要扫描的域名。"
        else:
            try:
                scan_report = run_tools(domain=domain, tools=["subfinder"], store=store)
                scan_message = f"{domain} 扫描完成。"
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
                scan_error = f"扫描未完成，退出码: {code}"
            except Exception as exc:
                scan_error = f"扫描失败: {exc}"

    context = build_page_context(
        store,
        domain=domain,
        scan_message=scan_message,
        scan_error=scan_error,
        scan_report=scan_report,
    )
    return render_template("index.html", **context)


@app.route("/api/tools", methods=["GET"])
def api_tools():
    store = ScanResultStore()
    database_by_tool = {
        item["tool_name"]: item
        for item in store.get_tool_databases()
    }
    return jsonify(
        {
            "tools": [
                {
                    **build_tool_payload(tool_name),
                    "database": database_by_tool.get(tool_name),
                }
                for tool_name in get_supported_runners()
            ]
        }
    )


@app.route("/api/databases", methods=["GET"])
def api_databases():
    store = ScanResultStore()
    return jsonify({"databases": store.get_tool_databases()})


@app.route("/api/run", methods=["POST"])
def api_run():
    payload = request.get_json(silent=True) or {}
    domain = normalize_domain(payload.get("domain"))
    tools = payload.get("tools") or payload.get("tool")

    if isinstance(tools, str):
        tools = [tools]

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    try:
        selected_tools = load_tools(tools)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    store = ScanResultStore()
    report = run_tools(domain=domain, tools=selected_tools, store=store)
    return jsonify(report)


@app.route("/api/tool/<tool_name>/run", methods=["POST"])
def api_run_single_tool(tool_name):
    payload = request.get_json(silent=True) or {}
    domain = normalize_domain(payload.get("domain"))

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    try:
        load_tools([tool_name])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(run_single_tool(tool_name, domain, store=ScanResultStore()))


@app.route("/api/results", methods=["GET"])
def api_results():
    store = ScanResultStore()
    domain = normalize_domain(request.args.get("domain"))
    tool_name = normalize_domain(request.args.get("tool"))
    category = normalize_domain(request.args.get("category"))
    limit = request.args.get("limit", "200")

    try:
        limit = max(1, min(int(limit), 1000))
    except ValueError:
        limit = 200

    subdomain_rows = []
    if category in {None, "", "subdomain"}:
        subdomain_rows = [
            {
                "domain": row_domain,
                "tool_name": row_tool,
                "category": "subdomain",
                "value": subdomain,
                "created_at": created_at,
            }
            for row_domain, subdomain, row_tool, created_at in store.get_view_results(
                domain=domain,
                tool_name=tool_name,
            )
        ][:limit]

    generic_rows = [
        {
            "domain": row_domain,
            "tool_name": row_tool,
            "category": row_category,
            "value": value,
            "created_at": created_at,
        }
        for row_domain, row_tool, row_category, value, created_at in store.get_tool_results(
            domain=domain,
            tool_name=tool_name,
            category=category if category != "subdomain" else None,
            limit=limit,
        )
    ]

    return jsonify({"results": subdomain_rows + generic_rows})


@app.route("/api/tool/<tool_name>/results", methods=["GET"])
def api_tool_results(tool_name):
    store = ScanResultStore()
    domain = normalize_domain(request.args.get("domain"))
    limit = request.args.get("limit", "200")

    try:
        limit = max(1, min(int(limit), 1000))
    except ValueError:
        limit = 200

    try:
        results = store.get_dedicated_results(tool_name, domain=domain, limit=limit)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
