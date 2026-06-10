import os
import time

from flask import Flask, jsonify, render_template, request, session
from werkzeug.utils import secure_filename

from agent import handle_agent_message
from config import ALLOWED_UPLOAD_EXTENSIONS, MAX_UPLOAD_SIZE, UPLOAD_DIR
from exporter import export_results, gather_export_rows
from modules import build_runner, get_supported_runners
from storage import ScanResultStore
from target_parser import parse_targets_file, save_normalized_targets
from tool_runner import load_tools, run_single_tool, run_tools


app = Flask(__name__, template_folder="web/templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE


def normalize_value(value):
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def normalize_domain(value):
    return normalize_value(value)


def _to_ui_history(history):
    if not history:
        return []
    return [item for item in history if item.get("role") in {"user", "assistant"}]


def build_page_context(
    store,
    domain=None,
    scan_message=None,
    scan_error=None,
    scan_report=None,
    chat_error=None,
):
    summary = store.get_global_summary()
    domain_results = store.get_results_by_domain(domain) if domain else []
    domain_summary = store.get_domain_summary(domain) if domain else None
    raw_history = session.get("agent_history", [])
    raw_steps = session.get("agent_steps", [])

    return {
        "current_domain": domain or "",
        "scan_message": scan_message,
        "scan_error": scan_error,
        "scan_report": scan_report,
        "chat_error": chat_error,
        "summary": summary,
        "domain_summary": domain_summary,
        "domain_results": domain_results,
        "agent_history": _to_ui_history(raw_history),
        "agent_steps": raw_steps,
        "pending_plan": session.get("pending_plan"),
        "uploaded_targets": session.get("uploaded_targets"),
        "agent_context": session.get("agent_context"),
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
    chat_error = None

    if request.method == "POST":
        action = request.form.get("action", "scan")

        if action == "scan":
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

        elif action == "chat":
            user_message = request.form.get("agent_message", "").strip()
            if not user_message:
                chat_error = "请输入聊天内容。"
            else:
                history = session.get("agent_history", [])
                pending_plan = session.get("pending_plan")
                uploaded_context = session.get("uploaded_targets")
                context_state = session.get("agent_context")
                try:
                    agent_reply = handle_agent_message(
                        user_message,
                        store=store,
                        history=history,
                        pending_plan=pending_plan,
                        uploaded_context=uploaded_context,
                        context_state=context_state,
                    )
                    if agent_reply.get("focus_domain"):
                        domain = agent_reply["focus_domain"]

                    session["agent_history"] = agent_reply.get("conversation_history", history)[-40:]
                    session["pending_plan"] = agent_reply.get("pending_plan")
                    session["agent_context"] = agent_reply.get("context_state", context_state)

                    steps = agent_reply.get("steps", [])
                    all_steps = session.get("agent_steps", [])
                    all_steps.extend(steps)
                    session["agent_steps"] = all_steps[-50:]
                except Exception as exc:
                    chat_error = f"处理失败: {exc}"
        else:
            scan_error = f"未知操作: {action}"

    context = build_page_context(
        store,
        domain=domain,
        scan_message=scan_message,
        scan_error=scan_error,
        scan_report=scan_report,
        chat_error=chat_error,
    )
    return render_template("index.html", **context)


@app.route("/api/tools", methods=["GET"])
def api_tools():
    store = ScanResultStore()
    database_by_tool = {item["tool_name"]: item for item in store.get_tool_databases()}
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
    file_path = payload.get("file_path")

    if isinstance(tools, str):
        tools = [tools]

    if not domain and not file_path:
        return jsonify({"error": "domain or file_path is required"}), 400

    try:
        selected_tools = load_tools(tools)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    store = ScanResultStore()
    report = run_tools(domain=domain, file_path=file_path, tools=selected_tools, store=store)
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
    tool_name = normalize_value(request.args.get("tool"))
    category = normalize_value(request.args.get("category"))
    limit = request.args.get("limit", "200")

    try:
        limit = max(1, min(int(limit), 1000))
    except ValueError:
        limit = 200

    rows = gather_export_rows(store, domain=domain, tool_name=tool_name, category=category, limit=limit)
    return jsonify({"results": rows})


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


@app.route("/api/upload-targets", methods=["POST"])
def api_upload_targets():
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "error": "未上传文件"}), 400

    filename = secure_filename(file.filename or "")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return jsonify({"ok": False, "error": "仅支持 .txt / .csv 文件"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ts = int(time.time())
    raw_path = os.path.join(UPLOAD_DIR, f"{ts}_{filename}")
    normalized_path = os.path.join(UPLOAD_DIR, f"{ts}_normalized_targets.txt")
    file.save(raw_path)

    targets = parse_targets_file(raw_path)
    save_normalized_targets(targets, normalized_path)

    uploaded_context = {
        "original_path": raw_path,
        "file_path": normalized_path,
        "target_count": len(targets),
        "targets_preview": targets[:20],
        "label": filename,
    }
    session["uploaded_targets"] = uploaded_context
    session["last_uploaded_file"] = {
        "file_path": normalized_path,
        "target_count": len(targets),
        "targets_preview": targets[:20],
    }

    return jsonify(
        {
            "ok": True,
            "file_path": normalized_path,
            "target_count": len(targets),
            "targets_preview": targets[:20],
        }
    )


@app.route("/api/export", methods=["GET"])
def api_export():
    store = ScanResultStore()
    domain = normalize_domain(request.args.get("domain"))
    tool_name = normalize_value(request.args.get("tool"))
    category = normalize_value(request.args.get("category"))
    fmt = (request.args.get("format") or "csv").lower()
    limit = request.args.get("limit", "1000")

    try:
        limit = max(1, min(int(limit), 5000))
    except ValueError:
        limit = 1000

    rows = gather_export_rows(
        store,
        domain=domain,
        tool_name=tool_name,
        category=category,
        limit=limit,
    )
    path = export_results(rows, fmt=fmt, prefix=domain or "all_results")

    return jsonify(
        {
            "ok": True,
            "path": path,
            "count": len(rows),
            "format": fmt,
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
