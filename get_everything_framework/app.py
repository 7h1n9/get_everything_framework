"""
资产收集工具 — 主应用入口

职责:
    - 页面路由 (/) — 渲染 Web UI + 处理表单提交
    - API Blueprint 注册 — 将 api/ 目录下的所有接口挂载到 /api 前缀
    - 辅助函数 — 规范化、上下文构建

API 接口已拆分至 api/ 目录, 便于独立维护和前端对接:

    api/__init__.py    Blueprint 注册
    api/tools.py       GET  /api/tools, /api/databases
    api/scan.py        POST /api/run, /api/tool/<name>/run
    api/results.py     GET  /api/results, /api/tool/<name>/results, /api/export
"""

from flask import Flask, render_template, request, session

from agent import handle_agent_message
from config import Config, MAX_UPLOAD_SIZE
from storage import ScanResultStore
from tool_runner import run_tools

# ── 应用工厂 ──────────────────────────────────────────────

app = Flask(__name__, template_folder="web/templates")
app.secret_key = Config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

# 注册 API Blueprint (所有接口统一挂载在 /api 下)
from api import api_bp  # noqa: E402
app.register_blueprint(api_bp)


# ── 辅助函数 ──────────────────────────────────────────────
# 字符串规范化（去空白 → 转小写 → 空值返回 None）
# 业务侧用法：normalize(value) 用于任意查询参数，normalize_domain 为语义化别名。

def normalize(value):
    """规范化通用字符串值：去空白 + 转小写，空值返回 None。"""
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


# 域名为业务专用语义别名 — 调用方阅读更清晰。
normalize_domain = normalize


def _to_ui_history(history):
    """过滤 agent 历史记录，仅保留 user/assistant 角色"""
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
    """构建页面模板所需的上下文数据"""
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


# ── 页面路由 ──────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    """Web UI 主页: 域名扫描 + AI Agent 对话"""
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


# ── 启动入口 ──────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
