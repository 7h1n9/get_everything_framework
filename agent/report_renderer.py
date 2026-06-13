from typing import Any, Dict, List


def _join_tools(task: Dict[str, Any]) -> str:
    steps = task.get("completed_steps", [])
    tools = []
    for item in steps:
        tool_name = item.get("step", {}).get("tool")
        if tool_name and tool_name not in tools:
            tools.append(tool_name)
    return ", ".join(tools) if tools else "-"


def _step_input_source(step: Dict[str, Any]) -> str:
    args = step.get("args", {})
    if args.get("source") == "existing_subdomains":
        return "数据库已有子域名"
    if step.get("tool") == "view_results":
        return "数据库"
    if step.get("tool") == "summary":
        return "数据库"
    if args.get("file_path"):
        return "上传文件"
    return args.get("domain") or "用户输入"


def _step_output_count(result: Dict[str, Any]) -> str:
    for key in ("total", "count", "target_count", "total_found"):
        value = result.get(key)
        if value is not None:
            return str(value)
    items = result.get("items")
    if isinstance(items, list):
        return str(len(items))
    return "-"


def _result_storage(task: Dict[str, Any]) -> Dict[str, str]:
    for item in task.get("completed_steps", []):
        storage = item.get("result", {}).get("storage") or {}
        if storage:
            return {
                "path": storage.get("path", "-"),
                "tables": " / ".join(storage.get("tables", [])) or "-",
            }
    return {"path": "-", "tables": "-"}


def _alive_rows(context_results: Dict[str, Any]) -> List[str]:
    rows = []
    for item in context_results.get("httpx_fingerprints", [])[:20]:
        tech = ", ".join(item.get("tech") or []) or "-"
        rows.append(
            f"| {item.get('url') or '-'} | {item.get('status_code') or '-'} | {item.get('title') or '-'} | {tech} |"
        )
    if not rows:
        rows.append("| - | - | - | - |")
    return rows


def _priority_rows(context_results: Dict[str, Any]) -> List[str]:
    rows = []
    for item in context_results.get("alive_urls", [])[:10]:
        rows.append(f"| 中 | {item.get('url') or item.get('hostname') or '-'} | 存活探测命中 |")
    if not rows:
        rows.append("| - | - | - |")
    return rows


def render_final_report(task: Dict[str, Any]) -> str:
    storage = _result_storage(task)
    context_results = task.get("context_results", {})
    completed_steps = task.get("completed_steps", [])
    active = any(item.get("step", {}).get("tool") not in {"summary", "view_results", "alive_results", "export_results"} for item in completed_steps)
    lines = [
        "# 信息收集任务报告",
        "",
        "## 1. 任务概况",
        "",
        f"- 目标：{task.get('target') or '-'}",
        f"- 执行模式：{task.get('mode') or '-'}",
        f"- 是否主动探测：{'是' if active else '否'}",
        f"- 用户确认：{'是' if task.get('requires_confirmation') else '否'}",
        f"- 工具链：{_join_tools(task)}",
        f"- 并发策略：保守默认限制",
        "",
        "## 2. 执行过程",
        "",
        "| 步骤 | 工具 | 输入来源 | 输出数量 | 状态 |",
        "|---|---|---|---|---|",
    ]
    if completed_steps:
        for index, item in enumerate(completed_steps, start=1):
            step = item.get("step", {})
            result = item.get("result", {})
            lines.append(
                f"| {index} | {step.get('tool') or '-'} | {_step_input_source(step)} | {_step_output_count(result)} | {'完成' if result.get('ok') else '失败'} |"
            )
    else:
        lines.append("| - | - | - | - | - |")

    lines.extend(
        [
            "",
            "## 3. 结果保存",
            "",
            f"- SQLite 数据库：{storage['path']}",
            f"- 相关表：{storage['tables']}",
            "- 原始输出文件：工具默认输出目录或数据库原始记录",
            f"- 导出文件：{', '.join(context_results.get('exports', [])) if context_results.get('exports') else '-'}",
            "",
            "## 4. 关键结果",
            "",
            "### 存活目标",
            "",
            "| URL | 状态码 | 标题 | 技术栈 |",
            "|---|---:|---|---|",
        ]
    )
    lines.extend(_alive_rows(context_results))
    lines.extend(
        [
            "",
            "## 5. 优先关注目标",
            "",
            "| 优先级 | 目标 | 判断依据 |",
            "|---|---|---|",
        ]
    )
    lines.extend(_priority_rows(context_results))
    lines.extend(
        [
            "",
            "## 6. 风险与边界",
            "",
            "- 本次是否执行漏洞验证：否",
            "- 本次是否执行目录爆破：否",
            "- 本次是否执行端口扫描：否",
            "- 并发是否受限：是",
            "",
            "## 7. 下一步建议",
            "",
            "1. 先复核高优先级存活入口与授权范围。",
            "2. 如需扩展主动探测，再逐项确认工具和范围。",
            "3. 如需交付，可导出已有结果为 CSV 或 JSON。",
        ]
    )
    return "\n".join(lines)
