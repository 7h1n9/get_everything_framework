import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from exporter import export_results, gather_export_rows
from modules.httpx import HttpxRunner
from storage import ScanResultStore, TOOL_DATABASES
from tool_runner import run_tools

from .intent import UserIntent, analyze_intent, extract_domain
from .mode_classifier import classify_mode
from .plan_state import apply_user_intervention, is_cancel, is_confirm, is_meaningful_new_intent, is_plan_modification
from .planner import AgentPlan, build_passive_plan, build_plan
from .report_renderer import render_final_report
from .system_prompt import SYSTEM_PROMPT
from .target_ranker import rank_subdomains
from .task_state import advance_task, cancel_task, current_step, init_task_state, normalize_task_state
from .tool_policy import clamp_step_args, requires_confirmation, tool_group


class AgentAction:
    RATE_LIMIT_CACHE: Dict[str, float] = {}
    DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

    def __init__(
        self,
        store: Optional[ScanResultStore] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        client: Optional[Any] = None,
        max_history_messages: int = 30,
        debug: bool = False,
        pending_plan: Optional[Dict[str, Any]] = None,
        uploaded_context: Optional[Dict[str, Any]] = None,
        context_state: Optional[Dict[str, Any]] = None,
    ):
        self.store = store or ScanResultStore()
        self.client = client
        self.max_history_messages = max(8, max_history_messages)
        self.debug = debug
        self.pending_plan = normalize_task_state(pending_plan) if pending_plan else None
        self.uploaded_context = uploaded_context or {}
        self.context = {
            "mode": None,
            "org": None,
            "target": None,
            "last_target": None,
            "last_menu": None,
            "strategy_context": None,
            "context_results": {
                "subdomains": [],
                "alive_urls": [],
                "httpx_fingerprints": [],
                "ports": [],
                "content_paths": [],
                "exports": [],
            },
        }
        if context_state:
            for key, value in context_state.items():
                if key == "context_results" and isinstance(value, dict):
                    self.context["context_results"].update(value)
                elif key in self.context:
                    self.context[key] = value
        self.steps: List[Dict[str, Any]] = []
        self.min_tool_interval_sec = int(os.getenv("AGENT_TOOL_MIN_INTERVAL_SEC", "8"))
        self.blocked_domains = self._load_set_env("AGENT_BLOCKED_DOMAINS", defaults={"localhost", "localdomain"})
        self.blocked_suffixes = self._load_set_env("AGENT_BLOCKED_SUFFIXES", defaults={".local", ".lan", ".internal"})
        self.allowed_suffixes = self._load_set_env("AGENT_ALLOWED_SUFFIXES", defaults=set())
        self.conversation_history = self._normalize_history(conversation_history)

        self.available_tools = {
            "subdomain": {"handler": self._tool_subdomain},
            "summary": {"handler": self._tool_summary},
            "view_results": {"handler": self._tool_view_results},
            "alive_results": {"handler": self._tool_alive_results},
            "httpx": {"handler": self._tool_httpx},
            "export_results": {"handler": self._tool_export_results},
        }

    def run(self, user_message: str) -> Dict[str, Any]:
        self.steps = []
        text = (user_message or "").strip()
        if not text:
            return self._build_response("请输入有效问题。")

        self._append_message("user", text)
        text = self._resolve_menu_input(text) or text

        if self.pending_plan:
            handled = self._handle_pending_plan(text)
            if handled:
                return handled

        intent = analyze_intent(
            text,
            has_uploaded_file=bool(self.uploaded_context.get("file_path")),
            context_state=self.context,
        )
        self._update_context_from_intent(intent)
        mode = classify_mode(intent)
        self.context["mode"] = "passive_only" if intent.passive_only else ("task" if mode == "task" else self.context.get("mode"))

        if intent.intent_type == "cancel_plan":
            return self._handle_cancel_without_pending()

        if intent.intent_type == "set_target":
            return self._handle_set_target(intent)

        if intent.intent_type == "view_existing_results":
            return self._handle_view_existing_results(intent)

        if intent.intent_type == "analyze_existing_subdomains":
            return self._handle_analyze_existing_subdomains(intent)

        if mode == "chat":
            return self._handle_chat_intent(intent)

        if intent.intent_type in {"probe_existing_subdomains", "web_probe", "subdomain_scan"} and not intent.target:
            return self._need_target_response()

        plan = build_plan(intent, self.uploaded_context)
        if self.context.get("mode") == "passive_only" and intent.intent_type == "strategy_only" and intent.target:
            plan = build_passive_plan(intent.target)

        if not plan:
            return self._build_chat_response("我没有识别到明确任务。你可以继续说明目标、查看已有结果，或要求生成执行计划。")

        if not plan.target or not plan.steps:
            return self._build_chat_response(self._format_strategy_only_message(plan, intent), plan_status="strategy_only")

        task = init_task_state(plan.to_dict())
        task["mode"] = "task"
        task["context_results"] = self.context.get("context_results", {})
        self.pending_plan = task

        if plan.requires_confirmation:
            message = self._format_pending_plan_message(task, intent)
            self._append_message("assistant", message)
            return self._build_response(message, focus_domain=plan.target, pending_plan=self.pending_plan, plan_status="awaiting_confirmation")

        return self._execute_next_step(task, user_message=text)

    def _handle_pending_plan(self, text: str) -> Optional[Dict[str, Any]]:
        if is_cancel(text):
            self.pending_plan = cancel_task(self.pending_plan)
            return self._cancel_pending_plan()

        if is_confirm(text):
            return self._execute_next_step(self.pending_plan, user_message=text)

        if is_plan_modification(text):
            self.pending_plan = normalize_task_state(apply_user_intervention(self.pending_plan, text))
            message = self._format_pending_plan_message(self.pending_plan)
            self._append_message("assistant", message)
            return self._build_response(message, focus_domain=self.pending_plan.get("target"), pending_plan=self.pending_plan, plan_status="awaiting_confirmation")

        new_intent = analyze_intent(
            text,
            has_uploaded_file=bool(self.uploaded_context.get("file_path")),
            context_state=self.context,
        )
        if is_meaningful_new_intent(new_intent):
            if new_intent.intent_type == "view_existing_results":
                self.pending_plan = None
                return self._handle_view_existing_results(new_intent)
            if new_intent.intent_type == "analyze_existing_subdomains":
                self.pending_plan = None
                return self._handle_analyze_existing_subdomains(new_intent)
            if new_intent.intent_type == "set_target":
                self.pending_plan = None
                return self._handle_set_target(new_intent)
            new_plan = build_plan(new_intent, self.uploaded_context)
            if new_plan:
                old_plan = self.pending_plan
                self.pending_plan = init_task_state(new_plan.to_dict())
                self.pending_plan["mode"] = "task"
                self.pending_plan["context_results"] = self.context.get("context_results", {})
                replace_message = self._render_replace_plan_message(old_plan, self.pending_plan)
                detail_message = self._format_pending_plan_message(self.pending_plan, new_intent)
                message = f"{replace_message}\n\n{detail_message}"
                self._append_message("assistant", message)
                return self._build_response(message, focus_domain=self.pending_plan.get("target"), pending_plan=self.pending_plan, plan_status="awaiting_confirmation")

        message = self._render_pending_plan_help(self.pending_plan)
        self._append_message("assistant", message)
        return self._build_response(message, focus_domain=self.pending_plan.get("target"), pending_plan=self.pending_plan, plan_status=self.pending_plan.get("status"))

    def _execute_next_step(self, task: Dict[str, Any], user_message: str) -> Dict[str, Any]:
        task = normalize_task_state(task)
        step = current_step(task)
        if not step:
            report = render_final_report(task)
            self.pending_plan = None
            self.context["context_results"] = task.get("context_results", self.context["context_results"])
            self._append_message("assistant", report)
            return self._build_response(report, focus_domain=task.get("target"), pending_plan=None, plan_status="completed")

        normalized_step, elevated = clamp_step_args(step)
        if elevated:
            message = "检测到你请求的并发超过默认保守限制。当前不会提升并发，请先明确二次确认更高并发参数。"
            self._append_message("assistant", message)
            return self._build_response(message, focus_domain=task.get("target"), pending_plan=task, plan_status="awaiting_confirmation")

        tool_name = normalized_step.get("tool")
        if requires_confirmation(tool_name) and task.get("status") == "awaiting_confirmation":
            task["status"] = "running"

        result = self._execute_tool(tool_name, normalized_step.get("args", {}))
        self._record_step(tool_name, normalized_step.get("args", {}), result)
        task["steps"][task["current_step_index"]] = normalized_step
        task = advance_task(task, result)
        task["context_results"] = self._merge_context_results(task.get("context_results", {}), tool_name, result)
        self.context["context_results"] = task["context_results"]

        if task.get("status") == "completed":
            report = render_final_report(task)
            self.pending_plan = None
            self._append_message("assistant", report)
            return self._build_response(report, focus_domain=task.get("target"), pending_plan=None, plan_status="completed", export_path=self._extract_export_path(task))

        if task.get("status") == "failed":
            self.pending_plan = task
            message = self._render_step_result(task, result, failed=True)
            self._append_message("assistant", message)
            return self._build_response(message, focus_domain=task.get("target"), pending_plan=self.pending_plan, plan_status="failed")

        self.pending_plan = task
        message = self._render_step_result(task, result, failed=False)
        self._append_message("assistant", message)
        return self._build_response(message, focus_domain=task.get("target"), pending_plan=self.pending_plan, plan_status=task.get("status"))

    def _execute_tool(self, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        tool = self.available_tools.get(action)
        if not tool:
            return self._attach_storage_info({"ok": False, "error": f"未知工具: {action}", "tool": action}, action, args)
        try:
            result = tool["handler"](args)
        except Exception as exc:
            result = {"ok": False, "error": str(exc), "tool": action}
        return self._attach_storage_info(result, action, args)

    def _tool_subdomain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        scan_tool = str(args.get("tool", "subfinder")).strip().lower()
        file_path = str(args.get("file_path", "")).strip()
        domain = str(args.get("domain", "")).strip().lower() or None
        if scan_tool not in {"amass", "subfinder", "dnsx"}:
            raise ValueError("subdomain 仅支持 amass/subfinder/dnsx")
        if file_path:
            report = run_tools(file_path=file_path, tools=[scan_tool], store=self.store)
            return {"ok": True, "tool": "subdomain", "scan_tool": scan_tool, "file_path": file_path, "target_count": len(report.get("targets", [])), "total_found": report["total_found"], "total_inserted": report["total_inserted"]}
        if not domain:
            raise ValueError("缺少 domain 或 file_path 参数")
        self._validate_domain(domain)
        self._enforce_rate_limit("subdomain", domain)
        report = run_tools(domain=domain, tools=[scan_tool], store=self.store)
        return {"ok": True, "tool": "subdomain", "domain": domain, "scan_tool": scan_tool, "total_found": report["total_found"], "total_inserted": report["total_inserted"]}

    def _tool_summary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(args.get("domain", "")).strip().lower()
        if domain:
            self._validate_domain(domain)
            return {"ok": True, "tool": "summary", "domain": domain, "data": self.store.get_domain_summary(domain)}
        return {"ok": True, "tool": "summary", "domain": None, "data": self.store.get_global_summary()}

    def _tool_view_results(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        limit = self._safe_limit(args.get("limit"), default=50)
        tool_name = str(args.get("tool", "")).strip().lower() or None
        rows = self.store.get_view_results(domain=domain, tool_name=tool_name)
        items = [{"domain": row_domain, "subdomain": subdomain, "tool_name": row_tool, "created_at": created_at} for row_domain, subdomain, row_tool, created_at in rows[:limit]]
        return {"ok": True, "tool": "view_results", "domain": domain, "filter_tool": tool_name, "total": len(rows), "items": items}

    def _tool_alive_results(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        limit = self._safe_limit(args.get("limit"), default=50)
        rows = self.store.get_alive_results(domain=domain)
        items = [{"domain": row_domain, "hostname": hostname, "tool_name": tool_name, "created_at": created_at} for row_domain, hostname, tool_name, created_at in rows[:limit]]
        return {"ok": True, "tool": "alive_results", "domain": domain, "total": len(rows), "items": items}

    def _tool_httpx(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        source = str(args.get("source", "stored_subdomains")).strip()
        tech_detect = bool(args.get("tech_detect"))
        self._validate_domain(domain)
        self._enforce_rate_limit("httpx", domain)
        candidates: List[str] = []
        if source == "existing_subdomains":
            rows = self.store.get_results_by_domain(domain)
            candidates = [subdomain for subdomain, _, _ in rows]
            if not candidates:
                raise RuntimeError(f"数据库中没有 {domain} 的已有子域名结果，无法按 existing_subdomains 执行探测")
        elif source == "direct_input":
            candidates = [domain]
        runner = HttpxRunner()
        if "threads" in args:
            runner.config["threads"] = int(args["threads"])
        items = runner.run_scan(domain=domain, candidates=candidates or None, tech_detect=tech_detect)
        self._save_httpx_metadata(domain, items)
        return {"ok": True, "tool": "httpx", "domain": domain, "source": source, "target_count": len(candidates) if candidates else 1, "total": len(items), "items": items, "tech_detect": tech_detect}

    def _tool_export_results(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(args.get("domain", "")).strip().lower() or None
        fmt = str(args.get("format", "csv")).strip().lower() or "csv"
        category = str(args.get("category", "")).strip().lower() or None
        tool_name = str(args.get("tool_name", "")).strip().lower() or None
        rows = gather_export_rows(self.store, domain=domain, tool_name=tool_name, category=category, limit=5000)
        path = export_results(rows, fmt=fmt, prefix=domain or "all_results")
        return {"ok": True, "tool": "export_results", "domain": domain, "count": len(rows), "format": fmt, "path": path}

    def _handle_set_target(self, intent: UserIntent) -> Dict[str, Any]:
        if not intent.target:
            return self._build_chat_response("没有识别到要设置的目标域名。", plan_status="need_target")
        self.context["target"] = intent.target
        self.context["last_target"] = intent.target
        message = (
            f"已将目标设置为 `{intent.target}`。\n"
            "你可以继续回复：\n"
            "- 查看已有结果\n"
            "- 导出为 CSV\n"
            "- 只做被动信息收集\n"
            "- 存活探测"
        )
        self._set_last_menu({"1": "查看已有结果", "2": "导出为 CSV", "3": "只做被动信息收集", "4": "存活探测"})
        self._append_message("assistant", message)
        return self._build_response(message, focus_domain=intent.target, plan_status="target_set")

    def _handle_view_existing_results(self, intent: UserIntent) -> Dict[str, Any]:
        if not intent.target:
            return self._need_target_response()
        summary_result = self._tool_summary({"domain": intent.target})
        view_result = self._tool_view_results({"domain": intent.target, "limit": 20})
        self._record_step("summary", {"domain": intent.target}, summary_result)
        self._record_step("view_results", {"domain": intent.target, "limit": 20}, view_result)
        self.context["context_results"] = self._merge_context_results(self.context["context_results"], "view_results", view_result)
        message = self._render_existing_results_message(intent.target, summary_result, view_result)
        self._set_last_menu({"1": "查看已有结果", "2": "导出为 CSV", "3": "基于这些结果做优先级分析", "4": "存活探测"})
        self._append_message("assistant", message)
        return self._build_response(message, focus_domain=intent.target, plan_status="completed_view_results")

    def _handle_analyze_existing_subdomains(self, intent: UserIntent) -> Dict[str, Any]:
        if not intent.target:
            return self._need_target_response()
        result = self._tool_view_results({"domain": intent.target, "tool": "subfinder", "limit": 200})
        self._record_step("view_results", {"domain": intent.target, "tool": "subfinder", "limit": 200}, result)
        ranked = rank_subdomains(result.get("items", []), top_n=20)
        message = self._render_src_target_advice(intent.target, result, ranked)
        self._set_last_menu({"1": "导出为 CSV", "2": "查看已有结果", "3": "只做被动信息收集", "4": "存活探测"})
        self._append_message("assistant", message)
        return self._build_response(message, focus_domain=intent.target, plan_status="completed_readonly_analysis")

    def _handle_chat_intent(self, intent: UserIntent) -> Dict[str, Any]:
        if intent.intent_type == "strategy_only":
            plan = build_passive_plan(intent.target) if intent.passive_only else build_plan(intent, self.uploaded_context)
            return self._build_chat_response(self._format_strategy_only_message(plan, intent), focus_domain=intent.target, plan_status="strategy_only")
        if intent.intent_type == "unknown_chat":
            return self._build_chat_response("当前是聊天模式。我可以帮你梳理信息收集路线、查看已有结果，或在你确认后生成主动探测计划。", focus_domain=intent.target)
        return self._build_chat_response("当前请求更像聊天问题。如果你要执行任务，请明确目标和动作。", focus_domain=intent.target)

    def _need_target_response(self) -> Dict[str, Any]:
        message = "我识别到你要执行任务，但当前还缺少目标域名。请补充域名，例如 `peizheng.edu.cn`。"
        self._append_message("assistant", message)
        return self._build_response(message, plan_status="need_target")

    def _format_pending_plan_message(self, task: Dict[str, Any], intent: Optional[UserIntent] = None) -> str:
        target = task.get("target") or "未指定目标"
        step = current_step(task)
        lines = []
        if intent and intent.intent_type == "probe_existing_subdomains":
            lines.extend(
                [
                    f"我识别到你要基于 {target} 已收集的子域名做进一步处理，不会重新执行子域名收集。",
                    "",
                    f"目标：{target}",
                    "数据来源：数据库中已有子域名结果",
                    "任务类型：主动 Web 探测",
                    f"技术栈识别：{'开启' if intent.need_tech_stack else '关闭'}",
                    "",
                    "建议执行步骤：",
                    "1. httpx：读取已有子域名并进行存活探测",
                    f"2. httpx：{'识别状态码、标题、Web 服务和技术栈信息' if intent.need_tech_stack else '识别状态码、标题和 Web 服务信息'}",
                    "3. summary：汇总结果与保存位置",
                    "",
                    "这会对已收集子域名发起 HTTP/HTTPS 请求。请确认是否执行。",
                    "",
                    "你可以回复：",
                    "- 确认执行",
                    "- 只探活，不识别技术栈",
                    "- 只看已有存活结果",
                    "- 导出已有结果为 CSV",
                    "- 取消",
                ]
            )
            return "\n".join(lines)

        lines.extend(
            [
                f"已生成待执行计划：{task.get('strategy')}",
                f"目标：{target}",
                f"下一步：{step.get('description') if step else '无'}",
                f"工具分组：{tool_group(step.get('tool')) if step else '-'}",
                "",
                "你可以回复：",
                "- 确认执行",
                "- 取消",
                "- 查看已有结果",
                "- 导出为 CSV",
            ]
        )
        return "\n".join(lines)

    def _render_step_result(self, task: Dict[str, Any], result: Dict[str, Any], failed: bool = False) -> str:
        step = task.get("completed_steps", [])[-1]["step"]
        round_no = task.get("round", 0)
        lines = [
            f"第 {round_no} 轮迭代",
            f"正在调用工具：{step.get('tool')}",
            f"工具调用参数：{json.dumps(step.get('args', {}), ensure_ascii=False)}",
            f"工具执行状态：{'失败' if failed else '完成'}",
            f"执行结果：{self._result_brief(result)}",
        ]
        next_step = current_step(task)
        if not failed and next_step:
            lines.extend(
                [
                    "",
                    f"下一步建议：{next_step.get('description')}",
                    "如需继续，请回复：确认执行",
                ]
            )
        return "\n".join(lines)

    def _result_brief(self, result: Dict[str, Any]) -> str:
        if not result.get("ok"):
            return result.get("error", "执行失败")
        if result.get("tool") == "httpx":
            return f"对 {result.get('target_count', 0)} 个目标发起请求，命中 {result.get('total', 0)} 个存活结果"
        if result.get("tool") == "subdomain":
            return f"发现 {result.get('total_found', 0)} 条子域名，新增入库 {result.get('total_inserted', 0)} 条"
        if result.get("tool") == "export_results":
            return f"已导出 {result.get('count', 0)} 条记录到 {result.get('path')}"
        if result.get("tool") == "summary":
            return "已读取目标汇总信息"
        if result.get("tool") == "view_results":
            return f"已读取 {result.get('total', 0)} 条已有结果"
        return "已完成"

    def _render_replace_plan_message(self, old_plan: Dict[str, Any], new_plan: Dict[str, Any]) -> str:
        old_target = old_plan.get("target") or "未指定目标"
        new_target = new_plan.get("target") or "未指定目标"
        return (
            f"当前有一个待确认计划：{old_target}\n"
            f"检测到你提出了新的明确任务，已替换为新计划：{new_target}\n"
            f"新计划：{new_plan.get('strategy')}\n"
            "如需执行，请回复：确认执行"
        )

    def _render_pending_plan_help(self, pending_plan: Dict[str, Any]) -> str:
        return (
            f"当前还有一个待处理计划：{pending_plan.get('target') or '未指定目标'}\n"
            "你可以回复：\n"
            "- 确认执行\n"
            "- 取消\n"
            "- 只探活，不识别技术栈\n"
            "- 查看已有结果"
        )

    def _render_existing_results_message(self, domain: str, summary_result: Dict[str, Any], view_result: Dict[str, Any]) -> str:
        summary = summary_result.get("data", {}) or {}
        items = view_result.get("items", [])
        lines = [
            f"已读取 `{domain}` 的已有结果。",
            f"子域名总数：{summary.get('total_subdomains', view_result.get('total', 0))}",
            f"最近扫描时间：{summary.get('last_scan_at') or '未知'}",
            f"结果库：`{self.store.db_path}`",
            "",
            "前 10 条结果：",
        ]
        if items:
            for index, item in enumerate(items[:10], start=1):
                lines.append(f"{index}. {item['subdomain']} 来源={item['tool_name']}")
        else:
            lines.append("当前没有找到已有子域名结果。")
        lines.extend(["", "你可以继续回复：", "- 导出为 CSV", "- 基于这些结果做优先级分析", "- 存活探测"])
        return "\n".join(lines)

    def _render_src_target_advice(self, domain: str, result: Dict[str, Any], ranked: List[Dict[str, Any]]) -> str:
        lines = [
            "我识别到你是要基于数据库中的已有子域名结果做只读分析，不会发起新的扫描请求。",
            f"目标：{domain}",
            f"已读取结果数量：{result.get('total', 0)}",
            "",
            "建议优先关注：",
        ]
        if ranked:
            for index, item in enumerate(ranked[:10], start=1):
                reason_text = "、".join(item.get("reasons") or []) or "命名特征命中"
                lines.append(f"{index}. {item['hostname']} 分数={item['score']} 理由={reason_text}")
        else:
            lines.append("当前没有足够结果可做排序。")
        lines.extend(["", "你可以继续回复：", "- 导出为 CSV", "- 查看已有结果", "- 存活探测"])
        return "\n".join(lines)

    def _format_strategy_only_message(self, plan: Optional[AgentPlan], intent: UserIntent) -> str:
        if plan and plan.message:
            return plan.message
        if plan and plan.strategy:
            return plan.strategy
        if intent.passive_only and intent.target:
            return build_passive_plan(intent.target).strategy
        return "当前更适合先做策略沟通。你可以提供目标域名，或要求查看已有结果。"

    def _build_chat_response(self, message: str, focus_domain: Optional[str] = None, plan_status: Optional[str] = None) -> Dict[str, Any]:
        self._append_message("assistant", message)
        return self._build_response(message, focus_domain=focus_domain, pending_plan=None, plan_status=plan_status)

    def _build_response(
        self,
        message: str,
        focus_domain: Optional[str] = None,
        pending_plan: Optional[Dict[str, Any]] = None,
        plan_status: Optional[str] = None,
        export_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "message": message,
            "focus_domain": focus_domain,
            "conversation_history": self.conversation_history,
            "steps": self.steps,
            "pending_plan": pending_plan,
            "plan_status": plan_status,
            "export_path": export_path,
            "context_state": self.context,
        }

    def _record_step(self, action: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        self.steps.append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "action": action, "args": args, "result": result})

    def _merge_context_results(self, existing: Dict[str, Any], tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(existing or {})
        merged.setdefault("subdomains", [])
        merged.setdefault("alive_urls", [])
        merged.setdefault("httpx_fingerprints", [])
        merged.setdefault("ports", [])
        merged.setdefault("content_paths", [])
        merged.setdefault("exports", [])
        if tool_name == "view_results":
            merged["subdomains"] = self._dedupe_records(merged["subdomains"] + result.get("items", []), ("subdomain",))
        if tool_name == "subdomain" and result.get("domain"):
            rows = self.store.get_results_by_domain(result["domain"])
            merged["subdomains"] = self._dedupe_records(
                merged["subdomains"] + [{"subdomain": subdomain, "tool_name": row_tool, "created_at": created_at} for subdomain, row_tool, created_at in rows],
                ("subdomain",),
            )
        if tool_name == "httpx":
            merged["httpx_fingerprints"] = self._dedupe_records(merged["httpx_fingerprints"] + result.get("items", []), ("url",))
            merged["alive_urls"] = self._dedupe_records(
                merged["alive_urls"] + [{"url": item.get("url"), "hostname": item.get("input"), "status_code": item.get("status_code")} for item in result.get("items", [])],
                ("url",),
            )
        if tool_name == "export_results" and result.get("path"):
            merged["exports"] = self._dedupe_list(merged["exports"] + [result["path"]])
        return merged

    def _dedupe_records(self, values: List[Dict[str, Any]], keys: tuple) -> List[Dict[str, Any]]:
        seen = set()
        items = []
        for value in values:
            marker = tuple(value.get(key) for key in keys)
            if marker in seen:
                continue
            seen.add(marker)
            items.append(value)
        return items

    def _normalize_history(self, history: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
        normalized: List[Dict[str, str]] = []
        if history:
            for item in history:
                role = (item or {}).get("role")
                content = (item or {}).get("content", "")
                if role in {"system", "user", "assistant"} and isinstance(content, str):
                    normalized.append({"role": role, "content": content})
        if not normalized or normalized[0].get("role") != "system":
            normalized = [{"role": "system", "content": SYSTEM_PROMPT}] + normalized
        else:
            normalized[0] = {"role": "system", "content": SYSTEM_PROMPT}
        return self._trim_history(normalized)

    def _append_message(self, role: str, content: str) -> None:
        self.conversation_history.append({"role": role, "content": content})
        self.conversation_history = self._trim_history(self.conversation_history)

    def _trim_history(self, history: List[Dict[str, str]]) -> List[Dict[str, str]]:
        if len(history) <= self.max_history_messages:
            return history
        return [history[0]] + history[-(self.max_history_messages - 1):]

    def _normalize_domain_arg(self, value: Any) -> str:
        domain = str(value or "").strip().lower()
        if not domain:
            raise ValueError("缺少 domain 参数")
        return domain

    def _validate_domain(self, domain: str) -> None:
        if not self.DOMAIN_PATTERN.fullmatch(domain):
            raise ValueError(f"非法域名: {domain}")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("不允许直接使用 IP 地址")
        if domain in self.blocked_domains:
            raise ValueError(f"域名被策略拦截: {domain}")
        if any(domain.endswith(suffix) for suffix in self.blocked_suffixes):
            raise ValueError(f"域名后缀被策略拦截: {domain}")
        if self.allowed_suffixes and not any(domain.endswith(suffix) for suffix in self.allowed_suffixes):
            raise ValueError(f"域名不在允许后缀范围内: {domain}")

    def _enforce_rate_limit(self, action: str, domain: str) -> None:
        key = f"{action}:{domain}"
        now = time.time()
        last = self.RATE_LIMIT_CACHE.get(key, 0.0)
        if now - last < self.min_tool_interval_sec:
            wait_sec = int(self.min_tool_interval_sec - (now - last)) + 1
            raise ValueError(f"触发频率限制，请 {wait_sec} 秒后重试: {action} {domain}")
        self.RATE_LIMIT_CACHE[key] = now

    def _safe_limit(self, value: Any, default: int = 20) -> int:
        try:
            parsed = int(value)
            return default if parsed < 1 else min(parsed, 5000)
        except Exception:
            return default

    def _load_set_env(self, env_key: str, defaults: Optional[set] = None) -> set:
        raw = os.getenv(env_key, "").strip()
        if not raw:
            return set(defaults or set())
        parsed = {item.strip().lower() for item in raw.split(",") if item.strip()}
        if defaults:
            parsed.update({item.lower() for item in defaults})
        return parsed

    def _attach_storage_info(self, result: Dict[str, Any], action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        storage_info = {"type": "sqlite", "path": self.store.db_path, "tables": []}
        if action == "subdomain":
            scan_tool = str(result.get("scan_tool") or args.get("tool") or "subfinder").lower()
            meta = TOOL_DATABASES.get(scan_tool)
            storage_info["tables"] = [meta["table"]] if meta else ["subdomain_results"]
        elif action == "httpx":
            storage_info["tables"] = ["httpx_results", "tool_results"]
        elif action == "summary":
            storage_info["tables"] = ["scan_runs", "subdomain_results", "tool_results"]
        elif action == "view_results":
            storage_info["tables"] = ["subdomain_results"]
        elif action == "alive_results":
            storage_info["tables"] = ["alive_results"]
        elif action == "export_results":
            storage_info["tables"] = ["tool_results", "subdomain_results", "alive_results"]
        result["storage"] = storage_info
        return result

    def _cancel_pending_plan(self) -> Dict[str, Any]:
        self.pending_plan = None
        message = "已取消当前待执行计划。"
        self._append_message("assistant", message)
        return self._build_response(message, plan_status="cancelled")

    def _handle_cancel_without_pending(self) -> Dict[str, Any]:
        if self.context.get("strategy_context") or self.context.get("last_menu") or self.context.get("last_target"):
            self.context["strategy_context"] = None
            self.context["last_menu"] = None
            self.context["last_target"] = None
            self.context["target"] = None
            self.context["mode"] = None
            self.context["context_results"] = {"subdomains": [], "alive_urls": [], "httpx_fingerprints": [], "ports": [], "content_paths": [], "exports": []}
            message = "已清理当前策略上下文。"
        else:
            message = "当前没有待取消的计划或策略上下文"
        self._append_message("assistant", message)
        return self._build_response(message, plan_status="cancelled")

    def _update_context_from_intent(self, intent: UserIntent) -> None:
        if intent.passive_only:
            self.context["mode"] = "passive_only"
        if intent.org_name:
            self.context["org"] = intent.org_name
        if intent.target:
            self.context["target"] = intent.target
            self.context["last_target"] = intent.target

    def _resolve_menu_input(self, text: str) -> Optional[str]:
        normalized = (text or "").strip()
        match = re.search(r"\b([1-4])\b", normalized)
        if normalized in {"1", "2", "3", "4"} or match:
            key = normalized if normalized in {"1", "2", "3", "4"} else match.group(1)
            return (self.context.get("last_menu") or {}).get(key)
        return None

    def _set_last_menu(self, mapping: Dict[str, str]) -> None:
        self.context["last_menu"] = mapping

    def _save_httpx_metadata(self, domain: str, rows: List[Dict[str, Any]]) -> None:
        serialized = [json.dumps(item, ensure_ascii=False, sort_keys=True) for item in rows]
        if serialized:
            self.store.save_tool_results(domain, "httpx", "web", serialized)

    def _extract_export_path(self, task: Dict[str, Any]) -> Optional[str]:
        for item in task.get("completed_steps", []):
            result = item.get("result", {})
            if result.get("tool") == "export_results" and result.get("path"):
                return result["path"]
        return None

    def _dedupe_list(self, values: List[str]) -> List[str]:
        seen = set()
        ordered = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered
