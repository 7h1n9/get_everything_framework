import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from modules.httpx import HttpxRunner
from storage import ScanResultStore, TOOL_DATABASES
from tool_runner import run_tools

from .client import OpenAICompatibleClient
from .system_prompt import SYSTEM_PROMPT


class AgentAction:
    """Core agent loop for model + tool execution."""

    RATE_LIMIT_CACHE: Dict[str, float] = {}
    DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
    DATABASE_QUERY_KEYWORDS = (
        "数据库",
        "database",
        "database file",
        "db",
        "sqlite",
        "保存路径",
        "保存位置",
        "存在哪里",
        "storage path",
        "save path",
        "数据库文件",
        "db_path",
    )
    SUBDOMAIN_KEYWORDS = ("子域名", "收集", "枚举", "subdomain", "subfinder", "amass", "dnsx")
    ALIVE_KEYWORDS = ("存活", "探活", "alive", "httpx", "可达", "访问")

    def __init__(
        self,
        store: Optional[ScanResultStore] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        client: Optional[OpenAICompatibleClient] = None,
        max_steps: int = 6,
        max_history_messages: int = 30,
        debug: bool = False,
    ):
        self.store = store or ScanResultStore()
        self.client = client or OpenAICompatibleClient()
        self.max_steps = max_steps
        self.max_history_messages = max(8, max_history_messages)
        self.debug = debug
        self.steps: List[Dict[str, Any]] = []

        self.min_tool_interval_sec = int(os.getenv("AGENT_TOOL_MIN_INTERVAL_SEC", "8"))
        self.blocked_domains = self._load_set_env(
            "AGENT_BLOCKED_DOMAINS",
            defaults={"localhost", "localdomain"},
        )
        self.blocked_suffixes = self._load_set_env(
            "AGENT_BLOCKED_SUFFIXES",
            defaults={".local", ".lan", ".internal"},
        )
        self.allowed_suffixes = self._load_set_env("AGENT_ALLOWED_SUFFIXES", defaults=set())
        self.conversation_history = self._normalize_history(conversation_history)

        self.available_tools = {
            "subdomain": {
                "description": "用于收集目标域名的子域名",
                "params": {"domain": "string", "tool": "amass|subfinder|dnsx"},
                "handler": self._tool_subdomain,
            },
            "summary": {
                "description": "查看汇总信息",
                "params": {"domain": "string(可选)"},
                "handler": self._tool_summary,
            },
            "view_results": {
                "description": "查看子域名明细",
                "params": {"domain": "string", "limit": "int(可选)"},
                "handler": self._tool_view_results,
            },
            "alive_results": {
                "description": "查看存活资产明细",
                "params": {"domain": "string", "limit": "int(可选)"},
                "handler": self._tool_alive_results,
            },
            "httpx": {
                "description": "执行 httpx 探测；可直接探测传入域名本身，也可在已有子域名记录时批量探测这些子域名",
                "params": {"domain": "string"},
                "handler": self._tool_httpx,
            },
        }

    def run(self, user_message: str) -> Dict[str, Any]:
        self.steps = []
        text = (user_message or "").strip()
        if not text:
            return {
                "message": "请输入有效问题。",
                "focus_domain": None,
                "conversation_history": self.conversation_history,
                "steps": self.steps,
            }

        self._append_message("user", text)
        focus_domain = self._extract_domain(text)

        if self._is_storage_question(text) and not self._has_scan_intent(text):
            final_output = self._answer_storage_question(focus_domain)
            self._append_message("assistant", final_output)
            return {
                "message": final_output,
                "focus_domain": focus_domain,
                "conversation_history": self.conversation_history,
                "steps": self.steps,
            }

        planned_calls = self._build_plan(text, focus_domain)
        if planned_calls:
            final_output = self._run_planned_calls(text, planned_calls)
            self._append_message("assistant", final_output)
            if self.debug:
                print(f"[debug] final_output={final_output}")
            return {
                "message": final_output,
                "focus_domain": focus_domain,
                "conversation_history": self.conversation_history,
                "steps": self.steps,
            }

        for step in range(1, self.max_steps + 1):
            model_output = self.client.chat(self.conversation_history)
            self._append_message("assistant", model_output)
            if self.debug:
                print(f"[debug] step={step} model_output={model_output}")

            tool_call = self._parse_tool_call(model_output)
            if not tool_call:
                retry_output, retry_call = self._retry_json_if_needed(user_message=text, step=step)
                if retry_output is not None:
                    self._append_message("assistant", retry_output)
                    if self.debug:
                        print(f"[debug] step={step} retry_output={retry_output}")
                if retry_call:
                    tool_call = retry_call
                else:
                    final_message = retry_output or model_output
                    return {
                        "message": final_message,
                        "focus_domain": focus_domain,
                        "conversation_history": self.conversation_history,
                        "steps": self.steps,
                    }

            action = tool_call["action"]
            args = tool_call.get("args", {})
            if isinstance(args, dict) and args.get("domain"):
                focus_domain = str(args["domain"]).strip().lower()

            tool_result = self._execute_tool(action, args)
            self._record_step(action, args, tool_result)
            if self.debug:
                print(f"[debug] tool={action} args={args} result={tool_result}")

            self._append_message("system", "TOOL_RESULT: " + self._safe_json(tool_result))
            final_output = self._finalize_after_tool(text, tool_result)
            self._append_message("assistant", final_output)
            if self.debug:
                print(f"[debug] final_output={final_output}")
            return {
                "message": final_output,
                "focus_domain": focus_domain,
                "conversation_history": self.conversation_history,
                "steps": self.steps,
            }

        return {
            "message": "达到最大推理步数，未得到最终结论。请缩小问题范围后重试。",
            "focus_domain": focus_domain,
            "conversation_history": self.conversation_history,
            "steps": self.steps,
        }

    def _run_planned_calls(self, user_message: str, planned_calls: List[Dict[str, Any]]) -> str:
        tool_results: List[Dict[str, Any]] = []
        for planned in planned_calls:
            action = planned["action"]
            args = planned.get("args", {})
            tool_result = self._execute_tool(action, args)
            self._record_step(action, args, tool_result)
            if self.debug:
                print(f"[debug] planned_tool={action} args={args} result={tool_result}")
            tool_results.append(tool_result)
            self._append_message("system", "TOOL_RESULT: " + self._safe_json(tool_result))
            if not tool_result.get("ok"):
                break

        return self._finalize_after_tool(user_message, tool_results[-1], tool_results)

    def _build_plan(self, text: str, focus_domain: Optional[str]) -> List[Dict[str, Any]]:
        if not focus_domain:
            return []

        lowered = text.lower()
        wants_subdomain = any(keyword in text or keyword in lowered for keyword in self.SUBDOMAIN_KEYWORDS)
        wants_alive = any(keyword in text or keyword in lowered for keyword in self.ALIVE_KEYWORDS)

        if wants_subdomain and wants_alive:
            preferred_tool = "subfinder"
            if "amass" in lowered:
                preferred_tool = "amass"
            elif "dnsx" in lowered:
                preferred_tool = "dnsx"
            return [
                {"action": "subdomain", "args": {"domain": focus_domain, "tool": preferred_tool}},
                {"action": "httpx", "args": {"domain": focus_domain}},
            ]

        direct_tool_call = self._infer_direct_tool_call(text, focus_domain)
        return [direct_tool_call] if direct_tool_call else []

    def _infer_direct_tool_call(self, text: str, focus_domain: Optional[str]) -> Optional[Dict[str, Any]]:
        if not focus_domain:
            return None

        lowered = text.lower()

        if "汇总" in text or "summary" in lowered:
            return {"action": "summary", "args": {"domain": focus_domain}}

        if "明细" in text or "结果" in text:
            if "存活" in text or "alive" in lowered:
                return {"action": "alive_results", "args": {"domain": focus_domain}}
            return {"action": "view_results", "args": {"domain": focus_domain}}

        if any(keyword in text or keyword in lowered for keyword in self.SUBDOMAIN_KEYWORDS):
            preferred_tool = "subfinder"
            if "amass" in lowered:
                preferred_tool = "amass"
            elif "dnsx" in lowered:
                preferred_tool = "dnsx"
            return {"action": "subdomain", "args": {"domain": focus_domain, "tool": preferred_tool}}

        if any(keyword in text or keyword in lowered for keyword in self.ALIVE_KEYWORDS):
            return {"action": "httpx", "args": {"domain": focus_domain}}

        return None

    def _finalize_after_tool(
        self,
        user_message: str,
        tool_result: Dict[str, Any],
        tool_results: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        results = tool_results or [tool_result]
        messages = list(self.conversation_history)
        messages.append(
            {
                "role": "system",
                "content": (
                    "现在进入 final_answer 阶段。"
                    "下面这些 TOOL_RESULT 都已经是真实工具执行结果。"
                    "你必须基于这些结果直接输出自然语言总结。"
                    "不要输出 JSON。"
                    "不要继续调用工具。"
                    "要明确说明保存位置、数据库类型和表名。"
                    f"\nUSER_REQUEST={user_message}\n"
                    f"TOOL_RESULTS={self._safe_json(results)}"
                ),
            }
        )
        model_output = self.client.chat(messages)
        if self._parse_tool_call(model_output):
            return self._format_tool_results(results)
        return model_output

    def _format_tool_results(self, tool_results: List[Dict[str, Any]]) -> str:
        if not tool_results:
            return "本轮没有可用的工具结果。"
        return "\n\n".join(self._format_single_tool_result(item) for item in tool_results)

    def _format_single_tool_result(self, tool_result: Dict[str, Any]) -> str:
        tool_name = tool_result.get("tool", "unknown")
        storage = tool_result.get("storage", {})
        db_type = storage.get("type", "sqlite")
        db_path = storage.get("path", self.store.db_path)
        tables = "、".join(storage.get("tables", [])) or "未标注表名"

        if not tool_result.get("ok"):
            error = tool_result.get("error", "未知错误")
            return f"{tool_name} 执行失败：{error}。结果保存位置为 {db_type} 数据库 `{db_path}`，相关表：{tables}。"

        if tool_name == "subdomain":
            domain = tool_result.get("domain", "")
            scan_tool = tool_result.get("scan_tool", "subdomain")
            total_found = tool_result.get("total_found", 0)
            total_inserted = tool_result.get("total_inserted", 0)
            return (
                f"已使用 {scan_tool} 对 `{domain}` 完成子域名收集，发现 {total_found} 条结果，"
                f"本次新增入库 {total_inserted} 条。结果保存在 {db_type} 数据库 `{db_path}`，"
                f"相关表：{tables}。"
            )

        if tool_name == "httpx":
            domain = tool_result.get("domain", "")
            total = tool_result.get("total", 0)
            probe_mode = tool_result.get("probe_mode", "stored_subdomains")
            target_count = tool_result.get("target_count", 0)
            mode_text = "直接探测目标域名本身" if probe_mode == "direct_domain" else "基于已有子域名批量探测"
            return (
                f"已使用 httpx 对 `{domain}` 完成存活探测，模式为{mode_text}，目标数 {target_count}，"
                f"探测到 {total} 条存活结果。结果保存在 {db_type} 数据库 `{db_path}`，相关表：{tables}。"
            )

        if tool_name == "alive_results":
            domain = tool_result.get("domain", "")
            total = tool_result.get("total", 0)
            items = tool_result.get("items", [])
            tool_names = sorted({str(item.get("tool_name", "")).strip() for item in items if item.get("tool_name")})
            source_text = "、".join(tool_names) if tool_names else "alive_results"
            return (
                f"`{domain}` 当前共有 {total} 条存活记录，来源工具为 {source_text}。"
                f"结果保存在 {db_type} 数据库 `{db_path}`，相关表：{tables}。"
            )

        if tool_name == "view_results":
            domain = tool_result.get("domain", "")
            total = tool_result.get("total", 0)
            return (
                f"`{domain}` 当前共有 {total} 条子域名记录。"
                f"结果保存在 {db_type} 数据库 `{db_path}`，相关表：{tables}。"
            )

        if tool_name == "summary":
            domain = tool_result.get("domain") or "全局"
            return (
                f"已返回 `{domain}` 的汇总信息。结果数据位于 {db_type} 数据库 `{db_path}`，"
                f"相关表：{tables}。"
            )

        return f"已完成工具 `{tool_name}` 执行。结果保存在 {db_type} 数据库 `{db_path}`，相关表：{tables}。"

    def _retry_json_if_needed(self, user_message: str, step: int) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        if not self._should_force_json(user_message, step):
            return None, None

        messages = list(self.conversation_history)
        messages.append(
            {
                "role": "system",
                "content": "你上一条回复无法解析。现在处于 tool_call 阶段。请只输出 JSON，不要解释。格式: {\"action\":\"工具名\",\"args\":{...}}",
            }
        )
        retry_output = self.client.chat(messages)
        retry_call = self._parse_tool_call(retry_output)
        return retry_output, retry_call

    def _should_force_json(self, user_message: str, step: int) -> bool:
        return step <= 2 and not self.steps

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
        system_msg = history[0]
        tail = history[-(self.max_history_messages - 1) :]
        return [system_msg] + tail

    def _parse_tool_call(self, text: str) -> Optional[Dict[str, Any]]:
        payload = self._extract_json_object(text)
        if not payload:
            return None
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        action = parsed.get("action")
        args = parsed.get("args", {})
        if not isinstance(action, str) or not action.strip():
            return None
        if not isinstance(args, dict):
            return None
        return {"action": action.strip(), "args": args}

    def _extract_json_object(self, text: str) -> Optional[str]:
        stripped = text.strip()
        if stripped.startswith("```"):
            match = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", stripped)
            if match:
                return match.group(1)

        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        return stripped[start : end + 1]

    def _execute_tool(self, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        tool = self.available_tools.get(action)
        if not tool:
            return self._attach_storage_info(
                {
                    "ok": False,
                    "error": f"未知工具: {action}",
                    "available_tools": list(self.available_tools.keys()),
                    "tool": action,
                },
                action,
                args,
            )

        try:
            result = tool["handler"](args)
        except Exception as exc:
            result = {"ok": False, "error": str(exc), "tool": action}
        return self._attach_storage_info(result, action, args)

    def _tool_subdomain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        scan_tool = str(args.get("tool", "subfinder")).strip().lower()

        self._validate_domain(domain)
        self._enforce_rate_limit("subdomain", domain)

        if scan_tool not in {"amass", "subfinder", "dnsx"}:
            raise ValueError("tool 仅支持 amass/subfinder/dnsx")

        report = run_tools(domain=domain, tools=[scan_tool], store=self.store)
        return {
            "ok": True,
            "tool": "subdomain",
            "domain": domain,
            "scan_tool": scan_tool,
            "total_found": report["total_found"],
            "total_inserted": report["total_inserted"],
        }

    def _tool_summary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain_raw = str(args.get("domain", "")).strip().lower()
        if domain_raw:
            self._validate_domain(domain_raw)
            data = self.store.get_domain_summary(domain_raw)
            return {"ok": True, "tool": "summary", "domain": domain_raw, "data": data}

        data = self.store.get_global_summary()
        return {"ok": True, "tool": "summary", "domain": None, "data": data}

    def _tool_view_results(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        self._validate_domain(domain)
        self._enforce_rate_limit("view_results", domain)

        limit = self._safe_limit(args.get("limit"), default=20)
        rows = self.store.get_results_by_domain(domain)
        return {
            "ok": True,
            "tool": "view_results",
            "domain": domain,
            "total": len(rows),
            "items": [
                {"subdomain": subdomain, "tool_name": tool_name, "created_at": created_at}
                for subdomain, tool_name, created_at in rows[:limit]
            ],
        }

    def _tool_alive_results(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        self._validate_domain(domain)
        self._enforce_rate_limit("alive_results", domain)

        limit = self._safe_limit(args.get("limit"), default=20)
        rows = self.store.get_alive_results(domain=domain)
        return {
            "ok": True,
            "tool": "alive_results",
            "domain": domain,
            "total": len(rows),
            "items": [
                {"hostname": hostname, "tool_name": tool_name, "created_at": created_at}
                for _, hostname, tool_name, created_at in rows[:limit]
            ],
        }

    def _tool_httpx(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        self._validate_domain(domain)
        self._enforce_rate_limit("httpx", domain)

        existing_subdomains = self.store.get_results_by_domain(domain)
        runner = HttpxRunner()
        if existing_subdomains:
            rows = runner.run_scan(domain=domain)
            probe_mode = "stored_subdomains"
            target_count = len(existing_subdomains)
        else:
            rows = runner.run_scan(domain=domain, candidates=[domain])
            probe_mode = "direct_domain"
            target_count = 1

        return {
            "ok": True,
            "tool": "httpx",
            "domain": domain,
            "probe_mode": probe_mode,
            "target_count": target_count,
            "total": len(rows),
            "items": rows[:20],
        }

    def _attach_storage_info(self, result: Dict[str, Any], action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = str(result.get("tool") or action).strip().lower()
        result["storage"] = {
            "type": "sqlite",
            "path": self.store.db_path or "results/scan_results.db",
            "tables": self._get_storage_tables(tool_name, result, args),
        }
        return result

    def _get_storage_tables(self, tool_name: str, result: Dict[str, Any], args: Dict[str, Any]) -> List[str]:
        if tool_name == "subdomain":
            scan_tool = str(result.get("scan_tool") or args.get("tool") or "subfinder").strip().lower()
            tables = ["subdomain_results"]
            if scan_tool in TOOL_DATABASES:
                tables.append(TOOL_DATABASES[scan_tool]["table"])
            if scan_tool == "dnsx":
                tables.append("alive_results")
            return self._dedupe_list(tables)

        if tool_name == "httpx":
            return ["httpx_results", "tool_results"]

        if tool_name == "alive_results":
            return ["alive_results", "dnsx_results"]

        if tool_name == "view_results":
            return ["subdomain_results"]

        if tool_name == "summary":
            return ["scan_runs", "subdomain_results", "alive_results", "tool_results"]

        return ["tool_results"]

    def _record_step(self, action: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        self.steps.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "action": action,
                "args": args,
                "result": result,
            }
        )

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
            if parsed < 1:
                return default
            return min(parsed, 200)
        except Exception:
            return default

    def _extract_domain(self, text: str) -> Optional[str]:
        match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
        return match.group(0).lower() if match else None

    def _load_set_env(self, env_key: str, defaults: Optional[set] = None) -> set:
        raw = os.getenv(env_key, "").strip()
        if not raw:
            return set(defaults or set())
        parsed = {item.strip().lower() for item in raw.split(",") if item.strip()}
        if defaults:
            parsed.update({item.lower() for item in defaults})
        return parsed

    def _safe_json(self, value: Any) -> str:
        raw = json.dumps(value, ensure_ascii=False)
        if len(raw) <= 4000:
            return raw
        return raw[:4000] + "...<truncated>"

    def _is_storage_question(self, text: str) -> bool:
        lowered = text.lower()
        return any(keyword in text or keyword in lowered for keyword in self.DATABASE_QUERY_KEYWORDS)

    def _has_scan_intent(self, text: str) -> bool:
        lowered = text.lower()
        subdomain_hits = any(keyword in text or keyword in lowered for keyword in self.SUBDOMAIN_KEYWORDS)
        alive_hits = any(keyword in text or keyword in lowered for keyword in self.ALIVE_KEYWORDS)
        return subdomain_hits or alive_hits

    def _answer_storage_question(self, focus_domain: Optional[str]) -> str:
        db_path = self.store.db_path or "results/scan_results.db"
        domain_text = f"当前与 `{focus_domain}` 相关的扫描结果" if focus_domain else "当前扫描结果"
        return (
            f"{domain_text} 默认保存在 SQLite 数据库 `{db_path}`。"
            "主要表包括 `subdomain_results`、`alive_results`、`tool_results`，"
            "各工具的专用表例如 `dnsx_results`、`httpx_results` 也会按工具分别保存。"
        )

    def _dedupe_list(self, values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered
