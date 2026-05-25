import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from modules.httpx import HttpxRunner
from storage import ScanResultStore
from tool_runner import run_tools

from .client import OpenAICompatibleClient
from .system_prompt import SYSTEM_PROMPT


class AgentAction:
    """中文注释：核心 Agent 执行器，负责多轮推理和工具调用循环。"""

    RATE_LIMIT_CACHE: Dict[str, float] = {}
    DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

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

        # 中文注释：统一工具注册表，包含描述、参数和执行函数
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
        direct_tool_call = self._infer_direct_tool_call(text, focus_domain)

        if direct_tool_call:
            action = direct_tool_call["action"]
            args = direct_tool_call.get("args", {})
            tool_result = self._execute_tool(action, args)
            self._record_step(action, args, tool_result)
            if self.debug:
                print(f"[debug] direct_tool={action} args={args} result={tool_result}")

            self._append_message(
                "system",
                "TOOL_RESULT: " + self._safe_json(tool_result),
            )

            final_output = self._finalize_after_single_tool()
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

            # 中文注释：将工具结果以 system 消息回填，避免模型误判为用户输入
            self._append_message(
                "system",
                "TOOL_RESULT: " + self._safe_json(tool_result),
            )

            final_output = self._finalize_after_single_tool()
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

    def _infer_direct_tool_call(self, text: str, focus_domain: Optional[str]) -> Optional[Dict[str, Any]]:
        if not focus_domain:
            return None

        lowered = text.lower()

        if "子域名" in text:
            preferred_tool = "subfinder"
            if "amass" in lowered:
                preferred_tool = "amass"
            elif "dnsx" in lowered:
                preferred_tool = "dnsx"
            return {"action": "subdomain", "args": {"domain": focus_domain, "tool": preferred_tool}}

        if "汇总" in text or "summary" in lowered:
            return {"action": "summary", "args": {"domain": focus_domain}}

        if "明细" in text or "结果" in text:
            if "存活" in text:
                return {"action": "alive_results", "args": {"domain": focus_domain}}
            return {"action": "view_results", "args": {"domain": focus_domain}}

        # 中文注释：只要用户给了域名、且没有明确要求“子域名/汇总/明细”，默认直接走 httpx，
        # 这样“测试某域名存活”不会再先绕去做子域名收集。
        return {"action": "httpx", "args": {"domain": focus_domain}}

    def _finalize_after_single_tool(self) -> str:
        messages = list(self.conversation_history)
        messages.append(
            {
                "role": "system",
                "content": (
                    "本轮用户请求最多只能执行一个工具。"
                    "你已经拿到了本轮唯一一次工具执行结果。"
                    "现在必须直接给出最终答复，解释结果、失败原因或下一步建议。"
                    "不要再输出 JSON，不要再调用任何工具。"
                ),
            }
        )
        return self.client.chat(messages)

    def _retry_json_if_needed(self, user_message: str, step: int) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        if not self._should_force_json(user_message, step):
            return None, None

        messages = list(self.conversation_history)
        messages.append(
            {
                "role": "system",
                "content": "你上一条回复无法解析。请只输出 JSON，不要解释。格式: {\"action\":\"工具名\",\"args\":{...}}",
            }
        )
        retry_output = self.client.chat(messages)
        retry_call = self._parse_tool_call(retry_output)
        return retry_output, retry_call

    def _should_force_json(self, user_message: str, step: int) -> bool:
        # 中文注释：在尚未成功调用任何工具时，前两步强制尝试 JSON 回退，降低“应调工具却输出自然语言”导致的失灵概率
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
        # 中文注释：保留首条 system 提示词，并截断最近 N 条消息，避免 token 膨胀
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
            return {
                "ok": False,
                "error": f"未知工具: {action}",
                "available_tools": list(self.available_tools.keys()),
            }

        try:
            return tool["handler"](args)
        except Exception as exc:
            return {"ok": False, "error": str(exc), "tool": action}

    def _tool_subdomain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._normalize_domain_arg(args.get("domain"))
        tool = str(args.get("tool", "subfinder")).strip().lower()

        self._validate_domain(domain)
        self._enforce_rate_limit("subdomain", domain)

        if tool not in {"amass", "subfinder", "dnsx"}:
            raise ValueError("tool 仅支持 amass/subfinder/dnsx")

        report = run_tools(domain=domain, tools=[tool], store=self.store)
        return {
            "ok": True,
            "tool": "subdomain",
            "domain": domain,
            "scan_tool": tool,
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
        # 中文注释：限制回填长度，避免超长工具结果快速耗尽上下文
        if len(raw) <= 4000:
            return raw
        return raw[:4000] + "...<truncated>"
