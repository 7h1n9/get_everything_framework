import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


DOMAIN_PATTERN = re.compile(r"(?<![A-Za-z0-9-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9-])")

PASSIVE_ONLY_KEYWORDS = ["先不扫描", "不扫描", "不要扫描", "先不执行", "只做被动", "被动信息收集"]
VIEW_RESULT_KEYWORDS = ["查看", "看一下", "结果", "已有结果", "扫描结果"]
UPLOAD_FILE_KEYWORDS = ["刚上传", "上传的目标", "目标列表", "上传文件"]
DB_QUERY_KEYWORDS = ["数据库", "已有", "历史", "结果", "调一下", "查一下", "之前扫过", "已经扫过", "history"]
SUBDOMAIN_KEYWORDS = ["子域名", "子域", "subdomain", "subfinder"]
RANK_KEYWORDS = ["判断", "优先", "排序", "rank", "priority", "src"]
PROBE_KEYWORDS = ["探活", "存活", "httpx", "可访问"]
TECH_STACK_KEYWORDS = ["技术栈", "指纹", "组件", "框架", "中间件", "tech"]
EXISTING_KEYWORDS = ["已收集", "已有", "数据库", "历史", "已经扫过", "之前扫过"]
STRATEGY_KEYWORDS = ["路线", "方案", "策略", "怎么做", "信息收集"]
SET_TARGET_PATTERNS = [
    r"使用\s+(.+?)\s+作为目标",
    r"把\s+(.+?)\s+作为目标",
    r"目标(?:设为|设置为)\s*(.+)",
]


@dataclass
class UserIntent:
    raw_text: str
    intent_type: str
    target: Optional[str] = None
    target_type: Optional[str] = None
    org_name: Optional[str] = None
    scan_allowed: bool = False
    passive_only: bool = False
    wants_export: bool = False
    export_format: Optional[str] = None
    needs_confirmation: bool = True
    requested_tools: List[str] = field(default_factory=list)
    excluded_tools: List[str] = field(default_factory=list)
    goal: Optional[str] = None
    result_filter: Dict[str, str] = field(default_factory=dict)
    need_tech_stack: bool = False


def extract_domain(text: str) -> Optional[str]:
    match = DOMAIN_PATTERN.search(text or "")
    return match.group(1).lower() if match else None


def extract_org_name(text: str) -> Optional[str]:
    value = (text or "").strip()
    if not value:
        return None
    patterns = [
        r"帮我收集(.+?)的信息",
        r"收集(.+?)的信息",
        r"对(.+?)做信息收集",
        r"帮我对(.+?)的已收集的子域名",
        r"帮我对(.+?)已收集的子域名",
    ]
    for pattern in patterns:
        match = re.search(pattern, value)
        if match:
            return match.group(1).strip(" ，。")
    return None


def guess_export_format(text: str) -> Optional[str]:
    lowered = (text or "").lower()
    if "json" in lowered:
        return "json"
    if "excel" in lowered or "xlsx" in lowered:
        return "xlsx"
    if "csv" in lowered or "导出" in text:
        return "csv"
    return None


def _has_any(text: str, keywords: List[str]) -> bool:
    lowered = (text or "").lower()
    return any(keyword in text or keyword in lowered for keyword in keywords)


def _extract_set_target(text: str) -> Optional[str]:
    for pattern in SET_TARGET_PATTERNS:
        match = re.search(pattern, text or "")
        if not match:
            continue
        candidate = match.group(1).strip(" ，。")
        domain = extract_domain(candidate)
        if domain:
            return domain
    return None


def analyze_intent(
    text: str,
    has_uploaded_file: bool = False,
    context_state: Optional[Dict[str, str]] = None,
) -> UserIntent:
    context_state = context_state or {}
    lowered = (text or "").lower()
    domain = extract_domain(text)
    org_name = extract_org_name(text)
    last_target = context_state.get("last_target") or context_state.get("target")
    has_tech_stack = _has_any(text, TECH_STACK_KEYWORDS)
    passive_only = _has_any(text, PASSIVE_ONLY_KEYWORDS)

    if _has_any(text, ["取消", "停止", "算了", "不要执行", "cancel", "stop", "abort", "never mind"]):
        return UserIntent(raw_text=text, intent_type="cancel_plan", needs_confirmation=False)

    if _has_any(text, ["确认", "执行", "开始", "继续", "可以执行", "confirm", "run", "start", "continue", "go ahead"]):
        return UserIntent(raw_text=text, intent_type="confirm_plan", needs_confirmation=False)

    set_target = _extract_set_target(text)
    if set_target:
        return UserIntent(
            raw_text=text,
            intent_type="set_target",
            target=set_target,
            target_type="domain",
            org_name=org_name or context_state.get("org"),
            passive_only=bool(context_state.get("mode") == "passive_only"),
            needs_confirmation=False,
        )

    if _has_any(text, ["导出", "下载", "保存为文件", "导出文件", "export"]):
        return UserIntent(
            raw_text=text,
            intent_type="export_results",
            target=domain or last_target,
            target_type="domain" if domain or last_target else None,
            passive_only=True,
            wants_export=True,
            export_format=guess_export_format(text),
            needs_confirmation=False,
            requested_tools=["export_results"],
        )

    if (domain or last_target) and _has_any(text, VIEW_RESULT_KEYWORDS):
        return UserIntent(
            raw_text=text,
            intent_type="view_existing_results",
            target=domain or last_target,
            target_type="domain",
            passive_only=True,
            needs_confirmation=False,
            requested_tools=["summary", "view_results"],
        )

    if (domain or last_target) and _has_any(text, DB_QUERY_KEYWORDS) and (_has_any(text, SUBDOMAIN_KEYWORDS) or _has_any(text, RANK_KEYWORDS)):
        return UserIntent(
            raw_text=text,
            intent_type="analyze_existing_subdomains",
            target=domain or last_target,
            target_type="domain",
            passive_only=True,
            needs_confirmation=False,
            requested_tools=["view_results"],
            goal="rank_src_targets" if _has_any(text, RANK_KEYWORDS) else "view_results",
            result_filter={"tool": "subfinder", "category": "subdomain"},
        )

    if _has_any(text, EXISTING_KEYWORDS) and _has_any(text, SUBDOMAIN_KEYWORDS) and _has_any(text, PROBE_KEYWORDS):
        return UserIntent(
            raw_text=text,
            intent_type="probe_existing_subdomains",
            target=domain or last_target,
            target_type="domain" if domain or last_target else None,
            org_name=org_name or context_state.get("org"),
            scan_allowed=True,
            needs_confirmation=True,
            requested_tools=["httpx", "summary"],
            need_tech_stack=has_tech_stack,
        )

    if ("httpx" in lowered or "探活" in text or "存活" in text) and (domain or last_target):
        return UserIntent(
            raw_text=text,
            intent_type="web_probe",
            target=domain or last_target,
            target_type="domain",
            scan_allowed=True,
            needs_confirmation=True,
            requested_tools=["httpx"],
            need_tech_stack=has_tech_stack,
        )

    if has_uploaded_file and _has_any(text, UPLOAD_FILE_KEYWORDS):
        return UserIntent(
            raw_text=text,
            intent_type="uploaded_file_scan",
            target_type="uploaded_file",
            scan_allowed=True,
            needs_confirmation=True,
            requested_tools=["subdomain"] if ("子域" in text or "subdomain" in lowered) else [],
        )

    if has_uploaded_file and _has_any(text, SUBDOMAIN_KEYWORDS):
        return UserIntent(
            raw_text=text,
            intent_type="uploaded_file_scan",
            target_type="uploaded_file",
            scan_allowed=True,
            needs_confirmation=True,
            requested_tools=["subdomain"],
        )

    if _has_any(text, SUBDOMAIN_KEYWORDS):
        return UserIntent(
            raw_text=text,
            intent_type="subdomain_scan",
            target=domain or last_target,
            target_type="domain" if domain or last_target else "org",
            org_name=org_name or context_state.get("org"),
            scan_allowed=True,
            needs_confirmation=True,
            requested_tools=["subdomain"],
        )

    if passive_only or _has_any(text, STRATEGY_KEYWORDS):
        return UserIntent(
            raw_text=text,
            intent_type="strategy_only",
            target=domain or last_target,
            target_type="domain" if domain or last_target else "org",
            org_name=org_name or context_state.get("org"),
            passive_only=True,
            needs_confirmation=False,
        )

    return UserIntent(
        raw_text=text,
        intent_type="unknown_chat",
        target=domain or last_target,
        target_type="domain" if domain or last_target else None,
        org_name=org_name or context_state.get("org"),
        passive_only=bool(context_state.get("mode") == "passive_only"),
        needs_confirmation=False,
    )
