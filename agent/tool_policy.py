from copy import deepcopy
from typing import Any, Dict, Tuple


READ_ONLY_TOOLS = {"summary", "view_results", "alive_results", "export_results"}
ACTIVE_TOOLS = {"subdomain", "httpx", "dnsx", "naabu", "nmap", "dirsearch", "feroxbuster", "ping"}
HIGH_RISK_TOOLS = {"naabu", "nmap", "dirsearch", "feroxbuster"}

DEFAULT_LIMITS = {
    "httpx_threads": 10,
    "dnsx_threads": 20,
    "naabu_rate": 50,
    "dirsearch_threads": 5,
    "feroxbuster_threads": 5,
    "nmap_timing": "T2",
}


def requires_confirmation(tool_name: str) -> bool:
    return tool_name in ACTIVE_TOOLS


def tool_group(tool_name: str) -> str:
    if tool_name in READ_ONLY_TOOLS:
        return "read_only"
    if tool_name in HIGH_RISK_TOOLS:
        return "high_risk"
    if tool_name in ACTIVE_TOOLS:
        return "active"
    return "other"


def clamp_step_args(step: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    normalized = deepcopy(step)
    args = normalized.setdefault("args", {})
    elevated = False

    if normalized.get("tool") == "httpx":
        requested = int(args.get("threads") or DEFAULT_LIMITS["httpx_threads"])
        if requested > DEFAULT_LIMITS["httpx_threads"]:
            elevated = True
        args["threads"] = min(requested, DEFAULT_LIMITS["httpx_threads"])

    if normalized.get("tool") == "dnsx":
        requested = int(args.get("threads") or DEFAULT_LIMITS["dnsx_threads"])
        if requested > DEFAULT_LIMITS["dnsx_threads"]:
            elevated = True
        args["threads"] = min(requested, DEFAULT_LIMITS["dnsx_threads"])

    if normalized.get("tool") == "naabu":
        requested = int(args.get("rate") or DEFAULT_LIMITS["naabu_rate"])
        if requested > DEFAULT_LIMITS["naabu_rate"]:
            elevated = True
        args["rate"] = min(requested, DEFAULT_LIMITS["naabu_rate"])

    if normalized.get("tool") == "dirsearch":
        requested = int(args.get("threads") or DEFAULT_LIMITS["dirsearch_threads"])
        if requested > DEFAULT_LIMITS["dirsearch_threads"]:
            elevated = True
        args["threads"] = min(requested, DEFAULT_LIMITS["dirsearch_threads"])

    if normalized.get("tool") == "feroxbuster":
        requested = int(args.get("threads") or DEFAULT_LIMITS["feroxbuster_threads"])
        if requested > DEFAULT_LIMITS["feroxbuster_threads"]:
            elevated = True
        args["threads"] = min(requested, DEFAULT_LIMITS["feroxbuster_threads"])

    if normalized.get("tool") == "nmap":
        args["timing"] = args.get("timing") or DEFAULT_LIMITS["nmap_timing"]

    return normalized, elevated
