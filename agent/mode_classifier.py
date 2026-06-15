from .intent import UserIntent


TASK_INTENTS = {
    "confirm_plan",
    "cancel_plan",
    "export_results",
    "view_existing_results",
    "analyze_existing_subdomains",
    "probe_existing_subdomains",
    "web_probe",
    "subdomain_scan",
    "uploaded_file_scan",
}


def classify_mode(intent: UserIntent) -> str:
    if intent.intent_type in TASK_INTENTS:
        return "task"
    if intent.intent_type == "strategy_only":
        return "chat"
    if intent.intent_type == "unknown_chat":
        return "chat"
    return "task" if intent.scan_allowed or intent.requested_tools else "chat"
