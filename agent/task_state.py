from copy import deepcopy
from typing import Any, Dict, List, Optional


VALID_STATUSES = {
    "created",
    "awaiting_confirmation",
    "running",
    "waiting_tool_result",
    "completed",
    "failed",
    "cancelled",
}


def init_task_state(plan: Dict[str, Any]) -> Dict[str, Any]:
    task = deepcopy(plan)
    task["status"] = "awaiting_confirmation" if plan.get("requires_confirmation", True) else "created"
    task["current_step_index"] = 0
    task["completed_steps"] = []
    task["round"] = 0
    task["context_results"] = task.get(
        "context_results",
        {
            "subdomains": [],
            "alive_urls": [],
            "httpx_fingerprints": [],
            "ports": [],
            "content_paths": [],
            "exports": [],
        },
    )
    return task


def normalize_task_state(plan: Dict[str, Any]) -> Dict[str, Any]:
    task = init_task_state(plan)
    task.update({k: deepcopy(v) for k, v in plan.items()})
    if task.get("status") not in VALID_STATUSES:
        task["status"] = "awaiting_confirmation"
    task.setdefault("current_step_index", 0)
    task.setdefault("completed_steps", [])
    task.setdefault("round", 0)
    task.setdefault(
        "context_results",
        {
            "subdomains": [],
            "alive_urls": [],
            "httpx_fingerprints": [],
            "ports": [],
            "content_paths": [],
            "exports": [],
        },
    )
    return task


def current_step(task: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    index = int(task.get("current_step_index", 0))
    steps = task.get("steps", [])
    if index < 0 or index >= len(steps):
        return None
    return steps[index]


def advance_task(task: Dict[str, Any], step_result: Dict[str, Any]) -> Dict[str, Any]:
    updated = normalize_task_state(task)
    step = current_step(updated)
    if step is not None:
        updated["completed_steps"].append({"step": deepcopy(step), "result": deepcopy(step_result)})
        updated["current_step_index"] = int(updated.get("current_step_index", 0)) + 1
    updated["round"] = int(updated.get("round", 0)) + 1
    updated["status"] = "completed" if updated["current_step_index"] >= len(updated.get("steps", [])) else "waiting_tool_result"
    if not step_result.get("ok"):
        updated["status"] = "failed"
    return updated


def cancel_task(task: Dict[str, Any]) -> Dict[str, Any]:
    updated = normalize_task_state(task)
    updated["status"] = "cancelled"
    return updated


def summarize_steps(task: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(task.get("completed_steps", []))
