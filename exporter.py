import csv
import json
import os
import time
from typing import Any, Dict, List, Optional

from config import EXPORT_DIR
from storage import ScanResultStore


def ensure_export_dir() -> None:
    os.makedirs(EXPORT_DIR, exist_ok=True)


def gather_export_rows(
    store: ScanResultStore,
    domain: Optional[str] = None,
    tool_name: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if category in {None, "", "subdomain"}:
        subdomain_rows = store.get_view_results(domain=domain, tool_name=tool_name)
        for row_domain, subdomain, row_tool, created_at in subdomain_rows[:limit]:
            rows.append(
                {
                    "domain": row_domain,
                    "tool_name": row_tool,
                    "category": "subdomain",
                    "value": subdomain,
                    "created_at": created_at,
                }
            )

    generic_rows = store.get_tool_results(
        domain=domain,
        tool_name=tool_name,
        category=category if category != "subdomain" else None,
        limit=limit,
    )
    for row_domain, row_tool, row_category, value, created_at in generic_rows:
        rows.append(
            {
                "domain": row_domain,
                "tool_name": row_tool,
                "category": row_category,
                "value": value,
                "created_at": created_at,
            }
        )

    return rows[:limit]


def export_results(rows: List[Dict[str, Any]], fmt: str = "csv", prefix: str = "results") -> str:
    ensure_export_dir()

    ts = time.strftime("%Y%m%d_%H%M%S")
    fmt = (fmt or "csv").lower().strip()
    filename = f"{prefix}_{ts}.{fmt}"
    path = os.path.join(EXPORT_DIR, filename)

    if fmt == "json":
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=False, indent=2)
        return path

    if fmt == "csv":
        fieldnames = sorted({key for row in rows for key in row.keys()}) if rows else ["domain", "tool_name", "category", "value", "created_at"]
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return path

    raise ValueError("暂不支持该导出格式")
