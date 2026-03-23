import re
import sqlite3
from datetime import datetime

from config import SQLITE_CONFIG


class ScanResultStore:
    def __init__(self, db_path=None):
        self.db_path = db_path or SQLITE_CONFIG["path"]
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _extract_clean_subdomains(self, domain, value):
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_-])([A-Za-z0-9._-]+\.{re.escape(domain)})\b"
        )
        return [item.lower().rstrip(".") for item in pattern.findall(value)]

    def _normalize_domain_rows(self, rows, domain_index, value_index, tool_index):
        normalized_rows = []
        seen = set()

        for row in rows:
            row = list(row)
            domain = row[domain_index]
            value = row[value_index]
            tool_name = row[tool_index]

            if tool_name == "amass":
                candidates = self._extract_clean_subdomains(domain, value)
            else:
                candidates = [value.strip().lower()] if value.strip() else []

            for candidate in candidates:
                key = (domain, candidate, tool_name)
                if key in seen:
                    continue
                seen.add(key)
                row[value_index] = candidate
                normalized_rows.append(tuple(row))

        return normalized_rows

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    result_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subdomain_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(domain, subdomain, tool_name),
                    FOREIGN KEY(run_id) REFERENCES scan_runs(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alive_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(domain, hostname, tool_name),
                    FOREIGN KEY(run_id) REFERENCES scan_runs(id)
                )
                """
            )

    def save_results(self, domain, tool_name, results):
        normalized_results = []
        seen = set()
        for item in results:
            value = item.strip()
            if not value or value in seen:
                continue
            normalized_results.append(value)
            seen.add(value)

        created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_runs (domain, tool_name, result_count, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (domain, tool_name, len(normalized_results), created_at),
            )
            run_id = cursor.lastrowid

            inserted_count = 0
            for subdomain in normalized_results:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO subdomain_results
                    (run_id, domain, subdomain, tool_name, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (run_id, domain, subdomain, tool_name, created_at),
                )
                inserted_count += cursor.rowcount

                if tool_name == "dnsx":
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO alive_results
                        (run_id, domain, hostname, tool_name, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (run_id, domain, subdomain, tool_name, created_at),
                    )

            return {
                "run_id": run_id,
                "scan_count": len(normalized_results),
                "inserted_count": inserted_count,
            }

    def get_alive_results(self, domain=None):
        query = [
            "SELECT domain, hostname, tool_name, created_at",
            "FROM alive_results",
        ]
        params = []

        if domain:
            query.append("WHERE domain = ?")
            params.append(domain)

        query.append("ORDER BY domain ASC, hostname ASC")

        with self._get_connection() as conn:
            cursor = conn.execute("\n".join(query), params)
            return cursor.fetchall()

    def get_alive_overview(self, domain=None):
        rows = self.get_alive_results(domain=domain)
        grouped = {}

        for item_domain, hostname, tool_name, created_at in rows:
            key = (item_domain, tool_name)
            current = grouped.get(key)
            if not current:
                grouped[key] = {
                    "domain": item_domain,
                    "tool_name": tool_name,
                    "total_count": 1,
                    "last_scan_at": created_at,
                }
                continue

            current["total_count"] += 1
            if created_at > current["last_scan_at"]:
                current["last_scan_at"] = created_at

        return [
            (
                item["domain"],
                item["tool_name"],
                item["total_count"],
                item["last_scan_at"],
            )
            for item in sorted(
                grouped.values(),
                key=lambda item: (item["domain"], item["tool_name"]),
            )
        ]

    def get_results_by_domain(self, domain):
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT subdomain, tool_name, created_at
                FROM subdomain_results
                WHERE domain = ?
                ORDER BY subdomain ASC
                """,
                (domain,),
            )
            rows = [(domain, subdomain, tool_name, created_at) for subdomain, tool_name, created_at in cursor.fetchall()]
            normalized_rows = self._normalize_domain_rows(rows, 0, 1, 2)
            return [(subdomain, tool_name, created_at) for _, subdomain, tool_name, created_at in normalized_rows]

    def get_global_summary(self):
        with self._get_connection() as conn:
            run_cursor = conn.execute(
                """
                SELECT COUNT(*)
                FROM scan_runs
                """
            )
            total_runs = run_cursor.fetchone()[0]

            cursor = conn.execute(
                """
                SELECT
                    COUNT(DISTINCT domain) AS total_domains,
                    COUNT(DISTINCT subdomain) AS total_subdomains
                FROM subdomain_results
                """
            )
            summary = cursor.fetchone()

            tool_cursor = conn.execute(
                """
                SELECT tool_name, COUNT(*) AS total_count
                FROM subdomain_results
                GROUP BY tool_name
                ORDER BY total_count DESC, tool_name ASC
                """
            )
            tool_stats = tool_cursor.fetchall()

            run_cursor = conn.execute(
                """
                SELECT domain, tool_name, result_count, created_at
                FROM scan_runs
                ORDER BY id DESC
                LIMIT 10
                """
            )
            recent_runs = run_cursor.fetchall()

            return {
                "total_runs": total_runs,
                "total_domains": summary[0] if summary else 0,
                "total_subdomains": summary[1] if summary else 0,
                "tool_stats": tool_stats,
                "recent_runs": recent_runs,
            }

    def get_domain_summary(self, domain):
        results = [
            (subdomain, tool_name, created_at)
            for _, subdomain, tool_name, created_at in self.get_view_results(domain=domain)
        ]

        tool_counts = {}
        last_scan_at = None
        for subdomain, tool_name, created_at in results:
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            if not last_scan_at or created_at > last_scan_at:
                last_scan_at = created_at

        tool_stats = sorted(
            tool_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )

        return {
            "domain": domain,
            "total_subdomains": len({subdomain for subdomain, _, _ in results}),
            "last_scan_at": last_scan_at,
            "tool_stats": tool_stats,
            "results": results,
        }

    def get_view_results(self, domain=None, tool_name=None):
        query = [
            "SELECT domain, subdomain, tool_name, created_at",
            "FROM subdomain_results",
        ]
        conditions = []
        params = []

        if domain:
            conditions.append("domain = ?")
            params.append(domain)

        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)

        if conditions:
            query.append("WHERE " + " AND ".join(conditions))

        query.append("ORDER BY domain ASC, tool_name ASC, subdomain ASC")

        with self._get_connection() as conn:
            cursor = conn.execute("\n".join(query), params)
            return self._normalize_domain_rows(cursor.fetchall(), 0, 1, 2)

    def get_view_overview(self, domain=None, tool_name=None):
        query = [
            "SELECT domain, subdomain, tool_name, created_at",
            "FROM subdomain_results",
        ]
        conditions = []
        params = []

        if domain:
            conditions.append("domain = ?")
            params.append(domain)

        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)

        if conditions:
            query.append("WHERE " + " AND ".join(conditions))

        query.append("ORDER BY domain ASC, tool_name ASC, subdomain ASC")

        with self._get_connection() as conn:
            cursor = conn.execute("\n".join(query), params)
            rows = self._normalize_domain_rows(cursor.fetchall(), 0, 1, 2)

        grouped = {}
        for item_domain, subdomain, item_tool, created_at in rows:
            key = (item_domain, item_tool)
            current = grouped.get(key)
            if not current:
                grouped[key] = {
                    "domain": item_domain,
                    "tool_name": item_tool,
                    "total_count": 1,
                    "last_scan_at": created_at,
                }
                continue

            current["total_count"] += 1
            if created_at > current["last_scan_at"]:
                current["last_scan_at"] = created_at

        return [
            (
                item["domain"],
                item["tool_name"],
                item["total_count"],
                item["last_scan_at"],
            )
            for item in sorted(
                grouped.values(),
                key=lambda item: (item["domain"], item["tool_name"]),
            )
        ]
