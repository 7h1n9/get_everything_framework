import csv
import os
import re
from typing import List, Optional
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def normalize_target(value: str) -> Optional[str]:
    value = (value or "").strip()
    if not value:
        return None

    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        value = parsed.hostname or ""

    value = value.strip().lower()
    if DOMAIN_PATTERN.fullmatch(value):
        return value

    return None


def parse_targets_file(file_path: str) -> List[str]:
    targets: List[str] = []

    if file_path.lower().endswith(".csv"):
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.reader(handle)
            for row in reader:
                for cell in row:
                    target = normalize_target(cell)
                    if target:
                        targets.append(target)
    else:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                target = normalize_target(line)
                if target:
                    targets.append(target)

    return list(dict.fromkeys(targets))


def save_normalized_targets(targets: List[str], output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for target in targets:
            handle.write(target + "\n")
    return output_path
