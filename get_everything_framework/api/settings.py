"""
GET  /api/settings          — 读取当前配置 (API Key 脱敏)
POST /api/settings          — 保存配置到 .env 文件
GET  /api/settings/enscan   — 读取 enscan Cookie 配置
POST /api/settings/enscan   — 保存 enscan Cookie 到 config.yaml
"""

import os
import shutil
from pathlib import Path

from flask import jsonify, request

from api import api_bp
from config import _BASE_DIR, Config

ENV_PATH = os.path.join(_BASE_DIR, ".env")

# enscan 配置文件路径
# enscan 配置文件路径:
#   优先级: ENSCAN_CONFIG_PATH (.env) > %GOPATH%/bin/config.yaml > ~/.config/enscan/config.yaml
_GOPATH = os.getenv("GOPATH", str(Path.home() / "go"))
DEFAULT_ENSCAN_CONFIG = Path(_GOPATH) / "bin" / "config.yaml"
ENSCAN_CONFIG_YAML = Path(
    os.getenv("ENSCAN_CONFIG_PATH")
    or (DEFAULT_ENSCAN_CONFIG if DEFAULT_ENSCAN_CONFIG.exists() else Path.home() / ".config" / "enscan" / "config.yaml")
)

# YAML 默认模板
ENSCAN_CONFIG_TEMPLATE = """\
# ENScan_GO 配置文件 (由 framework-main 管理)
# 数据源 Cookie 请从浏览器登录后复制

aqc:
  cookie: ""

tyc:
  cookie: ""

icp:
  cookie: ""
"""

# ── 允许通过 API 修改的字段白名单 ───────────────────────

ALLOWED_KEYS = {
    # LLM
    "llm_provider", "llm_model_id", "llm_api_key", "llm_base_url",
    "llm_timeout", "llm_max_retries", "llm_temperature",
    "llm_max_tokens", "llm_json_mode",
    # Search
    "fofa_base_url", "fofa_email", "fofa_key",
    "hunter_api_key", "quake_api_key", "shodan_api_key",
    # ENScan 数据源
    "enscan_aqc_cookie", "enscan_tyc_cookie", "enscan_icp_cookie",
}

KEY_MAPPING = {
    # LLM
    "llm_provider":      "LLM_PROVIDER",
    "llm_model_id":      "LLM_MODEL_ID",
    "llm_api_key":       "LLM_API_KEY",
    "llm_base_url":      "LLM_BASE_URL",
    "llm_timeout":       "LLM_TIMEOUT",
    "llm_max_retries":   "LLM_MAX_RETRIES",
    "llm_temperature":   "LLM_TEMPERATURE",
    "llm_max_tokens":    "LLM_MAX_TOKENS",
    "llm_json_mode":     "LLM_JSON_MODE",
    # Search
    "fofa_base_url":     "FOFA_BASE_URL",
    "fofa_email":        "FOFA_EMAIL",
    "fofa_key":          "FOFA_KEY",
    "hunter_api_key":    "HUNTER_API_KEY",
    "quake_api_key":     "QUAKE_API_KEY",
    "shodan_api_key":    "SHODAN_API_KEY",
    # ENScan
    "enscan_aqc_cookie": "FOFA_EMAIL",   # 复用不会冲突的 key
    "enscan_tyc_cookie": "FOFA_KEY",     # 这些持久化在 config.yaml
    "enscan_icp_cookie": "HUNTER_API_KEY",
}


# ── .env 读写 ───────────────────────────────────────────

def _read_env_file():
    if not os.path.exists(ENV_PATH):
        return {}
    result = {}
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def _write_env_file(updates: dict):
    existing = _read_env_file()
    existing.update(updates)

    lines = []
    updated_keys = set(updates.keys())
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key = stripped.split("=", 1)[0].strip()
                    if key in existing:
                        line = f"{key}={existing[key]}\n"
                lines.append(line)

    for key, val in existing.items():
        found = any(l.strip().startswith(f"{key}=") for l in lines)
        if not found:
            lines.append(f"{key}={val}\n")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)


# ── enscan config.yaml 读写 ─────────────────────────────

def _ensure_enscan_config():
    """确保 enscan 配置文件存在, 不存在则用模板创建"""
    ENSCAN_CONFIG_YAML.parent.mkdir(parents=True, exist_ok=True)
    if not ENSCAN_CONFIG_YAML.exists():
        ENSCAN_CONFIG_YAML.write_text(ENSCAN_CONFIG_TEMPLATE, encoding="utf-8")


def _read_enscan_yaml():
    """读取 enscan config.yaml → {source: cookie}"""
    _ensure_enscan_config()
    cookies = {}
    try:
        text = ENSCAN_CONFIG_YAML.read_text(encoding="utf-8")
    except Exception:
        return cookies

    import re
    for source in ("aqc", "tyc", "icp"):
        m = re.search(rf'{source}:\s*\n\s+cookie:\s*"(.*?)"', text)
        if m:
            cookies[source] = m.group(1)
    return cookies


def _write_enscan_yaml(cookies: dict):
    """写入 enscan config.yaml, 保留其他配置不变"""
    _ensure_enscan_config()
    try:
        text = ENSCAN_CONFIG_YAML.read_text(encoding="utf-8")
    except Exception:
        text = ENSCAN_CONFIG_TEMPLATE

    import re
    for source, cookie in cookies.items():
        if not cookie:
            continue
        pattern = rf'({source}:\s*\n\s+cookie:\s*)"(.*?)"'
        replacement = rf'\1"{cookie}"'
        text = re.sub(pattern, replacement, text, count=1)

    ENSCAN_CONFIG_YAML.write_text(text, encoding="utf-8")


# ── API 路由 ────────────────────────────────────────────

@api_bp.route("/settings", methods=["GET"])
def get_settings():
    """读取系统配置 + enscan Cookie"""
    try:
        base = Config.to_dict(include_sensitive=True)
        enscan = _read_enscan_yaml()
        base["enscan"] = {
            "aqc_cookie": Config._mask(enscan.get("aqc", "")),
            "tyc_cookie": Config._mask(enscan.get("tyc", "")),
            "icp_cookie": Config._mask(enscan.get("icp", "")),
        }
        return jsonify({"ok": True, "settings": base})
    except Exception as e:
        return jsonify({"ok": False, "error": f"读取配置失败: {str(e)}"}), 500


@api_bp.route("/settings", methods=["POST"])
def save_settings():
    """保存 .env + 同步 enscan Cookie"""
    try:
        payload = request.get_json(silent=True) or {}
        if not payload:
            return jsonify({"ok": False, "error": "请求体为空"}), 400

        env_updates = {}
        yaml_updates = {}
        enscan_keys = {"enscan_aqc_cookie", "enscan_tyc_cookie", "enscan_icp_cookie"}

        for field, value in payload.items():
            if field not in ALLOWED_KEYS:
                continue
            if field in enscan_keys:
                source = field.replace("enscan_", "").replace("_cookie", "")
                yaml_updates[source] = str(value)
            else:
                env_key = KEY_MAPPING.get(field, field.upper())
                env_updates[env_key] = str(value)

        updated = []
        if env_updates:
            _write_env_file(env_updates)
            updated.extend(env_updates.keys())
        if yaml_updates:
            _write_enscan_yaml(yaml_updates)
            updated.extend(yaml_updates.keys())

        if not updated:
            return jsonify({"ok": False, "error": "没有可更新的字段"}), 400

        return jsonify({
            "ok": True,
            "message": "配置已保存, 部分配置需重启应用生效",
            "updated_fields": updated,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"保存配置失败: {str(e)}"}), 500


@api_bp.route("/settings/enscan", methods=["GET"])
def get_enscan_cookies():
    """单独获取 enscan Cookie 配置"""
    try:
        cookies = _read_enscan_yaml()
        return jsonify({
            "ok": True,
            "config_path": str(ENSCAN_CONFIG_YAML),
            "cookies": {
                "aqc": Config._mask(cookies.get("aqc", "")),
                "tyc": Config._mask(cookies.get("tyc", "")),
                "icp": Config._mask(cookies.get("icp", "")),
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@api_bp.route("/settings/enscan", methods=["POST"])
def save_enscan_cookies():
    """单独保存 enscan Cookie"""
    try:
        payload = request.get_json(silent=True) or {}
        yaml_updates = {}
        for source in ("aqc", "tyc", "icp"):
            key = f"enscan_{source}_cookie"
            if key in payload and payload[key]:
                yaml_updates[source] = str(payload[key])

        if not yaml_updates:
            return jsonify({"ok": False, "error": "未提供有效的 Cookie"}), 400

        _write_enscan_yaml(yaml_updates)
        return jsonify({
            "ok": True,
            "config_path": str(ENSCAN_CONFIG_YAML),
            "message": "Cookie 已保存到 enscan 配置文件",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
