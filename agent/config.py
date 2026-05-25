import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .errors import LLMConfigError


@dataclass
class LLMConfig:
    provider: str
    model_id: str
    api_key: str
    base_url: str
    timeout: float = 60.0
    max_retries: int = 2
    temperature: float = 0.0
    max_tokens: Optional[int] = 1024
    json_mode: bool = False


_ENV_LOADED = False


def _load_local_env_once() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return

    current = Path(__file__).resolve()
    env_candidates = [
        current.parent / ".env",
        current.parent.parent / ".env",
    ]

    for env_path in env_candidates:
        if not env_path.exists():
            continue

        for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(">") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value and os.getenv(key) is None:
                os.environ[key] = value

    _ENV_LOADED = True


def _first_env(keys: Iterable[str], default: Optional[str] = None) -> Optional[str]:
    for key in keys:
        value = os.getenv(key)
        if value:
            return value
    return default


def _to_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _to_optional_int(value: Optional[str], default: Optional[int]) -> Optional[int]:
    if value is None:
        return default

    stripped = str(value).strip().lower()
    if stripped in {"", "none", "null"}:
        return None

    return int(stripped)


def load_llm_config() -> LLMConfig:
    _load_local_env_once()

    return LLMConfig(
        provider=_first_env(["LLM_PROVIDER"], default="openai_compat") or "openai_compat",
        model_id=_first_env(["LLM_MODEL_ID", "MODEL_ID", "DEEPSEEK_MODEL"], default="") or "",
        api_key=_first_env(["LLM_API_KEY", "API_KEY", "DEEPSEEK_API_KEY"], default="") or "",
        base_url=_first_env(["LLM_BASE_URL", "BASE_URL", "DEEPSEEK_API_URL"], default="") or "",
        timeout=float(_first_env(["LLM_TIMEOUT"], default="60") or "60"),
        max_retries=int(_first_env(["LLM_MAX_RETRIES"], default="2") or "2"),
        temperature=float(_first_env(["LLM_TEMPERATURE"], default="0") or "0"),
        max_tokens=_to_optional_int(_first_env(["LLM_MAX_TOKENS"], default="1024"), 1024),
        json_mode=_to_bool(_first_env(["LLM_JSON_MODE"], default="false"), default=False),
    )


def validate_llm_config(config: LLMConfig) -> None:
    missing = []

    if not config.model_id:
        missing.append("LLM_MODEL_ID 或 MODEL_ID")
    if not config.api_key:
        missing.append("LLM_API_KEY 或 API_KEY")
    if not config.base_url:
        missing.append("LLM_BASE_URL 或 BASE_URL")

    if missing:
        raise LLMConfigError("模型配置不完整，缺少：" + "、".join(missing))

    if config.provider != "openai_compat":
        raise LLMConfigError("当前仅支持 LLM_PROVIDER=openai_compat")

    if not config.base_url.startswith(("http://", "https://")):
        raise LLMConfigError("LLM_BASE_URL / BASE_URL 必须以 http:// 或 https:// 开头")

    if config.timeout <= 0:
        raise LLMConfigError("LLM_TIMEOUT 必须大于 0")

    if config.max_retries < 0:
        raise LLMConfigError("LLM_MAX_RETRIES 不能小于 0")

    if config.max_tokens is not None and config.max_tokens <= 0:
        raise LLMConfigError("LLM_MAX_TOKENS 必须大于 0 或留空")
