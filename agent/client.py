import os
from pathlib import Path
from typing import List, Optional

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None


class OpenAICompatibleClient:
    """中文注释：兼容 OpenAI 风格接口，支持基于 messages 的多轮对话。"""

    _env_loaded = False

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self._load_local_env_once()

        self.model = model or os.getenv("LLM_MODEL_ID") or os.getenv("MODEL_ID")
        api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("API_KEY")
        base_url = base_url or os.getenv("LLM_BASE_URL") or os.getenv("BASE_URL")
        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", "60"))

        if not all([self.model, api_key, base_url]):
            raise ValueError("LLM 配置不完整，请检查 MODEL_ID/API_KEY/BASE_URL。")
        if OpenAI is None:
            raise ImportError("未安装 openai 依赖，请先执行: pip install -r requirement.txt")

        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=self.timeout)

    @classmethod
    def _load_local_env_once(cls) -> None:
        if cls._env_loaded:
            return

        env_path = Path(__file__).resolve().parent / ".env"
        if not env_path.exists():
            cls._env_loaded = True
            return

        for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            # 中文注释：跳过注释、展示命令和不规范行
            if not line or line.startswith("#") or line.startswith(">") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value and os.getenv(key) is None:
                os.environ[key] = value

        cls._env_loaded = True

    def chat(self, messages: List[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=False,
        )
        return (response.choices[0].message.content or "").strip()

    def generate(self, prompt: str, system_prompt: str) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        return self.chat(messages)
