import time
from dataclasses import replace
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None

try:
    import openai as legacy_openai
except ImportError:  # pragma: no cover
    legacy_openai = None

from .config import LLMConfig, load_llm_config, validate_llm_config
from .errors import (
    LLMAuthError,
    LLMConfigError,
    LLMConnectionError,
    LLMError,
    LLMRateLimitError,
    LLMResponseError,
    LLMServerError,
    LLMTimeoutError,
)
from .model_result import ModelResult


class LLMClient:
    """兼容 OpenAI-like API 的模型客户端，对外保持 chat(messages) -> str。"""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None,
        config: Optional[LLMConfig] = None,
    ):
        try:
            loaded = config or load_llm_config()
            self.config = replace(
                loaded,
                model_id=model or loaded.model_id,
                api_key=api_key or loaded.api_key,
                base_url=base_url or loaded.base_url,
                timeout=float(timeout) if timeout is not None else loaded.timeout,
            )
            validate_llm_config(self.config)
        except LLMConfigError:
            raise
        except Exception as exc:
            raise LLMConfigError(str(exc))

        self.client = None
        self._sdk_mode = None

        if OpenAI is not None and hasattr(OpenAI, "__call__"):
            self.client = OpenAI(
                api_key=self.config.api_key,
                base_url=self.config.base_url,
                timeout=self.config.timeout,
            )
            self._sdk_mode = "modern"
        elif legacy_openai is not None and hasattr(legacy_openai, "ChatCompletion"):
            legacy_openai.api_key = self.config.api_key
            legacy_openai.api_base = self.config.base_url
            self._sdk_mode = "legacy_chat"
        elif legacy_openai is not None:
            raise LLMConfigError(
                "当前 openai SDK 版本过旧，不支持 ChatCompletion。请安装支持聊天接口的版本，例如: "
                "python -m pip install --user \"openai>=0.27,<1\""
            )
        else:
            raise LLMConfigError("未安装 openai 依赖，请先执行: pip install -r requirement.txt")

    def chat(self, messages: List[Dict[str, str]]) -> str:
        return self._chat_with_retry(messages)

    def generate(self, prompt: str, system_prompt: str) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        return self.chat(messages)

    def health_check(self) -> Dict[str, Any]:
        try:
            content = self.chat(
                [
                    {"role": "system", "content": "你是模型连通性测试助手。"},
                    {"role": "user", "content": "请只回复 ok"},
                ]
            )
            return {
                "ok": True,
                "model": self.config.model_id,
                "base_url": self.config.base_url,
                "content": content,
            }
        except Exception as exc:
            return {
                "ok": False,
                "model": self.config.model_id,
                "base_url": self.config.base_url,
                "error": str(exc),
            }

    def _chat_with_retry(self, messages: List[Dict[str, str]]) -> str:
        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries + 1):
            try:
                return self._chat_once(messages)
            except (LLMTimeoutError, LLMConnectionError, LLMServerError) as exc:
                last_error = exc
                if attempt >= self.config.max_retries:
                    break
                time.sleep(min(2 ** attempt, 8))
            except LLMError:
                raise
            except Exception as exc:
                last_error = exc
                if attempt >= self.config.max_retries:
                    break
                time.sleep(min(2 ** attempt, 8))

        raise LLMError("模型调用失败，已重试 {} 次：{}".format(self.config.max_retries, last_error))

    def _chat_once(self, messages: List[Dict[str, str]]) -> str:
        payload: Dict[str, Any] = {
            "model": self.config.model_id,
            "messages": messages,
            "temperature": self.config.temperature,
        }

        if self.config.max_tokens is not None:
            payload["max_tokens"] = self.config.max_tokens

        if self.config.json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            response = self._create_completion(payload)
        except LLMConfigError as exc:
            if self.config.json_mode and payload.get("response_format") and self._should_fallback_json_mode(exc):
                downgraded = dict(payload)
                downgraded.pop("response_format", None)
                response = self._create_completion(downgraded)
            else:
                raise

        result = self._extract_result(response)
        return result.content

    def _create_completion(self, payload: Dict[str, Any]) -> Any:
        try:
            if self._sdk_mode == "legacy_chat":
                return legacy_openai.ChatCompletion.create(**payload)
            if self._sdk_mode == "modern":
                return self.client.chat.completions.create(stream=False, **payload)
            raise LLMConfigError("未识别的 openai SDK 模式")
        except Exception as exc:
            raise self._convert_openai_error(exc)

    def _extract_result(self, response: Any) -> ModelResult:
        try:
            choices = response["choices"] if isinstance(response, dict) else getattr(response, "choices", None)
            if not choices:
                raise LLMResponseError("模型响应中没有 choices")

            first_choice = choices[0]
            message = first_choice["message"] if isinstance(first_choice, dict) else getattr(first_choice, "message", None)
            if not message:
                raise LLMResponseError("模型响应中没有 message")

            content = message["content"] if isinstance(message, dict) else getattr(message, "content", None)
            if content is None:
                raise LLMResponseError("模型响应 content 为空")

            normalized = str(content).strip()
            if not normalized:
                raise LLMResponseError("模型返回了空字符串")

            finish_reason = (
                first_choice.get("finish_reason")
                if isinstance(first_choice, dict)
                else getattr(first_choice, "finish_reason", None)
            )
            request_id = (
                response.get("id")
                if isinstance(response, dict)
                else getattr(response, "id", None)
            )
            return ModelResult(
                content=normalized,
                finish_reason=finish_reason,
                request_id=request_id,
                raw_response=response,
            )
        except LLMResponseError:
            raise
        except Exception as exc:
            raise LLMResponseError("模型响应结构异常：{}".format(exc))

    def _convert_openai_error(self, exc: Exception) -> LLMError:
        message = self._sanitize_error_message(str(exc))
        status_code = self._extract_status_code(exc)
        lowered = message.lower()
        name = exc.__class__.__name__.lower()

        if status_code in {401, 403}:
            return LLMAuthError("模型认证失败：{}".format(message))
        if status_code == 429:
            return LLMRateLimitError("模型服务限流：{}".format(message))
        if status_code == 404:
            return LLMConfigError("模型不存在或 Base URL 错误：{}".format(message))
        if status_code == 400:
            return LLMConfigError("模型请求参数错误：{}".format(message))
        if status_code in {500, 502, 503, 504}:
            return LLMServerError("模型服务端异常：{}".format(message))

        if "timeout" in lowered or "timed out" in lowered or "apitimeouterror" in name:
            return LLMTimeoutError("模型请求超时：{}".format(message))
        if "connection" in lowered or "connect" in lowered or "apiconnectionerror" in name:
            return LLMConnectionError("模型连接失败：{}".format(message))
        if "json_object" in lowered or "response_format" in lowered:
            return LLMConfigError("模型不支持 JSON Mode，请关闭 LLM_JSON_MODE：{}".format(message))

        return LLMError("模型调用异常：{}".format(message))

    def _extract_status_code(self, exc: Exception) -> Optional[int]:
        direct = getattr(exc, "status_code", None)
        if isinstance(direct, int):
            return direct

        http_status = getattr(exc, "http_status", None)
        if isinstance(http_status, int):
            return http_status

        response = getattr(exc, "response", None)
        if response is not None:
            response_status = getattr(response, "status_code", None)
            if isinstance(response_status, int):
                return response_status

        return None

    def _sanitize_error_message(self, message: str) -> str:
        api_key = self.config.api_key or ""
        sanitized = message
        if api_key and api_key in sanitized:
            sanitized = sanitized.replace(api_key, self._mask_secret(api_key))
        return sanitized

    def _mask_secret(self, value: str) -> str:
        if len(value) <= 8:
            return "***"
        return "{}***{}".format(value[:4], value[-4:])

    def _should_fallback_json_mode(self, exc: Exception) -> bool:
        message = str(exc).lower()
        return "json mode" in message or "json_object" in message or "response_format" in message


OpenAICompatibleClient = LLMClient
