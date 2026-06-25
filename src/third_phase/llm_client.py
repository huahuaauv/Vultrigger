from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv
except ImportError:

    def load_dotenv(*_a: Any, **_k: Any) -> bool:
        return False


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_project_dotenv_files(root: Optional[Path] = None) -> Path:
    root_path = root or _project_root()
    load_dotenv(root_path / ".env")
    for name in ("qwen.env", "dashscope.env"):
        p = root_path / "config" / name
        if p.is_file():
            load_dotenv(p, override=True)
    return root_path


class LLMClient:
    def invoke(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        raise NotImplementedError


@dataclass
class LLMConfig:
    provider: str
    api_base: str
    api_key: str
    prompt_model: str
    generator_model: str
    debugger_model: str
    verifier_model: str
    request_timeout_sec: int = 60
    max_tokens: int = 4096
    temperature: float = 0.2
    extra_body: Dict[str, Any] = field(default_factory=dict)


def _read_json_strip_comments(p: Path) -> Dict[str, Any]:
    raw = p.read_text(encoding="utf-8")
    if "/*" in raw and "*/" in raw:
        raw = raw.split("/*", 1)[0]
    return json.loads(raw)


def load_llm_config(config_path: Optional[str] = None) -> LLMConfig:
    root = _project_root()
    cfg_path = (
        Path(config_path).resolve()
        if config_path
        else Path(os.getenv("LLM_CONFIG", "")).resolve()
        if os.getenv("LLM_CONFIG")
        else (root / "config" / "llm_config.json")
    )
    if not cfg_path.is_file():
        raise FileNotFoundError(
            f"LLM config file not found: {cfg_path}\n"
            "Copy config/llm_config.example.json or config/llm_config.qwen.example.json "
            "to config/llm_config.json and fill api_key."
        )
    data = _read_json_strip_comments(cfg_path)

    prompt_model = data.get("prompt_model") or data.get("planner_model") or data.get("model") or ""
    generator_model = data.get("generator_model") or data.get("coder_model") or data.get("model") or ""
    verifier_model = data.get("verifier_model") or data.get("model") or ""
    debugger_model = data.get("debugger_model") or verifier_model or data.get("model") or ""

    raw_extra = data.get("extra_body")
    extra_body: Dict[str, Any] = {}
    if isinstance(raw_extra, dict):
        extra_body.update(raw_extra)
    if bool(data.get("enable_thinking", False)):
        extra_body["enable_thinking"] = True

    return LLMConfig(
        provider=str(data.get("provider", "openai")),
        api_base=str(data.get("api_base", "https://api.openai.com/v1")),
        api_key=str(data.get("api_key", "")),
        prompt_model=str(prompt_model),
        generator_model=str(generator_model),
        debugger_model=str(debugger_model),
        verifier_model=str(verifier_model),
        request_timeout_sec=int(data.get("request_timeout_sec", 60)),
        max_tokens=int(data.get("max_tokens", 4096)),
        temperature=float(data.get("temperature", 0.2)),
        extra_body=extra_body,
    )


class OpenAICompatibleClient(LLMClient):
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout_sec: int,
        max_tokens: int,
        extra_body: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError("openai package is required for LLM calls; pip install openai") from e
        self._model = model
        self._max_tokens = max_tokens
        self._extra_body: Dict[str, Any] = dict(extra_body or {})
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_sec)

    def invoke(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        kwargs: Dict[str, Any] = dict(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=self._max_tokens,
        )
        if self._extra_body:
            kwargs["extra_body"] = self._extra_body
        resp = self._client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        return (getattr(msg, "content", None) or "") or ""


def try_build_optional_llm_from_config_file(
    config_path: Optional[str] = None,
) -> OpenAICompatibleClient | None:
    clients = try_build_optional_llm_clients_from_config_file(config_path)
    return None if clients is None else clients["generator"]


def try_build_optional_llm_clients_from_config_file(
    config_path: Optional[str] = None,
) -> Dict[str, LLMClient] | None:
    root = _project_root()
    if config_path:
        cfg_path = Path(config_path).resolve()
    elif os.getenv("LLM_CONFIG", "").strip():
        cfg_path = Path(os.getenv("LLM_CONFIG", "").strip()).resolve()
    else:
        cfg_path = root / "config" / "llm_config.json"
    if not cfg_path.is_file():
        return None
    cfg = load_llm_config(str(cfg_path))
    return build_llm_clients(cfg)


def try_build_optional_llm_from_env(
    *,
    timeout_sec: int = 600,
    max_tokens: int = 8192,
) -> OpenAICompatibleClient | None:
    _load_project_dotenv_files()

    api_key = (
        os.getenv("OPENAI_API_KEY") or os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY") or ""
    ).strip()
    if not api_key:
        return None

    base_url = (
        (os.getenv("OPENAI_BASE_URL") or "").strip()
        or (os.getenv("QWEN_BASE_URL") or "").strip()
        or (os.getenv("DASHSCOPE_BASE_URL") or "").strip()
    )
    if not base_url:
        if os.getenv("DASHSCOPE_API_KEY", "").strip() and not (
            os.getenv("OPENAI_API_KEY", "").strip() or os.getenv("QWEN_API_KEY", "").strip()
        ):
            base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
        else:
            base_url = "https://api.openai.com/v1"

    model = (
        (os.getenv("OPENAI_MODEL") or "").strip()
        or (os.getenv("QWEN_MODEL") or "").strip()
        or (os.getenv("DASHSCOPE_MODEL") or "").strip()
    )
    if not model:
        model = "qwen3.6-plus" if os.getenv("DASHSCOPE_API_KEY", "").strip() else "gpt-4o-mini"

    extra: Dict[str, Any] = {}
    if os.getenv("DASHSCOPE_ENABLE_THINKING", "").strip().lower() in ("1", "true", "yes"):
        extra["enable_thinking"] = True

    return OpenAICompatibleClient(
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout_sec=timeout_sec,
        max_tokens=max_tokens,
        extra_body=extra if extra else None,
    )


def try_build_optional_llm_clients_from_env(
    *,
    timeout_sec: int = 600,
    max_tokens: int = 8192,
) -> Dict[str, LLMClient] | None:
    client = try_build_optional_llm_from_env(timeout_sec=timeout_sec, max_tokens=max_tokens)
    if client is None:
        return None
    return {
        "prompt": client,
        "generator": client,
        "debugger": client,
        "verifier": client,
    }


def build_llm_clients(config: LLMConfig) -> Dict[str, LLMClient]:
    _load_project_dotenv_files()

    api_key = (
        config.api_key
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("QWEN_API_KEY")
        or os.getenv("DASHSCOPE_API_KEY")
        or ""
    ).strip()
    if not api_key:
        raise RuntimeError(
            "No LLM api_key found. Fill config/llm_config.json or set "
            "OPENAI_API_KEY / QWEN_API_KEY / DASHSCOPE_API_KEY."
        )

    base_url = (
        (config.api_base or "").strip()
        or (os.getenv("OPENAI_BASE_URL") or "").strip()
        or (os.getenv("QWEN_BASE_URL") or "").strip()
        or (os.getenv("DASHSCOPE_BASE_URL") or "").strip()
    )
    if not base_url:
        base_url = "https://api.openai.com/v1"

    def mk(model: str) -> LLMClient:
        if not model:
            raise RuntimeError("LLM config missing model field for one of prompt/generator/debugger/verifier.")
        eb = dict(config.extra_body) if config.extra_body else None
        return OpenAICompatibleClient(
            api_key=api_key,
            base_url=base_url,
            model=model,
            timeout_sec=config.request_timeout_sec,
            max_tokens=config.max_tokens,
            extra_body=eb,
        )

    return {
        "prompt": mk(config.prompt_model),
        "generator": mk(config.generator_model),
        "debugger": mk(config.debugger_model),
        "verifier": mk(config.verifier_model),
    }
