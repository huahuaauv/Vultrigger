"""
一次请求：询问模型自身身份（名称/厂商/请求中的 model 等）。
依赖：pip install openai python-dotenv

用法（在项目根 b/work 下）:
  复制 config/dashscope.env.example -> config/dashscope.env，填写 DASHSCOPE_API_KEY
  python scripts/test_dashscope_once.py

或临时指定:
  set DASHSCOPE_API_KEY=sk-xxx && python scripts/test_dashscope_once.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.third_phase.llm_client import _load_project_dotenv_files  # noqa: E402


def main() -> int:
    _load_project_dotenv_files(ROOT)
    api_key = (os.getenv("DASHSCOPE_API_KEY") or "").strip()
    if not api_key:
        print(
            "未设置 DASHSCOPE_API_KEY。\n"
            "请复制 config/dashscope.env.example 为 config/dashscope.env，填写密钥后再运行。",
            file=sys.stderr,
        )
        return 2

    base_url = (
        os.getenv("DASHSCOPE_BASE_URL") or "https://dashscope.aliyuncs.com/compatible-mode/v1"
    ).strip()
    model = (os.getenv("DASHSCOPE_MODEL") or "qwen3.6-plus").strip()
    _think = os.getenv("DASHSCOPE_ENABLE_THINKING", "1").strip().lower()
    use_thinking = _think not in ("0", "false", "no", "off")

    try:
        from openai import OpenAI, OpenAIError
    except ImportError:
        print("请先安装: pip install openai", file=sys.stderr)
        return 3

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=120)
    user_q = (
        "请用中文回答：你具体是哪个大模型？请给出可核对的细节（例如服务商标识、"
        "本次 API 请求里使用的 model 名称、以及你如何确认自己不是其它模型）。"
        "回答尽量简洁但信息要具体。"
    )
    messages = [{"role": "user", "content": user_q}]

    extra_body: dict = {}
    if use_thinking:
        extra_body["enable_thinking"] = True

    print("--- 请求 ---", flush=True)
    print(f"base_url={base_url}\nmodel={model}\nextra_body={extra_body or '{}'}\n", flush=True)

    try:
        if extra_body.get("enable_thinking"):
            # 与官方教程一致：流式读取 reasoning_content + content
            stream = client.chat.completions.create(
                model=model,
                messages=messages,
                extra_body=extra_body,
                stream=True,
            )
            reasoning_buf: list[str] = []
            content_buf: list[str] = []
            is_answering = False
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                rc = getattr(delta, "reasoning_content", None)
                if rc:
                    if not is_answering:
                        reasoning_buf.append(rc)
                c = getattr(delta, "content", None) or ""
                if c:
                    if not is_answering:
                        is_answering = True
                    content_buf.append(c)

            reasoning = "".join(reasoning_buf).strip()
            content = "".join(content_buf).strip()
            print("--- 思考过程（若有）---")
            print(reasoning or "(无)")
            print("\n--- 模型回复 ---")
            print(content or "(空)")
        else:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                extra_body=extra_body if extra_body else None,
                stream=False,
            )
            msg = resp.choices[0].message
            rc = getattr(msg, "reasoning_content", None)
            if rc:
                print("--- 思考过程（若有）---")
                print(str(rc).strip())
                print()
            print("--- 模型回复 ---")
            print((msg.content or "").strip())
    except OpenAIError as e:
        body = getattr(e, "message", str(e))
        code = getattr(e, "status_code", None)
        prefix = f"HTTP {code} " if code else ""
        print(f"API 调用失败: {prefix}{body}", file=sys.stderr)
        return 1

    print("\n--- 完成 ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
