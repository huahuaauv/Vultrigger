from __future__ import annotations
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Optional, List

@dataclass
class CmdResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    cmd: List[str]

def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    timeout_sec: Optional[int] = None,
    log_path: Optional[Path] = None,
) -> CmdResult:
    """
    运行命令并返回结果。
    
    错误处理：
    - 如果命令不存在，会抛出 FileNotFoundError
    - 如果超时，会抛出 subprocess.TimeoutExpired
    - 其他错误会记录在 CmdResult 中
    """
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
    except FileNotFoundError as e:
        # 命令不存在
        error_msg = f"命令未找到: {cmd[0] if cmd else 'unknown'}\n请确保该命令已安装并在 PATH 中"
        result = CmdResult(
            ok=False,
            returncode=-1,
            stdout="",
            stderr=error_msg,
            cmd=cmd,
        )
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {' '.join(cmd)}\n\n--- ERROR ---\n{error_msg}\n原始异常: {e}\n",
                encoding="utf-8",
            )
        return result
    except subprocess.TimeoutExpired as e:
        # 超时
        timeout_msg = f"命令执行超时（{timeout_sec} 秒）: {' '.join(cmd)}"
        result = CmdResult(
            ok=False,
            returncode=-2,
            stdout=e.stdout.decode("utf-8", errors="replace") if e.stdout else "",
            stderr=timeout_msg,
            cmd=cmd,
        )
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {' '.join(cmd)}\n\n--- TIMEOUT ---\n{timeout_msg}\n",
                encoding="utf-8",
            )
        return result
    except Exception as e:
        # 其他错误
        error_msg = f"执行命令时出错: {e}"
        result = CmdResult(
            ok=False,
            returncode=-3,
            stdout="",
            stderr=error_msg,
            cmd=cmd,
        )
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {' '.join(cmd)}\n\n--- ERROR ---\n{error_msg}\n",
                encoding="utf-8",
            )
        return result

    # 正常执行完成
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"$ {' '.join(cmd)}\n\n--- STDOUT ---\n{p.stdout}\n\n--- STDERR ---\n{p.stderr}\n\n--- RETURN CODE ---\n{p.returncode}\n",
            encoding="utf-8",
        )
    return CmdResult(
        ok=(p.returncode == 0),
        returncode=p.returncode,
        stdout=p.stdout,
        stderr=p.stderr,
        cmd=cmd,
    )
