import argparse
import hashlib
import json
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sniff_signature(path: Path) -> Tuple[Optional[str], Optional[str]]:
    """
    用简单文件头签名判断常见格式，返回 (file_type, error)。
    - file_type: 'tiff'/'pdf'/'png'/'jpeg'/'gif'/None
    
    """
    try:
        with path.open("rb") as f:
            head = f.read(16)
    except Exception as e:  # noqa: BLE001
        return None, f"无法读取文件: {e}"

    # PDF: %PDF-
    if head.startswith(b"%PDF-"):
        return "pdf", None
    # PNG signature
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", None
    # JPEG: FF D8 FF
    if head[:3] == b"\xFF\xD8\xFF":
        return "jpeg", None
    # GIF87a/GIF89a
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "gif", None
    # TIFF: II*\x00 or MM\x00*
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff", None

    return None, None


def _infer_poc_type(poc_meta: Dict[str, Any]) -> Optional[str]:
    """
    从数据集 manifest 的 poc 字段做一个弱推断。
    """
    oracle = poc_meta.get("oracle_hint")
    if isinstance(oracle, str):
        low = oracle.lower()
        if "timeout" in low or "hang" in low:
            return "dos"
        if "crash" in low or "segfault" in low:
            return "crash"
    return poc_meta.get("type") if isinstance(poc_meta.get("type"), str) else None


@dataclass
class PoCRecord:
    file_path: str
    exists: bool
    valid: bool
    file_ext: str
    detected_type: Optional[str]
    mime_type: Optional[str]
    sha256: Optional[str]
    poc_type: Optional[str]
    error: Optional[str] = None


class PoCHandler:
    """
    作用：
    - 校验 PoC 文件可读性/基础格式（不做深度解包验证）
    - 提取元数据：路径、扩展名、检测到的类型、MIME、sha256、PoC 类型（可选）
    - 输出 poc_index.json

    输入：
    - PoC file path 列表，或单个路径
    -（可选）manifest.json / manifest_resolved.json 中的 poc 字段，用于补充 poc_type/oracle 信息
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def index_pocs(self, poc_files: List[Path], poc_meta: Optional[Dict[str, Any]] = None) -> Path:
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)

        records: List[Dict[str, Any]] = []
        for p in poc_files:
            p = p.expanduser()
            exists = p.exists()
            ext = p.suffix.lower()
            mime = mimetypes.guess_type(str(p))[0]

            if not exists:
                rec = PoCRecord(
                    file_path=str(p),
                    exists=False,
                    valid=False,
                    file_ext=ext,
                    detected_type=None,
                    mime_type=mime,
                    sha256=None,
                    poc_type=_infer_poc_type(poc_meta or {}) if poc_meta else None,
                    error="文件不存在",
                )
                records.append(rec.__dict__)
                continue

            detected_type, err = _sniff_signature(p)
            sha = None
            valid = err is None
            if valid:
                try:
                    sha = _sha256_file(p)
                except Exception as e:  # noqa: BLE001
                    valid = False
                    err = f"计算 SHA256 失败: {e}"

            rec = PoCRecord(
                file_path=str(p.resolve()),
                exists=True,
                valid=valid,
                file_ext=ext,
                detected_type=detected_type,
                mime_type=mime,
                sha256=sha,
                poc_type=_infer_poc_type(poc_meta or {}) if poc_meta else None,
                error=err,
            )
            records.append(rec.__dict__)

        out = self.output_dir / "poc_index.json"
        with out.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "meta": {"count": len(records)},
                    "pocs": records,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        return out


def _load_manifest_poc_meta(manifest_path: Path) -> Optional[Dict[str, Any]]:
    if not manifest_path:
        return None
    if not manifest_path.is_file():
        return None
    try:
        obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    poc = obj.get("poc")
    return poc if isinstance(poc, dict) else None


def main() -> None:
    parser = argparse.ArgumentParser(description="验证 PoC 文件有效性并提取元数据，生成 poc_index.json")
    parser.add_argument("output_dir", help="输出目录")
    parser.add_argument("poc_files", nargs="+", help="PoC 文件路径（一个或多个）")
    parser.add_argument("--manifest", default=None, help="可选：样本 manifest.json 路径（用于补充 PoC 类型/提示）")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    poc_files = [Path(p) for p in args.poc_files]
    poc_meta = _load_manifest_poc_meta(Path(args.manifest)) if args.manifest else None

    handler = PoCHandler(output_dir=output_dir)
    out = handler.index_pocs(poc_files=poc_files, poc_meta=poc_meta)
    print(f"已生成: {out.resolve()}")


if __name__ == "__main__":
    main()

