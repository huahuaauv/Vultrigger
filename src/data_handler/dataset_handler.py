from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .dataset_downloader import DatasetDownloader


def run_dataset_download(
    manifest_path: str = "config/dataset_manifest.yaml",
    dataset_root: str = "dataset/raw",
    metadata_root: str = "dataset/metadata",
    logs_dir: str = "logs",
    case_ids: Optional[set[str]] = None,
) -> dict[str, Any]:
    downloader = DatasetDownloader(
        manifest_path=Path(manifest_path),
        dataset_root=Path(dataset_root),
        metadata_root=Path(metadata_root),
        logs_dir=Path(logs_dir),
    )
    return downloader.process_cases(selected_case_ids=case_ids)
