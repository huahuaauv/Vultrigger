from __future__ import annotations

import argparse
import csv
import json
import logging
import shutil
import subprocess
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import yaml


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_cmd(args: list[str], cwd: Optional[Path] = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def is_valid_git_repo(dst: Path) -> bool:
    if not dst.is_dir():
        return False
    result = run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=dst, timeout=30)
    return result.returncode == 0 and result.stdout.strip() == "true"


def is_nonempty_source_tree(dst: Path) -> bool:
    if not dst.is_dir():
        return False
    if not any(dst.iterdir()):
        return False
    expected_markers = ["pom.xml", "build.gradle", "build.gradle.kts", "src", ".git", "README.md"]
    return any((dst / marker).exists() for marker in expected_markers)


def git_current_commit(dst: Path) -> str:
    result = run_cmd(["git", "rev-parse", "HEAD"], cwd=dst, timeout=30)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def reset_directory(dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)


def git_clone_or_update(repo: str, dst: Path, retries: int = 2, logger: Optional[logging.Logger] = None) -> None:
    last_err = ""
    for attempt in range(retries + 1):
        try:
            if dst.exists() and is_valid_git_repo(dst):
                fetch = run_cmd(["git", "fetch", "--all", "--tags", "--prune"], cwd=dst, timeout=600)
                if fetch.returncode == 0:
                    return
                last_err = fetch.stderr.strip() or fetch.stdout.strip()
            else:
                if dst.exists():
                    reset_directory(dst)
                dst.parent.mkdir(parents=True, exist_ok=True)
                clone = run_cmd(["git", "clone", repo, str(dst)], timeout=1200)
                if clone.returncode == 0:
                    return
                last_err = clone.stderr.strip() or clone.stdout.strip()
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
        if logger:
            logger.warning("clone/update attempt %s failed for %s: %s", attempt + 1, repo, last_err)
    raise RuntimeError(last_err or f"failed to clone/update {repo}")


def git_checkout(dst: Path, ref: str, checkout_type: str = "auto") -> None:
    commands: list[list[str]] = []
    if checkout_type == "branch":
        commands = [
            ["git", "checkout", ref],
            ["git", "checkout", "-B", ref, f"origin/{ref}"],
        ]
    elif checkout_type == "tag":
        commands = [
            ["git", "checkout", ref],
            ["git", "checkout", f"tags/{ref}"],
            ["git", "checkout", f"rel/v{ref}"],
            ["git", "checkout", f"tags/rel/v{ref}"],
            ["git", "checkout", f"v{ref}"],
            ["git", "checkout", f"tags/v{ref}"],
        ]
    elif checkout_type == "commit":
        commands = [["git", "checkout", ref]]
    else:
        commands = [
            ["git", "checkout", ref],
            ["git", "checkout", f"tags/{ref}"],
            ["git", "checkout", "-B", ref, f"origin/{ref}"],
        ]

    for cmd in commands:
        result = run_cmd(cmd, cwd=dst, timeout=300)
        if result.returncode == 0:
            return
    raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"checkout failed: {ref}")


def download_maven_artifact(
    package: dict[str, Any],
    artifacts_root: Path,
    logger: logging.Logger,
    timeout: int = 60,
) -> list[dict[str, Any]]:
    statuses: list[dict[str, Any]] = []
    group_id = package.get("group_id")
    artifact_id = package.get("artifact_id")
    versions = [package.get("affected_version"), package.get("fixed_version")]
    if not group_id or not artifact_id:
        return statuses
    group_path = str(group_id).replace(".", "/")
    for version in versions:
        if not version:
            continue
        version_dir = artifacts_root / "maven" / group_id / artifact_id / str(version)
        version_dir.mkdir(parents=True, exist_ok=True)
        for ext in ("jar", "pom"):
            url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.{ext}"
            dst = version_dir / f"{artifact_id}-{version}.{ext}"
            status_item: dict[str, Any] = {
                "role": "artifact",
                "name": f"{group_id}:{artifact_id}:{version}:{ext}",
                "repo": url,
                "checkout": str(version),
                "local_path": str(dst),
                "timestamp": now_iso(),
            }
            if dst.exists() and dst.stat().st_size > 0:
                status_item["status"] = "existing_valid"
                status_item["reason"] = ""
                statuses.append(status_item)
                continue
            try:
                response = requests.get(url, timeout=timeout)
                if response.status_code == 200:
                    dst.write_bytes(response.content)
                    status_item["status"] = "downloaded"
                    status_item["reason"] = ""
                    logger.info("Downloaded artifact %s", url)
                else:
                    status_item["status"] = "failed"
                    status_item["reason"] = f"http {response.status_code}"
            except Exception as exc:  # noqa: BLE001
                status_item["status"] = "failed"
                status_item["reason"] = str(exc)
            statuses.append(status_item)
    return statuses


@dataclass
class DownloadTarget:
    case_id: str
    role: str
    name: str
    repo: str
    checkout: str
    checkout_type: str
    local_path: Path
    expected_files: list[str]


class DatasetDownloader:
    def __init__(self, manifest_path: Path, dataset_root: Path, metadata_root: Path, logs_dir: Path) -> None:
        self.manifest_path = manifest_path
        self.dataset_root = dataset_root
        self.metadata_root = metadata_root
        self.logs_dir = logs_dir
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_root.mkdir(parents=True, exist_ok=True)
        self.logger = self._build_logger()
        self.status_records: list[dict[str, Any]] = []
        self.failed_records: list[dict[str, Any]] = []

    def _build_logger(self) -> logging.Logger:
        logger = logging.getLogger("dataset_downloader")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        fh = logging.FileHandler(self.logs_dir / "download.log", encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        return logger

    def load_manifest(self) -> dict[str, Any]:
        obj = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or "cases" not in obj:
            raise ValueError("manifest must include top-level 'cases'")
        return obj

    def _target_from_repo(self, case_id: str, role: str, obj: dict[str, Any], base_dir: Path) -> DownloadTarget:
        repo = str(obj.get("repo", "")).strip()
        if not repo:
            raise ValueError(f"{case_id}:{role} missing repo")
        name = str(obj.get("name") or Path(repo).name.replace(".git", "") or role)
        checkout = str(obj.get("checkout", "HEAD"))
        checkout_type = str(obj.get("checkout_type", "auto"))
        rel_path = str(obj.get("path", f"{role}/{name}"))
        local_path = base_dir / rel_path
        expected_files = [str(x) for x in (obj.get("expected_files") or [])]
        return DownloadTarget(case_id, role, name, repo, checkout, checkout_type, local_path, expected_files)

    def _validate_checkout(self, dst: Path, expected_ref: str) -> bool:
        commit = git_current_commit(dst)
        if not commit:
            return False
        if expected_ref in {"", "HEAD"}:
            return True
        exact = run_cmd(["git", "rev-parse", expected_ref], cwd=dst, timeout=30)
        return exact.returncode == 0 and exact.stdout.strip() == commit

    def _validate_repo(self, target: DownloadTarget) -> tuple[bool, str]:
        if not is_valid_git_repo(target.local_path):
            return False, "invalid_git_repo"
        if not is_nonempty_source_tree(target.local_path):
            return False, "empty_or_missing_source_markers"
        if not self._validate_checkout(target.local_path, target.checkout):
            return False, "checkout_mismatch"
        for rel in target.expected_files:
            if not (target.local_path / rel).exists():
                return False, f"missing_expected_file:{rel}"
        if not any((target.local_path / marker).exists() for marker in ("pom.xml", "build.gradle", "build.gradle.kts", "src")):
            return False, "missing_build_or_src_markers"
        return True, ""

    def _record_status(
        self,
        target: DownloadTarget,
        status: str,
        reason: str = "",
        stderr: str = "",
        current_commit: str = "",
    ) -> None:
        item = {
            "case_id": target.case_id,
            "role": target.role,
            "name": target.name,
            "repo": target.repo,
            "checkout": target.checkout,
            "local_path": str(target.local_path),
            "status": status,
            "reason": reason,
            "current_commit": current_commit,
            "timestamp": now_iso(),
        }
        self.status_records.append(item)
        if status == "failed":
            failed = dict(item)
            failed["traceback_or_stderr"] = stderr
            self.failed_records.append(failed)

    def _record_inline_poc_status(self, case_id: str, poc_path: Path, status: str, reason: str = "") -> None:
        item = {
            "case_id": case_id,
            "role": "poc",
            "name": poc_path.name,
            "repo": "inline",
            "checkout": "",
            "local_path": str(poc_path),
            "status": status,
            "reason": reason,
            "current_commit": "",
            "timestamp": now_iso(),
        }
        self.status_records.append(item)
        if status == "failed":
            failed = dict(item)
            failed["traceback_or_stderr"] = ""
            self.failed_records.append(failed)

    def _process_target(self, target: DownloadTarget) -> None:
        try:
            if target.local_path.exists():
                valid, _ = self._validate_repo(target)
                if valid:
                    self._record_status(target, "existing_valid", current_commit=git_current_commit(target.local_path))
                    return
            existed = target.local_path.exists()
            git_clone_or_update(target.repo, target.local_path, logger=self.logger)
            git_checkout(target.local_path, target.checkout, target.checkout_type)
            valid, reason = self._validate_repo(target)
            if valid:
                status = "redownloaded" if existed else "downloaded"
                self._record_status(target, status, current_commit=git_current_commit(target.local_path))
            else:
                self._record_status(target, "failed", reason=reason, current_commit=git_current_commit(target.local_path))
        except Exception as exc:  # noqa: BLE001
            self._record_status(target, "failed", reason=str(exc), stderr=traceback.format_exc())

    def _prepare_inline_poc(self, case_id: str, case_root: Path, poc_obj: dict[str, Any]) -> str:
        inline_rel = str(poc_obj.get("path", "poc/inline-poc"))
        inline_path = case_root / inline_rel
        inline_path.mkdir(parents=True, exist_ok=True)
        payloads = poc_obj.get("payloads") or []
        (inline_path / "payloads.txt").write_text("\n".join(str(p) for p in payloads), encoding="utf-8")
        (inline_path / "README.txt").write_text(
            "Inline PoC payload and expected behavior for deterministic oracle checks.\n",
            encoding="utf-8",
        )
        self._record_inline_poc_status(case_id, inline_path, "existing_valid")
        return str(inline_path)

    def process_cases(self, selected_case_ids: Optional[set[str]] = None) -> dict[str, Any]:
        manifest = self.load_manifest()
        cases: list[dict[str, Any]] = manifest.get("cases", [])
        match_info: dict[str, Any] = {}
        pairs_rows: list[dict[str, Any]] = []

        for case in cases:
            case_id = str(case.get("case_id") or case.get("cve_id") or "").strip()
            if not case_id:
                continue
            if selected_case_ids and case_id not in selected_case_ids:
                continue

            case_root = self.dataset_root / case_id
            (case_root / "upstream").mkdir(parents=True, exist_ok=True)
            (case_root / "downstream").mkdir(parents=True, exist_ok=True)
            (case_root / "poc").mkdir(parents=True, exist_ok=True)
            (case_root / "artifacts").mkdir(parents=True, exist_ok=True)
            (case_root / "notes.txt").touch(exist_ok=True)

            upstream = dict(case.get("upstream", {}))
            upstream_target = self._target_from_repo(case_id, "upstream", upstream, case_root)
            self._process_target(upstream_target)

            poc_obj = dict(case.get("poc", {}))
            poc_target: Optional[DownloadTarget] = None
            poc_local_path = ""
            if poc_obj.get("repo"):
                poc_name = str(poc_obj.get("name") or Path(str(poc_obj.get("repo"))).name.replace(".git", "") or "repo")
                poc_obj["name"] = poc_name
                poc_obj.setdefault("path", f"poc/{poc_name}")
                poc_target = self._target_from_repo(case_id, "poc", poc_obj, case_root)
                self._process_target(poc_target)
                poc_local_path = str(poc_target.local_path)
            elif poc_obj.get("type") == "inline":
                poc_local_path = self._prepare_inline_poc(case_id, case_root, poc_obj)

            downstreams = case.get("downstreams") or []
            for downstream in downstreams:
                ds_target = self._target_from_repo(case_id, "downstream", downstream, case_root)
                self._process_target(ds_target)
                pairs_rows.append(
                    {
                        "case_id": case_id,
                        "cve_id": str(case.get("cve_id", case_id)),
                        "upstream_name": upstream.get("name", ""),
                        "upstream_repo": upstream.get("repo", ""),
                        "upstream_checkout": upstream.get("checkout", ""),
                        "upstream_local_path": str(upstream_target.local_path),
                        "upstream_group_id": (upstream.get("package") or {}).get("group_id", ""),
                        "upstream_artifact_id": (upstream.get("package") or {}).get("artifact_id", ""),
                        "affected_version": (upstream.get("package") or {}).get("affected_version", ""),
                        "fixed_version": (upstream.get("package") or {}).get("fixed_version", ""),
                        "downstream_name": downstream.get("name", ""),
                        "downstream_repo": downstream.get("repo", ""),
                        "downstream_checkout": downstream.get("checkout", ""),
                        "downstream_local_path": str(case_root / downstream.get("path", f"downstream/{downstream.get('name', '')}")),
                        "downstream_build_system": downstream.get("build_system", ""),
                        "dependency_group_id": (downstream.get("dependency_hint") or {}).get("group_id", ""),
                        "dependency_artifact_id": (downstream.get("dependency_hint") or {}).get("artifact_id", ""),
                        "status": "tracked",
                        "notes": "; ".join(case.get("notes", [])) if isinstance(case.get("notes"), list) else "",
                    }
                )

            package = upstream.get("package") if isinstance(upstream, dict) else None
            if isinstance(package, dict):
                artifact_statuses = download_maven_artifact(package, case_root / "artifacts", self.logger)
                for artifact_status in artifact_statuses:
                    artifact_status["case_id"] = case_id
                    artifact_status["current_commit"] = ""
                    self.status_records.append(artifact_status)
                    if artifact_status.get("status") == "failed":
                        self.failed_records.append(
                            {
                                "case_id": case_id,
                                "role": "artifact",
                                "name": artifact_status.get("name", ""),
                                "repo": artifact_status.get("repo", ""),
                                "checkout": artifact_status.get("checkout", ""),
                                "reason": artifact_status.get("reason", ""),
                                "traceback_or_stderr": "",
                                "timestamp": artifact_status.get("timestamp", now_iso()),
                            }
                        )

            match_info[case_id] = {
                "case_id": case_id,
                "cve_id": str(case.get("cve_id", case_id)),
                "ecosystem": case.get("ecosystem", ""),
                "language": case.get("language", ""),
                "dataset_root": str(case_root),
                "upstream": {
                    "name": upstream.get("name", ""),
                    "repo": upstream.get("repo", ""),
                    "checkout": upstream.get("checkout", ""),
                    "local_path": str(upstream_target.local_path),
                    "package": upstream.get("package", {}),
                },
                "downstreams": [
                    {
                        "name": ds.get("name", ""),
                        "repo": ds.get("repo", ""),
                        "checkout": ds.get("checkout", ""),
                        "local_path": str(case_root / ds.get("path", f"downstream/{ds.get('name', '')}")),
                        "build_system": ds.get("build_system", ""),
                        "dependency_hint": ds.get("dependency_hint", {}),
                        "build_hint": ds.get("build_hint", {}),
                        "bridge_hints": ds.get("bridge_hints", []),
                        "vulnerable_apis": case.get("vulnerable_apis", []),
                        "poc_payloads": poc_obj.get("payloads", []),
                    }
                    for ds in downstreams
                ],
                "vulnerable_apis": case.get("vulnerable_apis", []),
                "poc": {
                    "repo": (poc_obj or {}).get("repo", ""),
                    "type": (poc_obj or {}).get("type", "repo" if poc_target else ""),
                    "local_path": poc_local_path,
                    "payloads": (poc_obj or {}).get("payloads", []),
                    "expected_vulnerable_result": (poc_obj or {}).get("expected_vulnerable_result", ""),
                    "expected_patched_behavior": (poc_obj or {}).get("expected_patched_behavior", ""),
                },
                "notes": case.get("notes", []),
            }

        self._write_metadata(match_info, pairs_rows)
        return match_info

    def _write_metadata(self, match_info: dict[str, Any], pairs_rows: list[dict[str, Any]]) -> None:
        fields = [
            "case_id",
            "cve_id",
            "upstream_name",
            "upstream_repo",
            "upstream_checkout",
            "upstream_local_path",
            "upstream_group_id",
            "upstream_artifact_id",
            "affected_version",
            "fixed_version",
            "downstream_name",
            "downstream_repo",
            "downstream_checkout",
            "downstream_local_path",
            "downstream_build_system",
            "dependency_group_id",
            "dependency_artifact_id",
            "status",
            "notes",
        ]
        pairs_path = self.metadata_root / "upstream_downstream_pairs.csv"
        with pairs_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(pairs_rows)

        (self.metadata_root / "dataset_match_info.json").write_text(
            json.dumps(match_info, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (self.metadata_root / "download_status.json").write_text(
            json.dumps(self.status_records, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (self.metadata_root / "failed_downloads.json").write_text(
            json.dumps(self.failed_records, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Download dataset based on YAML manifest.")
    parser.add_argument("--manifest", default="config/dataset_manifest.yaml", help="Path to manifest YAML")
    parser.add_argument("--dataset-root", default="dataset/raw", help="Dataset raw root directory")
    parser.add_argument("--metadata-root", default="dataset/metadata", help="Metadata output directory")
    parser.add_argument("--logs-dir", default="logs", help="Logs directory")
    parser.add_argument("--case-id", action="append", default=[], help="Case ID to process, can repeat")
    parser.add_argument("--all", action="store_true", help="Process all cases in manifest")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    if not args.all and not args.case_id:
        raise SystemExit("Please provide --all or at least one --case-id")
    selected = None if args.all else set(args.case_id)
    downloader = DatasetDownloader(
        manifest_path=Path(args.manifest),
        dataset_root=Path(args.dataset_root),
        metadata_root=Path(args.metadata_root),
        logs_dir=Path(args.logs_dir),
    )
    downloader.process_cases(selected_case_ids=selected)
    print(f"Metadata written to {Path(args.metadata_root).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
