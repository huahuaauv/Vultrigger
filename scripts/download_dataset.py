from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import stat
import subprocess
import traceback
import zipfile
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


def has_source_markers(dst: Path) -> bool:
    if not dst.is_dir() or not any(dst.iterdir()):
        return False
    markers = ("pom.xml", "build.gradle", "build.gradle.kts", "src", "public_pom.xml")
    if any((dst / m).exists() for m in markers):
        return True
    nested_checks = (
        dst / "httpclient" / "pom.xml",
        dst / "snowflake-jdbc" / "pom.xml",
    )
    return any(p.exists() for p in nested_checks)


def git_current_commit(dst: Path) -> str:
    result = run_cmd(["git", "rev-parse", "HEAD"], cwd=dst, timeout=30)
    return result.stdout.strip() if result.returncode == 0 else ""


def reset_directory(dst: Path) -> None:
    if dst.exists():
        def onerror(func: Any, path: str, _exc: Any) -> None:
            Path(path).chmod(stat.S_IWRITE)
            func(path)

        shutil.rmtree(dst, onerror=onerror)


def git_clone_or_update(repo: str, dst: Path) -> None:
    if dst.exists() and is_valid_git_repo(dst):
        fetched = run_cmd(["git", "fetch", "--all", "--tags", "--prune"], cwd=dst, timeout=600)
        if fetched.returncode != 0:
            raise RuntimeError(fetched.stderr.strip() or fetched.stdout.strip())
        return
    if dst.exists():
        reset_directory(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    cloned = run_cmd(["git", "clone", repo, str(dst)], timeout=1200)
    if cloned.returncode != 0:
        raise RuntimeError(cloned.stderr.strip() or cloned.stdout.strip())


def git_checkout_tag(dst: Path, ref: str) -> None:
    tag_candidates = [ref, f"tags/{ref}", f"refs/tags/{ref}"]
    if "/" not in ref and not ref.startswith("v") and not ref.startswith("rel/"):
        tag_candidates.extend(
            [
                f"rel/v{ref}",
                f"v{ref}",
                f"httpclient-{ref}",
                f"{ref}-RC1",
                f"tags/rel/v{ref}",
                f"refs/tags/rel/v{ref}",
                f"tags/v{ref}",
                f"refs/tags/v{ref}",
            ]
        )
    last: Optional[subprocess.CompletedProcess[str]] = None
    for cand in tag_candidates:
        last = run_cmd(["git", "checkout", cand], cwd=dst, timeout=300)
        if last.returncode == 0:
            return
    msg = (last.stderr.strip() if last else "") or (last.stdout.strip() if last else "") or f"checkout tag failed: {ref}"
    raise RuntimeError(msg)


def commit_exists(dst: Path, sha: str) -> bool:
    exists = run_cmd(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=dst, timeout=60)
    return exists.returncode == 0


def git_checkout_commit(dst: Path, sha: str) -> None:
    run_cmd(["git", "fetch", "--all", "--tags", "--prune"], cwd=dst, timeout=600)
    if not commit_exists(dst, sha):
        deep_fetch = run_cmd(
            [
                "git",
                "fetch",
                "origin",
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/tags/*:refs/tags/*",
                "--prune",
            ],
            cwd=dst,
            timeout=900,
        )
        if deep_fetch.returncode != 0:
            raise RuntimeError(deep_fetch.stderr.strip() or deep_fetch.stdout.strip())
    if not commit_exists(dst, sha):
        raise RuntimeError(f"commit not found after fetch: {sha}")
    checkout = run_cmd(["git", "checkout", "--detach", sha], cwd=dst, timeout=300)
    if checkout.returncode != 0:
        raise RuntimeError(checkout.stderr.strip() or checkout.stdout.strip())


def github_archive_url(repo: str, checkout: str, checkout_type: str) -> Optional[str]:
    if not repo.startswith("https://github.com/"):
        return None
    base = repo.removesuffix(".git")
    if checkout_type == "tag":
        return f"{base}/archive/refs/tags/{checkout}.zip"
    if checkout_type == "commit":
        return f"{base}/archive/{checkout}.zip"
    return None


def extract_single_root_zip(content: bytes, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        names = [n for n in zf.namelist() if n.strip()]
        if not names:
            raise RuntimeError("empty zip archive")
        root = names[0].split("/")[0]
        for member in names:
            if not member.startswith(f"{root}/"):
                continue
            rel = member[len(root) + 1 :]
            if not rel:
                continue
            out_path = dst / rel
            if member.endswith("/"):
                out_path.mkdir(parents=True, exist_ok=True)
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, out_path.open("wb") as out:
                    out.write(src.read())


def download_maven_artifacts(package: dict[str, Any], artifacts_root: Path) -> list[dict[str, Any]]:
    group_id = package.get("group_id")
    artifact_id = package.get("artifact_id")
    versions = [package.get("affected_version"), package.get("fixed_version")]
    records: list[dict[str, Any]] = []
    if not group_id or not artifact_id:
        return records
    group_path = str(group_id).replace(".", "/")
    for version in versions:
        if not version:
            continue
        ver_dir = artifacts_root / "maven" / group_id / artifact_id / str(version)
        ver_dir.mkdir(parents=True, exist_ok=True)
        for ext in ("jar", "pom"):
            dst = ver_dir / f"{artifact_id}-{version}.{ext}"
            url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.{ext}"
            item = {
                "role": "artifact",
                "name": f"{group_id}:{artifact_id}:{version}:{ext}",
                "repo": url,
                "checkout": str(version),
                "local_path": str(dst),
                "timestamp": now_iso(),
            }
            if dst.exists() and dst.stat().st_size > 0:
                item["status"] = "existing_valid"
                item["reason"] = ""
                records.append(item)
                continue
            try:
                res = requests.get(url, timeout=60)
                if res.status_code == 200:
                    dst.write_bytes(res.content)
                    item["status"] = "downloaded"
                    item["reason"] = ""
                else:
                    item["status"] = "failed"
                    item["reason"] = f"http {res.status_code}"
            except Exception as exc:  # noqa: BLE001
                item["status"] = "failed"
                item["reason"] = str(exc)
            records.append(item)
    return records


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
    confirmed: bool


class DatasetDownloader:
    def __init__(
        self,
        manifest_path: Path,
        dataset_root: Path,
        metadata_root: Path,
        include_disabled: bool,
        force: bool,
    ) -> None:
        self.manifest_path = manifest_path
        self.dataset_root = dataset_root
        self.metadata_root = metadata_root
        self.include_disabled = include_disabled
        self.force = force
        self.status_records: list[dict[str, Any]] = []
        self.failed_records: list[dict[str, Any]] = []
        self.metadata_root.mkdir(parents=True, exist_ok=True)

    def load_manifest(self) -> dict[str, Any]:
        obj = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or "cases" not in obj:
            raise ValueError("manifest must include top-level 'cases'")
        return obj

    def _record(
        self,
        target: DownloadTarget,
        status: str,
        reason: str = "",
        stderr: str = "",
        checkout_method: str = "git",
        is_git_repo_flag: Optional[bool] = None,
        current_commit_override: Optional[str] = None,
    ) -> dict[str, Any]:
        is_git = is_valid_git_repo(target.local_path) if is_git_repo_flag is None else is_git_repo_flag
        item = {
            "case_id": target.case_id,
            "role": target.role,
            "name": target.name,
            "repo": target.repo,
            "checkout": target.checkout,
            "local_path": str(target.local_path),
            "status": status,
            "reason": reason,
            "checkout_method": checkout_method,
            "is_git_repo": is_git,
            "current_commit": current_commit_override if current_commit_override is not None else (git_current_commit(target.local_path) if is_git else ""),
            "timestamp": now_iso(),
        }
        self.status_records.append(item)
        if status == "failed":
            failed = dict(item)
            failed["traceback_or_stderr"] = stderr
            self.failed_records.append(failed)
        return item

    def _target(self, case_id: str, role: str, obj: dict[str, Any], case_root: Path, confirmed: bool) -> DownloadTarget:
        repo = str(obj.get("repo", "")).strip()
        if not repo:
            raise ValueError(f"{case_id}:{role} missing repo")
        name = str(obj.get("name") or Path(repo).name.replace(".git", "") or role)
        return DownloadTarget(
            case_id=case_id,
            role=role,
            name=name,
            repo=repo,
            checkout=str(obj.get("checkout", "HEAD")),
            checkout_type=str(obj.get("checkout_type", "auto")),
            local_path=case_root / str(obj.get("path", f"{role}/{name}")),
            expected_files=[str(x) for x in (obj.get("expected_files") or [])],
            confirmed=confirmed,
        )

    def _validate_git_success(self, t: DownloadTarget) -> tuple[bool, str]:
        if not t.local_path.exists():
            return False, "local_path_missing"
        if not is_valid_git_repo(t.local_path):
            return False, "invalid_git_repo"
        if not has_source_markers(t.local_path):
            return False, "missing_source_markers"
        if not git_current_commit(t.local_path):
            return False, "missing_current_commit"
        for rel in t.expected_files:
            if not (t.local_path / rel).exists():
                return False, f"missing_expected_file:{rel}"
        return True, ""

    def _validate_archive_success(self, t: DownloadTarget) -> tuple[bool, str]:
        if not t.local_path.exists():
            return False, "local_path_missing"
        if not has_source_markers(t.local_path):
            return False, "missing_source_markers"
        for rel in t.expected_files:
            if not (t.local_path / rel).exists():
                return False, f"missing_expected_file:{rel}"
        return True, ""

    def _try_archive_fallback(self, t: DownloadTarget) -> tuple[bool, str]:
        url = github_archive_url(t.repo, t.checkout, t.checkout_type)
        if not url:
            return False, "archive_fallback_not_supported"
        if t.local_path.exists():
            reset_directory(t.local_path)
        t.local_path.mkdir(parents=True, exist_ok=True)
        try:
            res = requests.get(url, timeout=120)
            if res.status_code != 200:
                return False, f"archive_http_{res.status_code}"
            extract_single_root_zip(res.content, t.local_path)
            ok, reason = self._validate_archive_success(t)
            if ok:
                self._record(
                    t,
                    "downloaded",
                    checkout_method="github_archive_zip",
                    is_git_repo_flag=False,
                    current_commit_override=t.checkout,
                )
                return True, ""
            return False, reason
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def _process_git_target(self, t: DownloadTarget) -> dict[str, Any]:
        try:
            if self.force and t.local_path.exists():
                reset_directory(t.local_path)

            if t.local_path.exists():
                ok, _ = self._validate_git_success(t)
                if ok:
                    return self._record(t, "existing_valid", checkout_method="git")

            git_clone_or_update(t.repo, t.local_path)
            if t.checkout_type == "tag":
                git_checkout_tag(t.local_path, t.checkout)
            elif t.checkout_type == "commit":
                git_checkout_commit(t.local_path, t.checkout)
            elif t.checkout_type == "branch":
                branch = run_cmd(["git", "checkout", t.checkout], cwd=t.local_path, timeout=300)
                if branch.returncode != 0:
                    create = run_cmd(["git", "checkout", "-B", t.checkout, f"origin/{t.checkout}"], cwd=t.local_path, timeout=300)
                    if create.returncode != 0:
                        raise RuntimeError(create.stderr.strip() or create.stdout.strip())
            else:
                generic = run_cmd(["git", "checkout", t.checkout], cwd=t.local_path, timeout=300)
                if generic.returncode != 0:
                    raise RuntimeError(generic.stderr.strip() or generic.stdout.strip())

            ok, reason = self._validate_git_success(t)
            if ok:
                status = "redownloaded" if self.force else "downloaded"
                return self._record(t, status, checkout_method="git")

            archive_ok, archive_reason = self._try_archive_fallback(t)
            if archive_ok:
                return self.status_records[-1]
            return self._record(t, "failed", reason=f"{reason}; archive_fallback={archive_reason}")
        except Exception as exc:  # noqa: BLE001
            archive_ok, archive_reason = self._try_archive_fallback(t)
            if archive_ok:
                return self.status_records[-1]
            return self._record(t, "failed", reason=str(exc), stderr=traceback.format_exc())

    def _write_inline_poc(self, case_id: str, case_root: Path, poc: dict[str, Any]) -> str:
        rel = str(poc.get("path", "poc/inline"))
        poc_dir = case_root / rel
        poc_dir.mkdir(parents=True, exist_ok=True)
        payload_obj = {
            "payloads": poc.get("payloads", []),
            "expected_vulnerable_result": poc.get("expected_vulnerable_result", ""),
            "expected_patched_behavior": poc.get("expected_patched_behavior", ""),
            "oracle": "host_mismatch_assertion",
        }
        (poc_dir / "payloads.json").write_text(json.dumps(payload_obj, ensure_ascii=False, indent=2), encoding="utf-8")
        fake_t = DownloadTarget(case_id, "poc", poc_dir.name, "inline", "", "", poc_dir, [], confirmed=True)
        self._record(fake_t, "existing_valid", checkout_method="inline", is_git_repo_flag=False, current_commit_override="")
        return str(poc_dir)

    def process(self, selected_case_ids: Optional[set[str]]) -> dict[str, Any]:
        manifest = self.load_manifest()
        cases = manifest.get("cases", [])
        match_info: dict[str, Any] = {}
        pairs_rows: list[dict[str, Any]] = []

        for case in cases:
            case_id = str(case.get("case_id") or case.get("cve_id") or "").strip()
            if not case_id:
                continue
            if selected_case_ids and case_id not in selected_case_ids:
                continue

            case_root = self.dataset_root / case_id
            for rel in ("upstream", "downstream", "poc", "artifacts"):
                (case_root / rel).mkdir(parents=True, exist_ok=True)
            (case_root / "notes.txt").touch(exist_ok=True)

            upstream = dict(case.get("upstream", {}))
            up_t = self._target(case_id, "upstream", upstream, case_root, confirmed=True)
            upstream_rec = self._process_git_target(up_t)

            poc = dict(case.get("poc", {}))
            poc_local = ""
            if poc.get("type") == "inline":
                poc_local = self._write_inline_poc(case_id, case_root, poc)

            confirmed_downstreams: list[dict[str, Any]] = []
            downstream_entries_for_metadata: list[dict[str, Any]] = []
            for ds in case.get("downstreams", []):
                enabled = bool(ds.get("enabled", True))
                ds_status_label = str(ds.get("status", "confirmed"))
                is_confirmed = ds_status_label == "confirmed"
                ds_t = self._target(case_id, "downstream", ds, case_root, confirmed=is_confirmed)
                if not enabled and not self.include_disabled:
                    rec = self._record(ds_t, "skipped", reason="disabled_in_manifest", checkout_method="none")
                    downstream_entries_for_metadata.append((ds, rec))
                    continue
                rec = self._process_git_target(ds_t)
                downstream_entries_for_metadata.append((ds, rec))
                if is_confirmed and rec["status"] in {"downloaded", "existing_valid", "redownloaded"}:
                    confirmed_downstreams.append(ds)
                    pairs_rows.append(
                        {
                            "case_id": case_id,
                            "cve_id": str(case.get("cve_id", case_id)),
                            "upstream_name": upstream.get("name", ""),
                            "upstream_repo": upstream.get("repo", ""),
                            "upstream_checkout": upstream.get("checkout", ""),
                            "upstream_local_path": str(up_t.local_path),
                            "upstream_group_id": (upstream.get("package") or {}).get("group_id", ""),
                            "upstream_artifact_id": (upstream.get("package") or {}).get("artifact_id", ""),
                            "affected_version": (upstream.get("package") or {}).get("affected_version", ""),
                            "fixed_version": (upstream.get("package") or {}).get("fixed_version", ""),
                            "downstream_name": ds.get("name", ""),
                            "downstream_repo": ds.get("repo", ""),
                            "downstream_checkout": ds.get("checkout", ""),
                            "downstream_local_path": str(case_root / ds.get("path", f"downstream/{ds.get('name', '')}")),
                            "downstream_build_system": ds.get("build_system", ""),
                            "dependency_group_id": (ds.get("dependency_hint") or {}).get("group_id", ""),
                            "dependency_artifact_id": (ds.get("dependency_hint") or {}).get("artifact_id", ""),
                            "status": ds_status_label,
                            "notes": "; ".join(case.get("notes", [])) if isinstance(case.get("notes"), list) else "",
                        }
                    )

            package = upstream.get("package", {})
            for artifact_item in download_maven_artifacts(package, case_root / "artifacts"):
                artifact_item["case_id"] = case_id
                artifact_item["current_commit"] = ""
                artifact_item["checkout_method"] = "http_download"
                artifact_item["is_git_repo"] = False
                self.status_records.append(artifact_item)
                if artifact_item.get("status") == "failed":
                    self.failed_records.append(
                        {
                            "case_id": case_id,
                            "role": "artifact",
                            "name": artifact_item.get("name", ""),
                            "repo": artifact_item.get("repo", ""),
                            "checkout": artifact_item.get("checkout", ""),
                            "reason": artifact_item.get("reason", ""),
                            "traceback_or_stderr": "",
                            "timestamp": artifact_item.get("timestamp", now_iso()),
                        }
                    )

            vuln_apis = case.get("vulnerable_apis", [])
            downstream_status_map = {d["name"]: r for d, r in downstream_entries_for_metadata}
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
                    "local_path": str(up_t.local_path),
                    "download_status": upstream_rec.get("status", "failed"),
                    "checkout_method": upstream_rec.get("checkout_method", "git"),
                    "package": upstream.get("package", {}),
                },
                "downstreams": [
                    {
                        "name": ds.get("name", ""),
                        "repo": ds.get("repo", ""),
                        "checkout": ds.get("checkout", ""),
                        "local_path": str(case_root / ds.get("path", f"downstream/{ds.get('name', '')}")),
                        "build_system": ds.get("build_system", ""),
                        "status": ds.get("status", "confirmed"),
                        "download_status": downstream_status_map.get(ds.get("name", ""), {}).get("status", "failed"),
                        "checkout_method": downstream_status_map.get(ds.get("name", ""), {}).get("checkout_method", "git"),
                        "dependency_hint": ds.get("dependency_hint", {}),
                        "build_hint": ds.get("build_hint", {}),
                        "bridge_hints": ds.get("bridge_hints", []),
                        "vulnerable_apis": vuln_apis,
                        "poc_payload": (poc.get("payloads") or [None])[0],
                    }
                    for ds in case.get("downstreams", [])
                ],
                "vulnerable_apis": vuln_apis,
                "poc": {
                    "type": poc.get("type", ""),
                    "local_path": poc_local,
                    "payloads": poc.get("payloads", []),
                    "expected_vulnerable_result": poc.get("expected_vulnerable_result", ""),
                    "expected_patched_behavior": poc.get("expected_patched_behavior", ""),
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
        pairs = self.metadata_root / "upstream_downstream_pairs.csv"
        with pairs.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(pairs_rows)

        (self.metadata_root / "dataset_match_info.json").write_text(json.dumps(match_info, ensure_ascii=False, indent=2), encoding="utf-8")
        (self.metadata_root / "download_status.json").write_text(json.dumps(self.status_records, ensure_ascii=False, indent=2), encoding="utf-8")
        (self.metadata_root / "failed_downloads.json").write_text(json.dumps(self.failed_records, ensure_ascii=False, indent=2), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Download dataset for CVE experiments.")
    parser.add_argument("--manifest", default="config/dataset_manifest.yaml")
    parser.add_argument("--dataset-root", default="dataset/raw")
    parser.add_argument("--metadata-root", default="dataset/metadata")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--include-disabled", action="store_true")
    parser.add_argument("--force", action="store_true")
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
        include_disabled=bool(args.include_disabled),
        force=bool(args.force),
    )
    downloader.process(selected)
    print(f"Metadata written to {Path(args.metadata_root).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
