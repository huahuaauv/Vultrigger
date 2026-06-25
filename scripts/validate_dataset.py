from __future__ import annotations

import argparse
import csv
import json
import logging
from pathlib import Path
from typing import Any


def build_logger(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dataset_validation")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def is_nonempty(path: Path) -> bool:
    return path.is_dir() and any(path.iterdir())


def has_java_build_files(path: Path) -> bool:
    return (path / "pom.xml").exists() or (path / "build.gradle").exists() or (path / "build.gradle.kts").exists()


def validate(metadata_path: Path, pairs_csv: Path, log_path: Path) -> int:
    logger = build_logger(log_path)
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    total_cases = len(data)
    total_downstreams = 0
    failed = 0

    print(f"Validating {total_cases} cases from {metadata_path}")
    logger.info("Validating metadata: %s", metadata_path)

    for case_id, info in data.items():
        case_root = Path(info.get("dataset_root", ""))
        if not case_root.exists():
            print(f"[FAIL] {case_id} missing case root: {case_root}")
            logger.error("%s missing case root: %s", case_id, case_root)
            failed += 1

        upstream = info.get("upstream", {})
        up_path = Path(upstream.get("local_path", ""))
        if not is_nonempty(up_path):
            print(f"[FAIL] {case_id} upstream invalid/nonempty check failed: {up_path}")
            logger.error("%s upstream invalid/nonempty: %s", case_id, up_path)
            failed += 1
        elif not has_java_build_files(up_path):
            print(f"[WARN] {case_id} upstream has no pom.xml/build.gradle: {up_path}")
            logger.warning("%s upstream no build file: %s", case_id, up_path)

        downstreams: list[dict[str, Any]] = info.get("downstreams", [])
        for ds in downstreams:
            total_downstreams += 1
            ds_path = Path(ds.get("local_path", ""))
            if not is_nonempty(ds_path):
                print(f"[FAIL] {case_id}/{ds.get('name', '')} downstream invalid/nonempty: {ds_path}")
                logger.error("%s downstream invalid/nonempty: %s", case_id, ds_path)
                failed += 1
            if not has_java_build_files(ds_path):
                print(f"[FAIL] {case_id}/{ds.get('name', '')} no pom.xml/build.gradle: {ds_path}")
                logger.error("%s downstream no build file: %s", case_id, ds_path)
                failed += 1

        poc_path = Path((info.get("poc") or {}).get("local_path", ""))
        if not poc_path.exists():
            print(f"[FAIL] {case_id} poc path missing: {poc_path}")
            logger.error("%s poc path missing: %s", case_id, poc_path)
            failed += 1

    csv_rows = 0
    if pairs_csv.exists():
        with pairs_csv.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            csv_rows = sum(1 for _ in reader)
    else:
        print(f"[FAIL] Missing pairs csv: {pairs_csv}")
        logger.error("Missing pairs csv: %s", pairs_csv)
        failed += 1

    if csv_rows != total_downstreams:
        print(f"[FAIL] pairs row mismatch: csv={csv_rows}, downstreams={total_downstreams}")
        logger.error("pairs row mismatch csv=%s downstreams=%s", csv_rows, total_downstreams)
        failed += 1

    cve_2020 = data.get("CVE-2020-13956")
    if not isinstance(cve_2020, dict):
        print("[FAIL] Missing case CVE-2020-13956 in metadata")
        logger.error("Missing case CVE-2020-13956 in metadata")
        failed += 1
    else:
        expected_paths = [
            Path("dataset/raw/CVE-2020-13956/upstream/httpcomponents-client"),
            Path("dataset/raw/CVE-2020-13956/downstream/share"),
            Path("dataset/raw/CVE-2020-13956/downstream/snowflake-jdbc-vuln-4.5.11"),
        ]
        for expected in expected_paths:
            if not expected.exists():
                print(f"[FAIL] Missing required CVE-2020-13956 path: {expected}")
                logger.error("Missing required CVE-2020-13956 path: %s", expected)
                failed += 1

        vuln_apis = cve_2020.get("vulnerable_apis", [])
        has_extract_host = any(
            isinstance(api, dict)
            and api.get("class_name") == "org.apache.http.client.utils.URIUtils"
            and api.get("method_name") == "extractHost"
            for api in vuln_apis
        )
        if not has_extract_host:
            print("[FAIL] CVE-2020-13956 vulnerable API URIUtils.extractHost not found")
            logger.error("CVE-2020-13956 vulnerable API URIUtils.extractHost not found")
            failed += 1

        payloads = (cve_2020.get("poc") or {}).get("payloads", [])
        expected_payload = "http://user@apache.org:80@google.com/"
        if expected_payload not in payloads:
            print(f"[FAIL] CVE-2020-13956 missing expected payload: {expected_payload}")
            logger.error("CVE-2020-13956 missing expected payload: %s", expected_payload)
            failed += 1

    if failed == 0:
        print("[OK] Dataset validation passed")
        logger.info("Dataset validation passed")
        return 0

    print(f"[FAIL] Dataset validation finished with {failed} issue(s)")
    logger.error("Dataset validation finished with %s issue(s)", failed)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate recovered dataset metadata and local checkout layout.")
    parser.add_argument("--metadata", default="dataset/metadata/dataset_match_info.json", help="dataset_match_info.json")
    parser.add_argument(
        "--pairs-csv",
        default="dataset/metadata/upstream_downstream_pairs.csv",
        help="upstream_downstream_pairs.csv path",
    )
    parser.add_argument("--log-file", default="logs/dataset_validation.log", help="validation log file")
    args = parser.parse_args()
    return validate(Path(args.metadata), Path(args.pairs_csv), Path(args.log_file))


if __name__ == "__main__":
    raise SystemExit(main())
