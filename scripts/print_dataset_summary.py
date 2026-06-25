from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Print dataset summary from dataset_match_info.json")
    parser.add_argument("--metadata", default="dataset/metadata/dataset_match_info.json", help="metadata json path")
    parser.add_argument("--failed", default="dataset/metadata/failed_downloads.json", help="failed downloads json path")
    args = parser.parse_args()

    metadata_path = Path(args.metadata)
    failed_path = Path(args.failed)

    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    failed = []
    if failed_path.exists():
        failed = json.loads(failed_path.read_text(encoding="utf-8"))

    case_count = len(data)
    upstream_count = sum(1 for _ in data.values())
    downstream_count = sum(len(info.get("downstreams", [])) for info in data.values())

    print(f"Cases: {case_count}")
    print(f"Upstreams: {upstream_count}")
    print(f"Downstreams: {downstream_count}")
    print("")
    for case_id, info in data.items():
        upstream = info.get("upstream", {})
        ds_names = [d.get("name", "") for d in info.get("downstreams", [])]
        print(f"{case_id}")
        print(f"  CVE: {info.get('cve_id', '')}")
        print(f"  Upstream: {upstream.get('name', '')} ({upstream.get('local_path', '')})")
        print(f"  Downstreams: {', '.join(ds_names) if ds_names else '(none)'}")
        print(f"  Dataset root: {info.get('dataset_root', '')}")
        print("")

    print(f"Failed downloads: {len(failed)}")
    for item in failed:
        print(
            "- {case_id} {role} {name} :: {reason}".format(
                case_id=item.get("case_id", ""),
                role=item.get("role", ""),
                name=item.get("name", ""),
                reason=item.get("reason", ""),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
