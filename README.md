# Vulnerability Bridge Experiment Recovery

This recovered project focuses on studying how vulnerable upstream APIs are bridged and reached in downstream projects, then later generating trigger tests from those reachability paths.

Current recovery stage restores:

1. Stable project directory layout
2. Manifest-driven dataset acquisition
3. Upstream/downstream mapping metadata
4. Download status and failure tracking
5. Dataset validation and summary scripts

Later stages (kept for future recovery) include CodeQL, bridge-point localization, reachability analysis, and LLM-based test generation.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Download Dataset

```bash
python scripts/download_dataset.py --all
```

Or for a specific case:

```bash
python scripts/download_dataset.py --case-id CVE-2023-46442
```

## Validate Dataset

```bash
python scripts/validate_dataset.py
```

## Print Summary

```bash
python scripts/print_dataset_summary.py
```

## Dataset Structure

`dataset/raw/<CVE-ID>/` contains:

- `upstream/`: vulnerable upstream repository/artifact
- `downstream/`: one or more real downstream projects
- `poc/`: optional PoC checkout
- `artifacts/`: optional maven jars/poms or related files
- `notes.txt`: free-form notes

## Metadata Files

- `dataset/metadata/upstream_downstream_pairs.csv`: one line per downstream mapping
- `dataset/metadata/dataset_match_info.json`: canonical pipeline entry metadata for all cases
- `dataset/metadata/download_status.json`: full per-target status records
- `dataset/metadata/failed_downloads.json`: failed items only, with reason and stderr/traceback
