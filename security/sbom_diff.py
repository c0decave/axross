#!/usr/bin/env python3
"""SBOM diff utility for Syft JSON outputs."""

import argparse
import json
import os
from collections import defaultdict
from typing import Dict, List, Tuple


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def load_syft(path: str) -> Dict[Tuple[str, str], List[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    artifacts = data.get("artifacts", []) or []
    mapping: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for art in artifacts:
        name = art.get("name") or ""
        pkg_type = art.get("type") or ""
        version = art.get("version") or ""
        if not name or not pkg_type:
            continue
        mapping[(name, pkg_type)].append(version)
    return mapping


def normalize_versions(versions: List[str]) -> List[str]:
    seen = []
    for v in versions:
        if v not in seen:
            seen.append(v)
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description="Diff two Syft SBOM JSON files.")
    parser.add_argument("--current", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--txt-output", required=True)
    args = parser.parse_args()

    current = load_syft(args.current)
    baseline = load_syft(args.baseline)

    current_keys = set(current.keys())
    baseline_keys = set(baseline.keys())

    added = []
    removed = []
    changed = []

    for key in sorted(current_keys - baseline_keys):
        name, pkg_type = key
        versions = normalize_versions(current[key])
        added.append({"name": name, "type": pkg_type, "versions": versions})

    for key in sorted(baseline_keys - current_keys):
        name, pkg_type = key
        versions = normalize_versions(baseline[key])
        removed.append({"name": name, "type": pkg_type, "versions": versions})

    for key in sorted(current_keys & baseline_keys):
        cur_versions = set(current[key])
        base_versions = set(baseline[key])
        if cur_versions != base_versions:
            name, pkg_type = key
            changed.append(
                {
                    "name": name,
                    "type": pkg_type,
                    "baseline_versions": normalize_versions(list(base_versions)),
                    "current_versions": normalize_versions(list(cur_versions)),
                }
            )

    payload = {
        "statistics": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }

    ensure_parent_dir(args.json_output)
    ensure_parent_dir(args.txt_output)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    with open(args.txt_output, "w", encoding="utf-8") as f:
        f.write("SBOM Diff\n")
        f.write("=========\n\n")
        f.write(f"Added: {len(added)}\n")
        f.write(f"Removed: {len(removed)}\n")
        f.write(f"Changed: {len(changed)}\n\n")
        if added:
            f.write("Added packages:\n")
            for item in added:
                f.write(f"  {item['name']} ({item['type']}): {', '.join(item['versions'])}\n")
            f.write("\n")
        if removed:
            f.write("Removed packages:\n")
            for item in removed:
                f.write(f"  {item['name']} ({item['type']}): {', '.join(item['versions'])}\n")
            f.write("\n")
        if changed:
            f.write("Changed packages:\n")
            for item in changed:
                baseline_versions = ", ".join(item["baseline_versions"])
                current_versions = ", ".join(item["current_versions"])
                f.write(
                    f"  {item['name']} ({item['type']}): "
                    f"{baseline_versions} -> {current_versions}\n"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
