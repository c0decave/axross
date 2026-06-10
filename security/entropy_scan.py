#!/usr/bin/env python3
"""
Entropy Scanner

Computes Shannon entropy for files to highlight potentially encrypted
or packed content. Outputs JSON + text summaries.
"""

import argparse
import datetime
import json
import logging
import math
import os
from typing import Dict, List, Tuple

log = logging.getLogger(__name__)

DEFAULT_EXCLUDES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "staticfiles",
    "media",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "security/reports",
}


def shannon_entropy(path: str) -> Tuple[float, int]:
    counts = [0] * 256
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            for b in chunk:
                counts[b] += 1
    if total == 0:
        return 0.0, 0
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy, total


def should_skip_dir(path: str, exclude_dirs: set) -> bool:
    parts = path.replace("\\", "/").split("/")
    return any(part in exclude_dirs for part in parts)


def iter_files(root: str, exclude_dirs: set) -> List[str]:
    items: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if should_skip_dir(dirpath, exclude_dirs):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".")]
        for name in filenames:
            if name.startswith("."):
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                continue
            if not os.path.isfile(path):
                continue
            items.append(path)
    return items


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute Shannon entropy for files.")
    parser.add_argument("--root", default=".", help="Root directory to scan")
    parser.add_argument("--json-output", required=True, help="JSON output path")
    parser.add_argument("--txt-output", required=True, help="Text output path")
    parser.add_argument(
        "--exclude-dir", action="append", default=[], help="Directory names to exclude"
    )
    parser.add_argument(
        "--high-threshold", type=float, default=7.5, help="High entropy threshold (0-8)"
    )
    parser.add_argument(
        "--max-size-mb", type=float, default=0.0, help="Max file size to scan (0 = no limit)"
    )
    parser.add_argument(
        "--top", type=int, default=50, help="Top N high-entropy files in text output"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    exclude_dirs = set(DEFAULT_EXCLUDES)
    exclude_dirs.update(args.exclude_dir)

    files = iter_files(args.root, exclude_dirs)
    max_bytes = int(args.max_size_mb * 1024 * 1024) if args.max_size_mb > 0 else 0

    results: List[Dict] = []
    total_bytes = 0
    for path in files:
        try:
            size = os.path.getsize(path)
            if max_bytes and size > max_bytes:
                results.append(
                    {
                        "file": path,
                        "size": size,
                        "entropy": None,
                        "skipped": True,
                        "reason": f"size>{max_bytes}",
                    }
                )
                continue
            entropy, size_read = shannon_entropy(path)
            total_bytes += size_read
            results.append(
                {
                    "file": path,
                    "size": size_read,
                    "entropy": round(entropy, 5),
                    "skipped": False,
                }
            )
        except Exception as exc:
            log.warning("Could not read %s: %s", path, exc)
            results.append(
                {
                    "file": path,
                    "size": None,
                    "entropy": None,
                    "skipped": True,
                    "reason": f"read_error:{exc}",
                }
            )

    high_entropy = [
        r
        for r in results
        if not r.get("skipped")
        and r.get("entropy") is not None
        and r["entropy"] >= args.high_threshold
    ]

    stats = {
        "total_files": len(results),
        "total_bytes": total_bytes,
        "high_entropy_threshold": args.high_threshold,
        "high_entropy_files": len(high_entropy),
        "skipped_files": len([r for r in results if r.get("skipped")]),
    }

    payload = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "root": os.path.abspath(args.root),
        "statistics": stats,
        "files": results,
    }

    ensure_parent_dir(args.json_output)
    ensure_parent_dir(args.txt_output)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Build text report
    high_sorted = sorted(high_entropy, key=lambda r: r.get("entropy", 0), reverse=True)
    with open(args.txt_output, "w", encoding="utf-8") as f:
        f.write("Entropy Scan\n")
        f.write("============\n\n")
        f.write(f"Total files scanned: {stats['total_files']}\n")
        f.write(f"Total bytes scanned: {stats['total_bytes']}\n")
        f.write(f"High entropy threshold: {stats['high_entropy_threshold']}\n")
        f.write(f"High entropy files: {stats['high_entropy_files']}\n")
        f.write(f"Skipped files: {stats['skipped_files']}\n\n")
        f.write(f"Top {args.top} high-entropy files:\n")
        for item in high_sorted[: args.top]:
            f.write(f"  {item['entropy']:.5f}  {item['size']:>10}  {item['file']}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
