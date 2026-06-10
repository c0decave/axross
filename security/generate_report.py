#!/usr/bin/env python3
"""Generate a consolidated Markdown and PDF report from scan outputs."""

import argparse
import datetime
import glob
import os
import re
import sys


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def max_backticks(text: str) -> int:
    matches = re.findall(r"`+", text)
    return max((len(m) for m in matches), default=0)


def fenced_block(text: str, lang: str = "") -> str:
    fence_len = max_backticks(text) + 3
    fence = "`" * fence_len
    lang = lang.strip()
    header = f"{fence}{lang}" if lang else fence
    return f"{header}\n{text}\n{fence}\n"


def detect_lang(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return "json"
    if ext in (".yml", ".yaml"):
        return "yaml"
    if ext == ".md":
        return "markdown"
    return "text"


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def build_report(
    summary_path: str, report_dir: str, timestamp: str, exclude_prefix: str = ""
) -> str:
    title = "OTI Dashboard Security Scan Report"
    generated = datetime.datetime.now(datetime.timezone.utc).isoformat()

    lines = [f"# {title}", "", f"Generated: {generated}", "", f"Timestamp: {timestamp}", ""]

    if summary_path and os.path.exists(summary_path):
        lines.append("## Summary")
        lines.append("")
        summary = read_file(summary_path)
        lines.append(fenced_block(summary, "text"))

    lines.append("## Raw Tool Outputs")
    lines.append("")

    pattern = os.path.join(report_dir, f"*{timestamp}*")
    report_files = sorted(glob.glob(pattern))

    for path in report_files:
        name = os.path.basename(path)
        if exclude_prefix and name.startswith(exclude_prefix):
            continue
        if name == os.path.basename(summary_path):
            continue
        lines.append(f"### {name}")
        lines.append("")
        try:
            content = read_file(path)
        except Exception as exc:
            lines.append(f"Could not read file: {exc}")
            lines.append("")
            continue
        lang = detect_lang(path)
        lines.append(fenced_block(content, lang))

    return "\n".join(lines)


def write_pdf(markdown_text: str, output_pdf: str) -> None:
    try:
        from markdown import markdown as md_to_html
        from weasyprint import CSS, HTML
    except Exception as exc:
        raise RuntimeError(f"PDF generation requires markdown + weasyprint: {exc}")

    body = md_to_html(markdown_text, extensions=["extra", "tables"])
    css = """
        body { font-family: Arial, sans-serif; font-size: 12px; }
        code, pre { font-family: 'DejaVu Sans Mono', monospace; font-size: 10px; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        h1, h2, h3 { color: #111; }
        table { border-collapse: collapse; }
        table, th, td { border: 1px solid #ddd; padding: 4px; }
    """
    html = (
        f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>{body}</body></html>"
    )
    HTML(string=html).write_pdf(output_pdf, stylesheets=[CSS(string=css)])


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate consolidated markdown and PDF report.")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--timestamp", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-pdf", required=True)
    parser.add_argument("--exclude-prefix", default="security_report_")
    args = parser.parse_args()

    report_md = build_report(args.summary, args.report_dir, args.timestamp, args.exclude_prefix)
    ensure_parent_dir(args.output_md)
    ensure_parent_dir(args.output_pdf)
    with open(args.output_md, "w", encoding="utf-8") as f:
        f.write(report_md)

    try:
        write_pdf(report_md, args.output_pdf)
    except Exception as exc:
        sys.stderr.write(f"PDF generation failed: {exc}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
