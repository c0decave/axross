#!/usr/bin/env python3
"""
Network Egress Surface Scanner

Heuristically identifies code locations that could initiate outbound
network connections. This is a best-effort static scan intended to
support backdoor research and review.
"""

import argparse
import datetime
import json
import logging
import os
import re
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

EXT_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".php": "php",
    ".rb": "ruby",
}

RULES: Dict[str, List[Tuple[str, str, str]]] = {
    "python": [
        (
            "py-requests",
            r"\brequests\.(get|post|put|patch|delete|head|options|request)\b",
            "requests HTTP client",
        ),
        (
            "py-httpx",
            r"\bhttpx\.(get|post|put|patch|delete|head|options|request|Client|AsyncClient)\b",
            "httpx HTTP client",
        ),
        ("py-urllib", r"\burllib\.request\.(urlopen|Request)\b", "urllib.request"),
        (
            "py-urllib3",
            r"\burllib3\.(PoolManager|ProxyManager|HTTPSConnectionPool|HTTPConnectionPool|request)\b",
            "urllib3",
        ),
        ("py-aiohttp", r"\baiohttp\.(ClientSession|request|TCPConnector)\b", "aiohttp"),
        (
            "py-socket",
            r"\bsocket\.(socket|create_connection|getaddrinfo|connect|connect_ex)\b",
            "socket API",
        ),
        ("py-http-client", r"\bhttp\.client\.(HTTPConnection|HTTPSConnection)\b", "http.client"),
        ("py-websockets", r"\bwebsockets\.(connect|serve)\b", "websockets"),
        ("py-ftplib", r"\bftplib\.(FTP|FTP_TLS)\b", "ftplib"),
        ("py-smtplib", r"\bsmtplib\.(SMTP|SMTP_SSL)\b", "smtplib"),
        ("py-imaplib", r"\bimaplib\.(IMAP4|IMAP4_SSL)\b", "imaplib"),
        ("py-poplib", r"\bpoplib\.(POP3|POP3_SSL)\b", "poplib"),
        ("py-paramiko", r"\bparamiko\.(SSHClient|Transport)\b", "paramiko SSH"),
        ("py-redis", r"\bredis\.(Redis|StrictRedis|from_url)\b", "redis client"),
        ("py-grpc", r"\bgrpc\.(insecure_channel|secure_channel)\b", "gRPC"),
        (
            "py-subprocess-net",
            r"\b(subprocess\.(run|Popen|call)|os\.system)\b.*\b(curl|wget|nc|ncat|ssh|telnet|ftp|sftp)\b",
            "subprocess network tooling",
        ),
    ],
    "javascript": [
        ("js-fetch", r"\bfetch\s*\(", "fetch API"),
        ("js-axios", r"\baxios\.(get|post|put|patch|delete|head|request)\b", "axios"),
        ("js-xmlhttp", r"\bXMLHttpRequest\b", "XMLHttpRequest"),
        ("js-websocket", r"\bWebSocket\b", "WebSocket"),
        ("js-http", r"\bhttps?\.(request|get)\b", "node http/https"),
        ("js-net", r"\bnet\.(connect|createConnection)\b", "net sockets"),
        ("js-tls", r"\btls\.connect\b", "TLS sockets"),
        ("js-dgram", r"\bdgram\.createSocket\b", "UDP sockets"),
        ("js-got", r"\bgot\s*\(", "got"),
        ("js-superagent", r"\b(superagent|request)\s*\(", "superagent/request"),
        (
            "js-child-process-net",
            r"\bchild_process\.(exec|execSync|spawn|spawnSync)\b.*\b(curl|wget|nc|ncat|ssh|telnet|ftp|sftp)\b",
            "child_process network tooling",
        ),
    ],
    "go": [
        ("go-net-dial", r"\bnet\.Dial(Timeout|TCP|UDP)?\s*\(", "net.Dial"),
        ("go-http", r"\bhttp\.(Get|Post|Head|DefaultClient|Client)\b", "net/http"),
        ("go-websocket", r"\bwebsocket\.(Dial|DefaultDialer)\b", "websocket"),
    ],
    "shell": [
        ("sh-curl", r"\bcurl\b", "curl"),
        ("sh-wget", r"\bwget\b", "wget"),
        ("sh-nc", r"\b(nc|ncat)\b", "netcat"),
        ("sh-ssh", r"\bssh\b", "ssh"),
        ("sh-telnet", r"\btelnet\b", "telnet"),
        ("sh-ftp", r"\b(ftp|sftp|scp)\b", "ftp/sftp/scp"),
    ],
    "php": [
        ("php-curl", r"\bcurl_(init|exec|setopt)\b", "PHP cURL"),
        ("php-fsockopen", r"\bfsockopen\b", "fsockopen"),
        ("php-stream", r"\bstream_socket_client\b", "stream_socket_client"),
    ],
    "ruby": [
        ("rb-net-http", r"\bNet::HTTP\b", "Net::HTTP"),
        ("rb-open-uri", r"\bopen-uri\b", "open-uri"),
        ("rb-socket", r"\bTCPSocket\b|\bUDPSocket\b", "socket"),
    ],
}


def build_patterns() -> Dict[str, List[Tuple[str, re.Pattern, str]]]:
    compiled: Dict[str, List[Tuple[str, re.Pattern, str]]] = {}
    for lang, rules in RULES.items():
        compiled[lang] = []
        for rule_id, pattern, desc in rules:
            compiled[lang].append((rule_id, re.compile(pattern), desc))
    return compiled


def should_skip_dir(path: str, exclude_dirs: set) -> bool:
    parts = path.replace("\\", "/").split("/")
    return any(part in exclude_dirs for part in parts)


def iter_files(root: str, exclude_dirs: set) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if should_skip_dir(dirpath, exclude_dirs):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".")]
        for name in filenames:
            if name.startswith("."):
                continue
            ext = os.path.splitext(name)[1].lower()
            lang = EXT_LANGUAGE.get(ext)
            if not lang:
                continue
            path = os.path.join(dirpath, name)
            items.append((path, lang))
    return items


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def scan_file(path: str, lang: str, patterns: Dict[str, List[Tuple[str, re.Pattern, str]]]):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                for rule_id, regex, desc in patterns.get(lang, []):
                    if regex.search(line):
                        findings.append(
                            {
                                "file": path,
                                "line": idx,
                                "language": lang,
                                "rule": rule_id,
                                "description": desc,
                                "snippet": line.rstrip()[:300],
                            }
                        )
    except Exception as exc:
        log.warning("Could not scan %s: %s", path, exc)
        return []
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan for potential outbound network call sites.")
    parser.add_argument("--root", default=".", help="Root directory to scan")
    parser.add_argument("--json-output", required=True, help="JSON output path")
    parser.add_argument("--txt-output", required=True, help="Text output path")
    parser.add_argument(
        "--exclude-dir", action="append", default=[], help="Directory names to exclude"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    exclude_dirs = set(DEFAULT_EXCLUDES)
    exclude_dirs.update(args.exclude_dir)

    patterns = build_patterns()
    files = iter_files(args.root, exclude_dirs)

    all_findings: List[dict] = []
    for path, lang in files:
        all_findings.extend(scan_file(path, lang, patterns))

    stats = {
        "total_findings": len(all_findings),
        "by_language": {},
        "by_rule": {},
    }
    for item in all_findings:
        stats["by_language"][item["language"]] = stats["by_language"].get(item["language"], 0) + 1
        stats["by_rule"][item["rule"]] = stats["by_rule"].get(item["rule"], 0) + 1

    payload = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "root": os.path.abspath(args.root),
        "statistics": stats,
        "findings": all_findings,
    }

    ensure_parent_dir(args.json_output)
    ensure_parent_dir(args.txt_output)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    with open(args.txt_output, "w", encoding="utf-8") as f:
        f.write("Network Egress Surface Scan\n")
        f.write("==============================\n\n")
        f.write(f"Total findings: {stats['total_findings']}\n\n")
        f.write("By rule:\n")
        for rule_id, count in sorted(stats["by_rule"].items(), key=lambda x: (-x[1], x[0])):
            f.write(f"  {rule_id}: {count}\n")
        f.write("\n")
        current = None
        for item in all_findings:
            if item["file"] != current:
                current = item["file"]
                f.write(f"\n{current}\n")
            f.write(f"  L{item['line']}: [{item['rule']}] {item['snippet']}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
