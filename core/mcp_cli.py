"""The headless MCP server's command line: ``axross --mcp-server`` and friends,
and the ``axross-headless-mcp`` command of the Qt-free package.

``axross`` (main.py) adds :func:`add_arguments` to its parser and hands the
MCP start to :func:`run`; ``axross-headless-mcp`` (:func:`main`) is the same server
with the same flags and without the GUI around it: stdio by default,
``--mcp-http HOST:PORT`` for HTTP, ``--mcp-list-tools`` for the manifest.

Nothing here imports PyQt6, at import time or later on the MCP path:
``scripts/export_standalone.py mcp`` builds the package ``axross-headless-mcp`` from
this module and what it imports, without Qt, and
tests/test_mcp_without_qt.py runs the server with PyQt6 blocked.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

#: The bearer token of a plain-HTTP server, when the operator sets one.
MCP_HTTP_TOKEN_ENV = "AXROSS_MCP_HTTP_TOKEN"
#: What AXROSS_MCP / AXROSS_MCP_WRITE accept as "on".
TRUTHY = frozenset({"1", "true", "yes", "on"})
#: axross's log file (main.LOG_FILE): the headless server logs there too.
LOG_FILE = Path.home() / ".local" / "state" / "axross" / "logs" / "axross.log"


def add_arguments(parser: argparse.ArgumentParser, *, standalone: bool = False) -> None:
    """The MCP flags. *standalone* (``axross-headless-mcp``): stdio is the default
    there, so --mcp-server only says so."""
    if standalone:
        server_help = ("Serve MCP on stdio - the default (--mcp-http: over HTTP); "
                       "accepted for the command lines written for axross --mcp-server.")
    else:
        server_help = ("Run as an MCP (Model Context Protocol) server on stdio instead "
                       "of launching the GUI (--mcp-http: over HTTP). Can also be enabled via "
                       "AXROSS_MCP=1.")
    parser.add_argument("--mcp-server", action="store_true", help=server_help)
    parser.add_argument(
        "--mcp-write",
        action="store_true",
        help="When running as an MCP server, expose the nine write tools "
        "(write_file, mkdir, remove, rename, copy, bulk_copy, symlink, "
        "hardlink, chmod) and the mutating tools of the --mcp-tools groups. "
        "Needs --mcp-root. Off by default — read-only is safe.",
    )
    parser.add_argument(
        "--mcp-allow-scripts",
        action="store_true",
        help="Expose the script_list/api_schema/read/write/run/delete tools to the "
        "MCP client. script_run executes arbitrary Python as you (in a "
        "child process), so this is gated behind its own opt-in (separate from "
        "--mcp-write). stdio only: refused together with --mcp-http.",
    )
    parser.add_argument(
        "--mcp-allow-exec",
        action="store_true",
        help="Serve the exec group (remote_exec, remote_script, exec_backends): "
        "commands and scripts on remote hosts over SSH, SCP, Telnet, rsh, ADB, "
        "WinRM and Cisco (show only). Needs --mcp-tools exec (or all); its own "
        "opt-in, separate from --mcp-write. Refused in the paranoid security mode.",
    )
    parser.add_argument(
        "--mcp-tools",
        action="append",
        default=None,
        metavar="GROUP[,GROUP...]",
        help="Add optional MCP capability groups on top of the file tools; "
        "repeatable or comma-separated, also via AXROSS_MCP_TOOLS. Groups: "
        "metadata, duplicates, packer, archive, crypto, index, filetype, "
        "transfer, remote, exec, agent, extensions; 'all' is every group. Mutating tools "
        "of a group additionally need --mcp-write (exec: --mcp-allow-exec). "
        "Default: no group (the file tools only).",
    )
    parser.add_argument(
        "--mcp-list-tools",
        action="store_true",
        help="Print a JSON manifest of the MCP tools that --mcp-server with the "
        "same --mcp-tools / --mcp-write / --mcp-allow-scripts / --mcp-allow-exec "
        "flags (and their AXROSS_MCP_* variables) would serve - name, group, "
        "read-only or mutating, required flags, input schema, timeout class, "
        "description - and exit without starting a server. docs/mcp-tools.json "
        "is this output for '--mcp-tools all --mcp-write --mcp-allow-scripts "
        "--mcp-allow-exec'.",
    )
    parser.add_argument(
        "--mcp-allow-secret-reads",
        action="store_true",
        help="Let MCP tools read the contents of secret files: axross's own "
        "tokens and keys (cloud OAuth tokens, the MCP HTTP token, chat and "
        "Bluetooth keys, its ADB key) and the private keys in ~/.ssh and "
        "~/.gnupg. Off by default: read_file, grep, checksum, preview, copies "
        "and the groups refuse them, whatever --mcp-root says (their names "
        "are still listed). stdio only: refused together with --mcp-http.",
    )
    parser.add_argument(
        "--mcp-root",
        default=None,
        help="Filesystem root exposed to MCP file tools. Defaults to the "
        "backend home directory.",
    )
    parser.add_argument(
        "--mcp-http",
        default=None,
        help="Run the MCP server as HTTP on HOST:PORT (e.g. 127.0.0.1:7331, "
        "[::1]:7331) instead of stdio; implies --mcp-server. Non-loopback hosts "
        "require TLS flags; without TLS every request needs the bearer token "
        "printed at start.",
    )
    parser.add_argument(
        "--mcp-cert",
        default=None,
        help="Server certificate file for mTLS (PEM).",
    )
    parser.add_argument(
        "--mcp-key",
        default=None,
        help="Server private-key file for mTLS (PEM).",
    )
    parser.add_argument(
        "--mcp-ca",
        default=None,
        help="CA bundle that signs valid client certificates. mTLS is "
        "enabled when all three of --mcp-cert / --mcp-key / --mcp-ca "
        "are supplied.",
    )


def parse_mcp_http(value: str) -> tuple[str, int]:
    """``HOST:PORT`` of --mcp-http as (host, port); an IPv6 host goes in
    brackets (``[::1]:7331``), an empty host is 127.0.0.1. ValueError
    with the one-line message otherwise."""
    if value.startswith("["):
        host, sep, rest = value[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError(f"--mcp-http expects [IPV6]:PORT, got {value!r}")
        port_str = rest[1:]
    else:
        if ":" not in value:
            raise ValueError(f"--mcp-http expects HOST:PORT, got {value!r}")
        host, _, port_str = value.rpartition(":")
        if ":" in host:
            raise ValueError(
                f"--mcp-http: an IPv6 address goes in brackets ([::1]:7331), got {value!r}"
            )
    if not port_str:
        raise ValueError(f"--mcp-http expects HOST:PORT, got {value!r}")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"--mcp-http port {port_str!r} is not an integer") from None
    # Port 0 means "OS picks an ephemeral port" which is pointless for a
    # server you want to connect to; negative and >65535 are invalid by
    # the TCP spec. Reject up-front rather than letting bind() surface a
    # cryptic error.
    if not (1 <= port <= 65535):
        raise ValueError(f"--mcp-http port must be 1..65535, got {port}")
    return host or "127.0.0.1", port


def mcp_http_token(args) -> str | None:
    """The bearer token of an ``--mcp-http`` server.

    Plain HTTP (no mTLS) always gets one: ``$AXROSS_MCP_HTTP_TOKEN`` when
    set, else a fresh random token. An mTLS server uses the variable only
    when it is set. :func:`announce_token` hands it out once the server is
    bound."""
    import secrets

    token = os.environ.get(MCP_HTTP_TOKEN_ENV, "").strip()
    if args.mcp_cert and args.mcp_key and args.mcp_ca:
        return token or None
    return token or secrets.token_urlsafe(32)


def announce_token(token: str, host: str, port: int):
    """For :func:`core.mcp_http.serve_http`'s *announce*: once the socket
    is bound, write the token to its 0600 file (named after host and
    port) and show it once on stderr; the file goes when the server
    stops. A second server on a busy port fails its bind first and
    touches nothing of the running one's."""

    def announce(_server):
        from core import mcp_http as MH

        path = MH.publish_token(token, port, host=host)
        print(
            "MCP HTTP: every request needs the header 'Authorization: Bearer <token>'.\n"
            f"Token: {token}\n(also in {path}, readable only by you)",
            file=sys.stderr,
            flush=True,
        )
        return lambda: MH.withdraw_token(path)

    return announce


def resolve_mcp_root(backend, raw_root: str | None) -> str:
    if not raw_root:
        return backend.home()
    root = Path(raw_root).expanduser()
    return str(root.resolve(strict=False))


def _audit_to_stderr() -> None:
    """The audit trail (core.mcp_server.audit: what each tool was asked to
    do, refused or did - paths and sizes, never contents) also on stderr,
    where an MCP client keeps the server's log; the log file has it
    anyway. Not twice when --debug / -v put everything on stderr already."""
    from core import log_config

    if log_config.terminal_handler() is not None:
        return
    audit = logging.getLogger("core.mcp_server.audit")
    if any(getattr(h, "_axross_audit_stderr", False) for h in audit.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(log_config.EscapingFormatter("%(asctime)s [AUDIT] %(message)s"))
    handler.setLevel(logging.INFO)
    handler._axross_audit_stderr = True  # type: ignore[attr-defined]
    audit.addHandler(handler)


def run(args, *, install_excepthook=None) -> int:
    """Serve (or list) MCP as *args* say: the MCP branch of ``axross``
    and all of ``axross-headless-mcp``. *args* carries the flags of
    :func:`add_arguments`; logging and the security mode are set up by
    the caller. Returns the exit status (2: refused before serving)."""
    log = logging.getLogger("axross")
    write_env = os.environ.get("AXROSS_MCP_WRITE", "").strip().lower()
    log.info(
        "%s Axross MCP server (read-only=%s, http=%s)",
        "Listing the tools of the" if args.mcp_list_tools else "Starting",
        not args.mcp_write,
        bool(args.mcp_http),
    )
    if install_excepthook is not None:
        install_excepthook()
    from core.backend_registry import init_registry

    init_registry()
    from core import mcp_server as M

    allow_write = args.mcp_write or write_env in TRUTHY
    from core.security_mode import current_policy

    if args.mcp_allow_scripts and not current_policy().allow_scripts:
        print(
            "Security mode 'paranoid' blocks MCP script execution.",
            file=sys.stderr,
        )
        return 2
    if args.mcp_allow_exec and not current_policy().allow_remote_exec:
        print(
            "Security mode 'paranoid' blocks MCP remote command execution.",
            file=sys.stderr,
        )
        return 2
    if args.mcp_allow_secret_reads and args.mcp_http:
        # The HTTP transport keeps the secret files out: a network
        # client reading the SSH keys and cloud tokens is not offered.
        print(
            "--mcp-allow-secret-reads is stdio-only: secret files are not "
            "read over a network transport (--mcp-http).",
            file=sys.stderr,
        )
        return 2
    if args.mcp_allow_scripts and args.mcp_http:
        # The HTTP transport never wires the script tools. Accepting
        # the flag there would let an operator believe scripts are
        # reachable (or, worse, later wire them by accident) — and
        # Python execution over a network transport is not offered.
        print(
            "--mcp-allow-scripts is stdio-only: script execution over a "
            "network transport (--mcp-http) is not offered.",
            file=sys.stderr,
        )
        return 2
    from core import mcp_groups as MG

    try:
        tool_groups = MG.groups_from(args.mcp_tools, env_value=os.environ.get(MG.ENV_VAR))
    except MG.GroupError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.mcp_allow_exec and "exec" not in tool_groups:
        # The flag alone serves nothing: the exec tools are a group.
        print(
            "--mcp-allow-exec needs the exec group: add --mcp-tools exec "
            "(or all, or AXROSS_MCP_TOOLS=exec).",
            file=sys.stderr,
        )
        return 2
    backend = M.default_backend()
    if not args.mcp_list_tools:
        _audit_to_stderr()
        # What a server killed mid-write left (temporary files and staging
        # folders it recorded) goes now.
        from core import partials

        root = resolve_mcp_root(backend, args.mcp_root)
        # Records are never kept where the agent writes, and a record is
        # only obeyed inside this server's root.
        partials.serve_roots([root])
        partials.sweep(root=root)
    if args.mcp_list_tools:
        # The manifest of exactly what this start would serve; nothing
        # is served, so the write root is not demanded here.
        tools = M._build_tools(
            backend,
            allow_write=allow_write,
            root=resolve_mcp_root(backend, args.mcp_root),
            allow_scripts=args.mcp_allow_scripts,
            tool_groups=tool_groups,
            allow_exec=args.mcp_allow_exec,
            allow_secret_reads=args.mcp_allow_secret_reads,
        )
        manifest = MG.tool_manifest(
            tools,
            groups=tool_groups,
            allow_write=allow_write,
            allow_scripts=args.mcp_allow_scripts,
            allow_exec=args.mcp_allow_exec,
        )
        sys.stdout.write(MG.manifest_json(manifest))
        return 0
    # Default the MCP root to the backend's home() so an LLM
    # cannot read or write outside what we deliberately exposed
    # (e.g. read_file("/etc/passwd")). Users who want a wider
    # surface have to lower the root explicitly.
    if allow_write and not args.mcp_root:
        # The default root is $HOME. A writable $HOME lets a
        # prompt-injected client plant ~/.bashrc, ~/.ssh/authorized_keys
        # or an autostart entry, which the user then executes.
        print(
            "MCP write tools need an explicit --mcp-root DIR: the default "
            "root (your home directory) is too wide to be writable.",
            file=sys.stderr,
        )
        return 2
    root = resolve_mcp_root(backend, args.mcp_root)
    if args.mcp_root and not os.path.isdir(root):
        # A typo served an empty tree: every call answered "not found".
        print(f"--mcp-root {args.mcp_root}: no such directory.", file=sys.stderr)
        return 2
    if args.mcp_http:
        # CLI-usage errors go to stderr regardless of the logging
        # config - the user may not have --debug on, and a silent
        # failure with exit 2 is worse than a one-line complaint. A
        # refusal is one line, never a traceback.
        try:
            host, port = parse_mcp_http(args.mcp_http)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        from core import mcp_http as MH

        config = MH.HTTPServerConfig(
            backend=backend,
            host=host,
            port=port,
            allow_write=allow_write,
            root=root,
            cert_file=args.mcp_cert,
            key_file=args.mcp_key,
            ca_file=args.mcp_ca,
            tool_groups=tool_groups,
            allow_exec=args.mcp_allow_exec,
        )
        try:
            # Refused before a token is handed out for nothing.
            MH.check_config(config)
            config.auth_token = mcp_http_token(args)
            plain = not (args.mcp_cert and args.mcp_key and args.mcp_ca)
            MH.serve_http(config, announce=announce_token(config.auth_token, host, port)
                          if plain else None)
        except (ValueError, OSError) as exc:
            print(f"--mcp-http {args.mcp_http}: {exc}", file=sys.stderr)
            return 2
        return 0
    return M.serve(
        M.ServerConfig(
            backend=backend,
            allow_write=allow_write,
            allow_scripts=args.mcp_allow_scripts,
            root=root,
            tool_groups=tool_groups,
            allow_exec=args.mcp_allow_exec,
            allow_secret_reads=args.mcp_allow_secret_reads,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    """``axross-headless-mcp``'s command line: axross's MCP flags, stdio by default."""
    from axross._version import __version__

    parser = argparse.ArgumentParser(
        prog="axross-headless-mcp",
        description="axross's headless MCP server: its file tools for an LLM client, on "
        "stdio (the default) or over HTTP (--mcp-http HOST:PORT). No GUI, no Qt.",
    )
    parser.add_argument("--version", action="version", version=f"axross-headless-mcp {__version__}")
    parser.add_argument("--debug", action="store_true",
                        help="Debug logging (to the log file and stderr; stdout is MCP's)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Log to stderr as well as to the log file")
    add_arguments(parser, standalone=True)
    return parser


def boot(debug: bool = False, verbose: bool = False) -> None:
    """What ``axross`` sets up before its MCP start, without the GUI's parts:
    the CA bundle, logging (never to stdout: that is the protocol's), the
    interface language of the messages, the SSH banner, the tmpfs temp
    directory if chosen, the security mode."""
    from core.tls_env import apply_ca_bundle

    apply_ca_bundle()
    from core import log_config

    log_config.configure(LOG_FILE, debug=debug, verbose=verbose)
    from core.i18n import detect_language, install, stored_language

    install(detect_language(configured=stored_language()))
    from core.client_identity import banner_override_on_import

    banner_override_on_import()
    try:
        from core.tmpfs_detect import apply_tempdir_preference

        apply_tempdir_preference()
    except Exception as exc:  # noqa: BLE001 — never block the start for this
        logging.getLogger("axross").debug("tmpfs tempdir routing skipped: %s", exc)
    from core.security_mode import apply_stored_mode

    apply_stored_mode()


def main(argv: list[str] | None = None) -> int:
    """``axross-headless-mcp``: the MCP server on stdio, or what the flags say."""
    args = build_parser().parse_args(argv)
    args.mcp_server = True
    boot(args.debug, args.verbose)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
