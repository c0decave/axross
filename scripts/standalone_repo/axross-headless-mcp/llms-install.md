# Installing axross-headless-mcp (for AI agents)

axross-headless-mcp is an MCP server with file tools for the local disk and for
SFTP, SMB, WebDAV, S3 and more. It needs Python 3.11 or newer and has no GUI.
Follow these steps; ask the user before you widen anything beyond the safe default.

## 1. Install

Either run it with uv, without installing (preferred):

```sh
uvx axross-headless-mcp --version
```

or install it:

```sh
pipx install axross-headless-mcp        # or: pip install axross-headless-mcp
axross-headless-mcp --version
```

The remote protocols beyond SFTP and the archive, metadata and image extras come
with the `all` extra: `uvx --from 'axross-headless-mcp[all]' axross-headless-mcp`
or `pipx install 'axross-headless-mcp[all]'`.

## 2. Choose the folder and the tools

- `--mcp-root DIR` - the only folder the tools may touch. Ask the user which
  folder; never pick the home folder or `/` on your own.
- Read-only is the default. `--mcp-write` adds the write tools (write_file,
  create_directory, delete_path, move_path, copy_file, restore_file_version, ...) and
  needs `--mcp-root`. Add it only when the user wants the agent to change files.
- `--mcp-tools GROUP,...` adds tool groups: metadata, duplicates, archive,
  crypto, index, filetype, transfer, remote, adb (Android devices opened as ADB
  profiles: identity, apps, permissions, SMS, log, screenshots, AT commands), exec,
  agent, extensions. `all` is every group but adb, which comes only by name
  (`all,adb`, or `remote,adb` for a phone). Without it only the file tools are served.
- `--mcp-allow-exec` (remote commands, needs `--mcp-tools exec`),
  `--mcp-allow-scripts` (runs Python) and `--mcp-allow-secret-reads` (private keys,
  tokens) are separate opt-ins. Do not set them unless the user asks for exactly
  that.
- `axross-headless-mcp --mcp-list-tools --mcp-root DIR [flags]` prints, as JSON,
  what a server with those flags would serve - check it before you configure.

## 3. Configure the client (stdio, the safe default)

Claude Desktop (`claude_desktop_config.json`), Cline (`cline_mcp_settings.json`),
Cursor (`.cursor/mcp.json`) - read-only, one folder:

```json
{
  "mcpServers": {
    "axross": {
      "command": "uvx",
      "args": ["axross-headless-mcp", "--mcp-root", "/path/the/user/chose"]
    }
  }
}
```

VS Code (`.vscode/mcp.json`):

```json
{
  "servers": {
    "axross": {
      "type": "stdio",
      "command": "uvx",
      "args": ["axross-headless-mcp", "--mcp-root", "${workspaceFolder}"]
    }
  }
}
```

Claude Code:

```sh
claude mcp add axross -- uvx axross-headless-mcp --mcp-root /path/the/user/chose
```

With pipx or pip, use `"command": "axross-headless-mcp"` and drop the first
argument. For write access add `"--mcp-write"` to `args`; for more tools add
`"--mcp-tools", "metadata,archive"` (or `"all"`).

## 4. Over HTTP (only when the client cannot start a program)

```sh
AXROSS_MCP_HTTP_TOKEN=<a long random string> \
  axross-headless-mcp --mcp-http 127.0.0.1:7331 --mcp-root /path/the/user/chose
```

The endpoint is `http://127.0.0.1:7331/messages` (streamable HTTP); every request
needs `Authorization: Bearer <token>`. Without `AXROSS_MCP_HTTP_TOKEN` a new token
is printed on stderr at each start and written to
`$XDG_RUNTIME_DIR/axross/mcp-http-127.0.0.1-7331.token`. Any address other than
loopback needs mTLS: `--mcp-cert server.pem --mcp-key server-key.pem --mcp-ca
clients-ca.pem`. `--mcp-allow-scripts` and `--mcp-allow-secret-reads` are refused
over HTTP.

## 5. Docker

```sh
docker run -i --rm -v "$PWD:/data" ghcr.io/c0decave/axross-headless-mcp:latest \
  --mcp-server --mcp-root /data
```

## 6. Check it works

Ask the server for `list_directory` on the root folder. A refused path lies outside
`--mcp-root` (or is a secret file, refused on purpose).
Logs: `~/.local/state/axross/logs/axross.log` (`-v` also on stderr; stdout is the
protocol's). Reference: https://github.com/c0decave/axross/blob/main/docs/MCP.md
