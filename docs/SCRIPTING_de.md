# Scripting & REPL

Axross ist mehr als ein Dateimanager — es bringt einen **eingebetteten
Python-REPL**, eine **kuratierte `axross.*`-API** als Wrapper über
jedes Backend, eine **durchsuchbare Doc-Pane**, ein **persistentes
Skript-Verzeichnis** und eine **MCP-Tool-Oberfläche**, über die ein
LLM-Agent eigene Skripte schreiben und ausführen kann.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

---

## Vier Wege, Code gegen axross laufen zu lassen

| Weg | Wann | Einstieg |
|---|---|---|
| **Console-Dock** (REPL) | Interaktives Erkunden in der GUI | Unteres Dock, Tab *Console* |
| **`axross --script <datei>`** | Headless / Cron / CI | `axross --script myscript.py` |
| **REPL-Slash-Commands** | Skripte am Prompt speichern/laden/starten | `.save name`, `.run name` |
| **MCP `script_*`-Tools** | LLM-Agent steuert axross | Mit `--mcp-allow-scripts` starten |

Alle vier nutzen dasselbe `core.scripting`-Modul — was im REPL geht,
geht im Skript, headless oder über LLM identisch.

---

## Die `axross.*`-API

Die kuratierte Oberfläche umfasst **90 öffentliche Namen** über
connect/backend, profiles, file I/O, crypto/archives, bookmarks,
scripts, per-protocol, DNS/net, network helpers, SNMP,
cross-backend search, content inspection, safety/diagnostics,
UI helpers und reference. Jede Funktion hat einen Docstring;
Doc-Pane und `axross.help()` ziehen direkt daraus.

```python
# Verbinden
b = axross.open("backup-server")
b = axross.open_url("sftp://alice@host/")
local = axross.localfs()
ram = axross.ramfs()

# Datei-IO
axross.copy(b1, src, b2, dst)
axross.copy(b1, src, b2, dst, overwrite=True)  # Ziel bewusst ersetzen
axross.remove(b, path, confirm=True)           # dauerhaft löschen
axross.trash(b, path, confirm=True)            # in Axross-Trash verschieben
axross.checksum(b, path)
axross.read_text(b, path)
axross.write_text(b, path, text, overwrite=True)
axross.hash_file(b, path, "sha256")

# Verschlüsselung & Archive
axross.encrypt(b, "/secret.txt", "passphrase")
axross.encrypt(b, "/secret.txt", "passphrase", keep_original=False)
axross.decrypt(b, "/secret.txt.axenc", "passphrase")
axross.extract_archive("/tmp/x.zip", "/tmp/out")

# Bookmarks & Profile
axross.list_bookmarks()
axross.add_bookmark(name="logs", path="/var/log")
axross.save_profile(profile)

# Skript-Verzeichnis
axross.script_dir()
axross.save_script("hello", "...")
axross.run_script("hello")

# Per-Protokoll
axross.find_tftp_files(tftp_session)
axross.slp_discover("10.0.0.10")     # CVE-2023-29552 entschärft
axross.nntp_post(session, "alt.test", subject, body)
axross.git_push(git_session)         # nur Fast-Forward, kein Force-Push

# Netzwerk
axross.dns_resolve("example.com")
axross.port_open("10.0.0.1", 22)
```

Copy/write/encrypt verweigern vorhandene Ziele standardmäßig.
`overwrite=True` ist der explizite Opt-in zum Ersetzen. `remove()` und
`trash()` laufen nur mit `confirm=True`.

### Safety & Diagnostics

```python
axross.preview_delete(local, ["/tmp/old"])
axross.preview_transfer(src, dst, ["/logs"], "/backup", operation="copy")
axross.diagnose(src, root="/", write_test=False)
axross.recovery_scan(src, "/")
axross.recent_operations(20)
axross.security_mode("paranoid")
```

---

## REPL-Slash-Commands

Werden am `>>> `-Prompt eingegeben — kein Python. Sie verändern den
Interpreter-Namespace nicht.

| Command | Wirkung |
|---|---|
| `.help` | Diese Liste |
| `.scripts` | Alle gespeicherten Skripte |
| `.save <name>` | Aktuelle Session-History als `<name>.py` speichern |
| `.load <name>` | Quellcode eines Skripts ausgeben |
| `.run <name>` | Skript im aktiven REPL-Namespace ausführen |
| `.delete <name>` | Skript löschen |
| `.open` | Pfad des Skript-Verzeichnisses zeigen |

---

## Mitgelieferte Beispiel-Skripte

32 fertige Skripte unter `resources/scripts/` — entweder direkt mit
`axross --script resources/scripts/<name>.py` oder ins
`~/.config/axross/scripts/` kopieren und aus dem REPL mit
`.run <name>` starten.

Beispiele fuer die oeffentliche `axross.*` API liegen unter
[`examples/scripting_api/`](../examples/scripting_api/). Das sind
normale Python-Module mit lokalen Smoke-Tests und optionalen
Docker-Lab-Protokolltests.

Die englische Version listet jedes Skript einzeln auf; siehe
[SCRIPTING.md](SCRIPTING.md#bundled-example-scripts).

---

## MCP-Tool-Oberfläche

Mit `--mcp-allow-scripts` werden fünf zusätzliche Tools für MCP-
Clients (Claude Desktop, Cline, eigene Agenten) freigeschaltet:

| Tool | Beschreibung |
|---|---|
| `script_list` | Namen aller gespeicherten Skripte |
| `script_read` | Quellcode eines Skripts |
| `script_write` | Python-Quelle als `<name>.py` (Mode 0o600) speichern |
| `script_run` | Skript ausführen, stdout/stderr + Namespace-Keys zurückgeben |
| `script_delete` | Skript löschen |

`script_run` führt Python im Server-Prozess aus — das Flag ist
deshalb **getrennt von `--mcp-write`**. Wer dem LLM kein
Code-Ausführungsrecht geben will, lässt es aus. Beide Flags off →
MCP bleibt strikt read-only.

---

## Siehe auch

- [USAGE_de.md](USAGE_de.md) — kompletter GUI-Durchgang
- [MCP_de.md](MCP_de.md) — MCP-Server-Referenz
- [OPSEC.md](OPSEC.md) — OPSEC-Defaults
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — adversarial review
