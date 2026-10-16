# Scripting & REPL

Axross ist mehr als ein Dateimanager — es bringt einen **eingebetteten
Python-REPL**, eine **kuratierte `axross.*`-API** als Wrapper über
jedes Backend, eine **durchsuchbare Doc-Pane**, ein **persistentes
Skript-Verzeichnis** und eine **MCP-Tool-Oberfläche**, über die ein
LLM-Agent eigene Skripte schreiben und ausführen kann.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

---

## Wege, Code gegen axross laufen zu lassen

| Weg | Wann | Einstieg |
|---|---|---|
| **Scripts-Dock** | Skripte in der GUI schreiben, verwalten, starten | *View > Panels > Scripts* (neben *Console*) |
| **Console-Dock** (REPL) | Interaktives Erkunden in der GUI | Unteres Dock, Tab *Console* |
| **`axross --script <datei>`** | Headless / Cron / CI | `axross --script myscript.py` |
| **REPL-Slash-Commands** | Skripte am Prompt speichern/laden/starten | `.save name`, `.run name` |
| **Scheduled Jobs** | Gespeichertes Skript im Intervall | *View > Scheduled Jobs…* |
| **MCP `script_*`-Tools** | LLM-Agent steuert axross | Mit `--mcp-allow-scripts` starten |

Alle nutzen dasselbe `core.scripting`-Modul — was im REPL geht,
geht im Skript, headless oder über LLM identisch. *Help > Scripting
Guide* zeigt diese Anleitung (in der Sprache der Oberfläche) und die
API-Referenz in der App; *F1* listet die Keys des Scripts-Docks und die
Slash-Commands.

---

## Das Scripts-Dock

*View > Panels > Scripts*: links die gespeicherten Skripte
(`~/.config/axross/scripts/`) und die mitgelieferten **Examples**
(read-only, **Copy to My Scripts** legt eine editierbare Kopie an), in
der Mitte ein Python-Editor mit Syntax-Highlighting, Zeilennummern und
Auto-Indent (Tab = vier Spaces, Shift+Tab rückt aus), unten der Output.

- **New**, **Save** (Ctrl+S), **Save As…**, **Rename…**, **Delete**
  verwalten die Datei; ein geändertes Skript trägt `*`, Wechseln oder
  Schließen mit ungespeicherten Änderungen fragt Save / Discard / Cancel.
- **Run** (Ctrl+Return) speichert zuerst und startet das Skript dann
  **in einem eigenen Python-Prozess** (`python -I`, cwd = Skript-
  Verzeichnis, derselbe `axross`-Namespace wie `--script`). Das Fenster
  wartet nie; stdout/stderr laufen live in den Output (die neuesten
  10 000 Zeilen), danach Exit-Status und Dauer. **Stop** beendet den
  Lauf, nach 3 s per Kill. Schließen des Fensters beendet ihn ebenfalls.
- Eine Traceback-Zeile, die ins Skript zeigt, ist ein Link zur Zeile.
- **Run in Console** führt das Skript im Live-Namespace der Console aus
  (wie `.run`); dann wartet das Fenster, bis es fertig ist. Im eigenen
  Prozess kann `axross.confirm()` niemanden fragen: es wirft
  `axross.NonInteractiveError`, statt den Default zu nehmen
  (`assume_yes=True` antwortet ohne Rückfrage mit Ja).
- Skripte eines Scheduled Jobs tragen `[scheduled]`; Rename/Delete
  warnen vorher.
- Im **paranoid**-Mode sind Run und Run in Console deaktiviert (der
  Tooltip sagt warum); `.run` und der Kindprozess verweigern ebenso.

---

## Die `axross.*`-API

Die kuratierte Oberfläche umfasst **über hundert öffentliche Namen**
(`len(axross.__all__)`; `axross.api_schema()` listet jeden) über
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

### Datei-Metadata

```python
report = axross.metadata(b, "/photos/IMG_0001.jpg")      # MetadataReport
for f in report.fields:
    print(f.group, f.name, f.value, "kept" if not f.removable else "")
axross.remove_metadata(b, "/photos/IMG_0001.jpg")        # in place, Ctrl+Z restores
axross.remove_metadata(b, "/photos", recursive=True, mode="copy")  # name.clean.ext
axross.export_metadata(b, "/photos", fmt="csv", recursive=True, out="/tmp/meta.csv")
```

Bilder behalten nur EXIF-Orientation und ICC-Profil und werden nie neu
kodiert; PDF braucht das Extra `[metadata]` (pypdf), Audio / Video
braucht ffmpeg. Ein `remove_metadata`-Aufruf ist ein Undo-Schritt.

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
| `.run <name>` | Skript im aktiven REPL-Namespace ausführen (im paranoid-Mode verweigert) |
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

Mit `--mcp-allow-scripts` werden sechs zusätzliche Tools für MCP-
Clients (Claude Desktop, Cline, eigene Agenten) freigeschaltet:

| Tool | Beschreibung |
|---|---|
| `script_list` | Namen aller gespeicherten Skripte |
| `script_api_schema` | Die `axross.*`-API als JSON (`axross.api_schema()`) |
| `script_read` | Quellcode eines Skripts |
| `script_write` | Python-Quelle als `<name>.py` (Mode 0o600) speichern |
| `script_run` | Skript im eigenen Prozess ausführen (`args`, `timeout_s`); liefert Exit-Status, stdout/stderr, eine nicht gefangene Exception |
| `script_delete` | Skript löschen |

`script_run` führt beliebigen Python-Code als Server-User aus — in
einem Kindprozess mit leerem stdin, Wall-Clock-Timeout und eigener
Prozessgruppe, aber mit allen Rechten dieses Users. Das Flag ist
deshalb **getrennt von `--mcp-write`**. Wer dem LLM kein
Code-Ausführungsrecht geben will, lässt es aus. Beide Flags off →
MCP bleibt strikt read-only. Das Antwortformat steht in
[MCP_de.md](MCP_de.md) §2.

---

## Skripte, die eine Maschine ausführt

Ein LLM (oder Cron, CI, jeder Aufrufer ohne Mensch an der Tastatur)
braucht Zusagen, die die REPL nie geben musste:

- **Erst nachsehen, dann schreiben.** `axross.api_schema()` (MCP:
  `script_api_schema`) ist die API als JSON, aus dem Code gebaut: je
  Funktion Signatur mit Typen, erster Docstring-Absatz, `mutates`
  (kann Dateien, Remote-Zustand oder Einstellungen ändern) und
  `prompts` (kann einen Menschen brauchen), dazu die Methoden jeder
  Backend-Session. `axross.docs(name)` ist der Fließtext zu einer
  Funktion.
- **Niemand zum Fragen.** Ohne Qt-Fenster und ohne Terminal auf stdin
  — oder mit `AXROSS_NONINTERACTIVE=1`, das `script_run` setzt — wirft
  `axross.confirm()` `axross.NonInteractiveError` (ein
  `PermissionError`), statt eine Antwort zu raten. `assume_yes=True`
  antwortet dort ohne Rückfrage mit Ja; `axross.is_interactive()` sagt
  dem Skript, welcher Fall vorliegt. Ein Schreibzugriff auf ein als
  *production* markiertes Profil wird genauso verweigert, außer die
  Umgebung, die axross startet, setzt `AXROSS_TARPIT_DISABLE=1`. Ein
  Lauf aus dem Scripts-Panel bekommt weiter den Countdown: seine Ausgabe
  ist live und Stop beendet ihn, ein Mensch kann also zusehen und
  abbrechen.
- **Schließen, was man öffnet.** Jede Session kann `with`; das Ende des
  Blocks beendet die Verbindung, auch nach einer Exception:

  ```python
  with axross.open("backup-server") as b:
      print(axross.summarize(b, "/var/log").render())
  ```
- **Argumente und Exit-Status.** `script_run` gibt `args` als
  `sys.argv[1:]` ans Skript und meldet `sys.exit(n)` als `exit`; eine
  nicht gefangene Exception kommt als `error_type`, `error` und
  `traceback` zurück.

---

## Siehe auch

- [USAGE_de.md](USAGE_de.md) — kompletter GUI-Durchgang
- [MCP_de.md](MCP_de.md) — MCP-Server-Referenz
- [OPSEC.md](OPSEC.md) — OPSEC-Defaults
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — adversarial review
