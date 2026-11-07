# Scripting & REPL

Axross ist mehr als ein Dateimanager — es bringt einen **eingebetteten
Python-REPL**, eine **kuratierte `axross.*`-API** als Wrapper über
jedes Backend, eine **durchsuchbare Doc-Pane**, ein **persistentes
Skript-Verzeichnis** und eine **MCP-Tool-Oberfläche**, über die ein
LLM-Agent eigene Skripte schreiben und ausführen kann.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

**Inhalt**

- [Wege, Code gegen axross laufen zu lassen](#wege-code-gegen-axross-laufen-zu-lassen)
- [Das Scripts-Dock](#das-scripts-dock)
- [Die `axross.*`-API](#die-axross-api)
  - [Öffnen / Verbinden](#öffnen--verbinden)
  - [Datei-I/O](#datei-io)
  - [Verschlüsselung + Archive](#verschlüsselung--archive)
  - [Bookmarks](#bookmarks)
  - [Skript-Verzeichnis](#skript-verzeichnis)
  - [Durchgriffe pro Protokoll](#durchgriffe-pro-protokoll)
  - [Netzwerk-Helfer](#netzwerk-helfer)
  - [Datei-Metadata](#datei-metadata)
  - [Safety + Diagnostics](#safety--diagnostics)
  - [Duplikat-Index](#duplikat-index)
- [REPL-Slash-Commands](#repl-slash-commands)
- [Mitgelieferte Beispiel-Skripte](#mitgelieferte-beispiel-skripte)
- [MCP-Tool-Oberfläche](#mcp-tool-oberfläche)
- [Skripte, die eine Maschine ausführt](#skripte-die-eine-maschine-ausführt)
- [Siehe auch](#siehe-auch)

---

## Wege, Code gegen axross laufen zu lassen

| Weg | Wann | Einstieg |
|---|---|---|
| **Scripts-Dock** | Skripte in der GUI schreiben, speichern, verwalten und starten | *View > Panels > Scripts* (neben *Console*) |
| **Console-Dock** (REPL) | Interaktives Erkunden in der GUI | Unteres Dock, Tab *Console* |
| **`axross --script <datei>`** | Headless / Cron / CI | `axross --script myscript.py` |
| **REPL-Slash-Commands** | Skripte am Prompt speichern / laden / starten | `.save name`, `.run name` |
| **Scheduled Jobs** | Ein gespeichertes Skript im Intervall starten | *View > Scheduled Jobs…* |
| **MCP `script_*`-Tools** | Ein LLM-Agent steuert axross | Mit `--mcp-allow-scripts` starten |

Alle Wege nutzen darunter dasselbe Modul `core.scripting` — was im
REPL geht, geht genauso im Skript, headless oder über ein LLM.
*Help > Scripting Guide* zeigt diese Anleitung (in der Sprache der
Oberfläche) und die vollständige API-Referenz in der App; *F1* listet
die Tasten des Scripts-Docks und die Slash-Commands.

---

## Das Scripts-Dock

*View > Panels > Scripts* öffnet die Skriptverwaltung, als Tab neben
der Console. Links: die gespeicherten Skripte
(`~/.config/axross/scripts/`) und die mitgelieferten **Examples**. In
der Mitte: ein Python-Editor mit Syntax-Highlighting, Zeilennummern
und Auto-Indent (Tab fügt vier Leerzeichen ein, Shift+Tab rückt aus,
beides auch für eine ganze Auswahl). Unten: die Ausgabe des letzten
Laufs.

| Aktion | Was sie tut |
|---|---|
| **New** | Legt `<name>.py` aus einer kurzen Vorlage an (Namen: Buchstaben, Ziffern, `_`, `-`) |
| **Save** (Ctrl+S) | Schreibt den Editor-Text (Mode 0600). Ein geändertes Skript zeigt `*` |
| **Save As…** | Speichert den Editor-Text unter neuem Namen; die Originaldatei bleibt unverändert |
| **Rename…** / **Delete** | Datei umbenennen oder löschen; Delete fragt vorher |
| **Run** (Ctrl+Return) | Speichert ungesicherte Änderungen und startet das Skript dann **in einem eigenen Python-Prozess** |
| **Stop** | Beendet den Lauf; ist er nach 3 s nicht zu Ende, per Kill |
| **Run in Console** | Führt das gespeicherte Skript im Live-Namespace der Console aus (wie `.run`) |
| **Copy to My Scripts** | Legt eine editierbare Kopie eines mitgelieferten Examples an (Examples sind read-only); an ihrem Ende steht der Aufruf des Examples als auskommentierter "Try it"-Abschnitt |
| **Run** / **Run in Console** auf einem Example | Zeigt den Usage-Aufruf des Examples zum Anpassen (Pfade, Hosts, Profile) und führt das Example damit aus |

So verhält sich ein Lauf:

- Das Kind läuft mit demselben `axross`-Namespace wie `axross --script`
  (`__name__ == "__main__"`, `__file__` ist der Skriptpfad), im
  Skript-Verzeichnis, isoliert mit `python -I`, damit ein gespeichertes
  Skript namens `json.py` für die anderen nicht die Standardbibliothek
  ersetzt. Das Fenster wartet nie darauf; es läuft immer nur ein Lauf.
- stdout und stderr (rot) laufen live in die Ausgabe, die die neuesten
  10 000 Zeilen behält und Zeilen über 1 000 Zeichen kürzt. Die
  Statuszeile zeigt Exit-Status und Dauer, oder *stopped*.
- Eine Traceback-Zeile, die ins Skript zeigt, ist ein Link: ein Klick
  springt im Editor zu dieser Zeile.
- Schließen des Fensters beendet ein laufendes Skript. Wechseln zu
  einem anderen Skript oder Schließen des Fensters mit ungespeicherten
  Änderungen fragt Save / Discard / Cancel.
- Ein eigener Lauf hat kein Terminal: `axross.confirm()` wirft
  `axross.NonInteractiveError`, statt für Sie zu antworten
  (`assume_yes=True` antwortet ohne Rückfrage mit Ja), und
  `axross.message()` schreibt in die Ausgabe. Skripte, die Dialoge
  brauchen, laufen mit **Run in Console** — dann auf dem GUI-Thread,
  und das Fenster wartet, bis sie fertig sind.
- Skripte, die ein Scheduled Job startet, tragen `[scheduled]`;
  Umbenennen oder Löschen warnt vorher, weil der Job sie beim Namen
  nennt.
- Im Sicherheitsmodus **paranoid** (*Edit > Settings > Security*) sind
  Run und Run in Console deaktiviert (der Tooltip sagt warum); `.run`
  und der Kindprozess verweigern ebenso.

---

## Die `axross.*`-API

Der kuratierte Namespace umfasst **über hundert öffentliche Namen**
(`len(axross.__all__)`; `axross.api_schema()` listet jeden) in den
Gruppen connect/backend, profiles, file I/O, crypto/archives,
bookmarks, scripts, Durchgriffe pro Protokoll, DNS/net, network
helpers, SNMP, cross-backend search, content inspection,
safety/diagnostics, UI helpers und reference. Jede Funktion hat einen
Docstring; die Doc-Pane des REPL und `axross.help()` ziehen direkt
daraus.

### Öffnen / Verbinden

```python
b = axross.open("backup-server")            # über den Namen eines gespeicherten Profils
b = axross.open_url("sftp://alice@host/")   # über eine URL
local = axross.localfs()                     # das Dateisystem des Rechners
ram = axross.ramfs(max_bytes=64 * 1024 ** 2) # flüchtiger Arbeitsbereich im Prozess

axross.list_profiles()      # Namen der gespeicherten Profile
axross.get_profile(name)    # das ConnectionProfile holen
axross.save_profile(p)      # hinzufügen oder ersetzen
axross.delete_profile(name)

axross.list_backends()      # alle registrierten Protokolle
axross.available_backends() # nur die, deren Abhängigkeiten installiert sind
```

### Datei-I/O

```python
axross.copy(b1, src, b2, dst)       # Kopie über Backends hinweg
axross.move(b1, src, b2, dst)       # Verschieben über Backends (Rename oder Copy+Delete)
axross.copy(b1, src, b2, dst, overwrite=True)  # Ziel bewusst ersetzen
axross.remove(b, path, confirm=True)           # dauerhaft löschen
axross.trash(b, path, confirm=True)            # wiederherstellbar löschen
axross.checksum(b, path)            # native Prüfsumme, wenn billig, sonst Streaming-Hash
axross.read_bytes(b, path)
axross.write_bytes(b, path, data, overwrite=True)
axross.read_text(b, path)
axross.write_text(b, path, text, overwrite=True)
axross.hash_bytes(data, "sha256")
axross.hash_file(b, path, "sha256")
```

Copy/write/encrypt verweigern vorhandene Ziele standardmäßig.
`overwrite=True` nur übergeben, wenn das Ersetzen gewollt ist.
`remove()` und `trash()` verlangen `confirm=True`, damit Headless-Skripte
nicht versehentlich löschen.

### Verschlüsselung + Archive

```python
axross.encrypt(b, "/secret.txt", "passphrase")     # behält /secret.txt
axross.encrypt(b, "/secret.txt", "passphrase", keep_original=False)
axross.decrypt(b, "/secret.txt.axenc", "passphrase")
axross.extract_archive("/tmp/x.zip", "/tmp/out")   # gegen Zip-Bombe / Zip-Slip geschützt
axross.is_archive("/tmp/x.zip")
```

### Bookmarks

```python
axross.list_bookmarks()
axross.add_bookmark(name="logs", path="/var/log", backend_name="Local")
axross.remove_bookmark(index)
```

### Skript-Verzeichnis

```python
axross.script_dir()                   # ~/.config/axross/scripts/, Mode 0700
axross.list_scripts()                 # Namen aller gespeicherten Skripte
axross.save_script("hello", "...")    # von Anfang an Mode 0600
axross.load_script("hello")           # Quelltext als str
axross.run_script("hello")            # exec in frischem Namespace; gibt ihn zurück
axross.delete_script("hello")
```

### Durchgriffe pro Protokoll

```python
axross.find_tftp_files(tftp_session)              # mitgelieferte Wortliste + Cache
axross.slp_discover("10.0.0.10", scope="DEFAULT") # CVE-2023-29552 entschärft
axross.nntp_post(nntp_session, "alt.test", subject, body)
axross.git_push(git_session)                      # nur Fast-Forward, kein Force-Push
```

### Netzwerk-Helfer

```python
axross.dns_resolve("example.com", family="any")
axross.port_open("10.0.0.1", 22, timeout=3.0)
```

### Datei-Metadata

```python
report = axross.metadata(b, "/photos/IMG_0001.jpg")      # MetadataReport
for f in report.fields:
    print(f.group, f.name, f.value, "kept" if not f.removable else "")
axross.remove_metadata(b, "/photos/IMG_0001.jpg")        # an Ort und Stelle, Ctrl+Z stellt wieder her
axross.remove_metadata(b, "/photos", recursive=True, mode="copy")  # name.clean.ext
axross.export_metadata(b, "/photos", fmt="csv", recursive=True, out="/tmp/meta.csv")
```

Bilder behalten nur EXIF-Orientation und ICC-Profil und werden nie neu
kodiert; PDF braucht das Extra `[metadata]` (pypdf), Audio / Video
braucht ffmpeg. Ein `remove_metadata`-Aufruf ist ein Undo-Schritt.

### Safety + Diagnostics

```python
axross.preview_delete(local, ["/tmp/old"])
axross.preview_transfer(src, dst, ["/logs"], "/backup", operation="copy")
axross.diagnose(src, root="/", write_test=False)
axross.recovery_scan(src, "/")
axross.recent_operations(20)
axross.security_mode("paranoid")  # sperrt Vorschauen, Skripte und Legacy-Protokolle
```

### Duplikat-Index

Der Index des Duplicate Finders (*View > Duplicate Finder…*,
Ctrl+Shift+D) und seine Scan-Historie (*View > Duplicate Index &
History…*). Jede Gruppe listet ihre Kopien in Behalten-Reihenfolge: die
nach Änderungszeit älteste zuerst, bei Gleichstand der kürzere, dann
der alphabetisch erste Pfad; Kopien ohne Zeit kommen zuletzt.

```python
for scan in axross.duplicate_scans():            # neueste zuerst
    print(scan.scan_id, scan.status, scan.root, scan.duplicate_groups)
groups = axross.duplicates(folder="/home/me/Photos")   # oder scan=<id>
plan = axross.dedupe(folder="/home/me/Photos")   # Probelauf: nichts wird angefasst
print(plan.render())                             # behalten / Trash je Gruppe
axross.dedupe(folder="/home/me/Photos", dry_run=False)  # in den axross-Trash
```

`dedupe(dry_run=False)` behält die erste Kopie jeder Gruppe und
verschiebt die anderen in den axross-Trash (wiederherstellbar), nachdem
es jede Datei und die behaltene Kopie auf dem Live-Backend erneut
geprüft hat; es handelt nur auf den übergebenen `backends`
(Standard: das lokale Dateisystem).

---

## REPL-Slash-Commands

Werden am `>>> `-Prompt eingegeben; kein Python. Sie verändern den
Interpreter-Namespace nie.

| Command | Wirkung |
|---|---|
| `.help` | Diese Liste |
| `.scripts` | Namen aller gespeicherten Skripte |
| `.save <name>` | Die History der aktuellen Session als `<name>.py` speichern; ein vorhandenes Skript gleichen Namens wird nie ersetzt (erst `.delete`) |
| `.load <name>` | Den Quelltext eines gespeicherten Skripts ausgeben |
| `.run <name>` | Ein gespeichertes Skript im Live-Namespace des REPL ausführen (im paranoid-Mode verweigert) |
| `.delete <name>` | Ein gespeichertes Skript löschen |
| `.open` | Den Pfad des Skript-Verzeichnisses ausgeben |

---

## Mitgelieferte Beispiel-Skripte

32 Beispiel-Skripte unter `resources/scripts/`. Jedes definiert
Funktionen; der `Usage::`-Block seines Docstrings zeigt den Aufruf, eine
Datei, die so wie sie ist gestartet wird, gibt also nichts aus. In der
GUI stehen sie im Scripts-Dock unter **Examples**: **Run** oder **Run in
Console** zeigt diesen Aufruf zum Anpassen und führt das Example damit
aus, **Copy to My Scripts** legt eine editierbare Kopie mit dem Aufruf
als auskommentiertem "Try it"-Abschnitt an. Ein Lauf, der nur
Funktionen definiert hat, sagt das in der Statuszeile.

Beispiele für die öffentliche `axross.*`-API liegen unter
[`examples/scripting_api/`](../examples/scripting_api/). Das sind
normale Python-Module mit lokalen Smoke-Tests und optionalen
Protokolltests gegen das Docker-Lab.

| Skript | Was es tut | E2E getestet |
|---|---|:---:|
| `mirror.py` | Inkrementeller, hash-bewusster Abgleich zwischen zwei beliebigen Backends | ✓ |
| `dedupe.py` | Doppelte Dateien per sha256 in einem Baum finden | ✓ |
| `du.py` | Platzbelegung als Baum, nach Größe sortiert — `du -sh` für jedes Backend | ✓ |
| `bulk_rename.py` | Umbenennen per Regex in einem Verzeichnis, standardmäßig als Probelauf | ✓ |
| `find_secrets.py` | Sucht AWS-Keys, JWTs, Private-Key-Blöcke, .env-Werte | ✓ |
| `port_scan.py` | Paralleler TCP-Test über Hosts × COMMON_PORTS | ✓ |
| `redact.py` | Jede Datei, die auf eine Regex passt, mit `.axenc` verschlüsseln | ✓ |
| `hash_audit.py` | Ein `<sha256>\\t<path>`-Manifest gegen ein Backend prüfen | ✓ |
| `fingerprint_diff.py` | sha256-Diff zweier Bäume: hinzugefügt / entfernt / geändert / gleich | ✓ |
| `sqlite_export.py` | Einen Verzeichnisbaum in eine SQLite-FS-Datei packen | ✓ |
| `ramfs_decrypt.py` | `.axenc` direkt in den RAM entschlüsseln, ohne die Platte zu berühren | ✓ |
| `bookmarks_export.py` | Gespeicherte Bookmarks als JSON oder CSV sichern / zurückspielen | ✓ |
| `s3_inventory.py` | Objektanzahl + Gesamtbytes + Top-N + Histogramm der Endungen | ✓ |
| `git_changelog.py` | Einen Git-FS-Branch durchgehen, `<sha>  <subject>`-Zeilen ausgeben | ✓ |
| `gopher_archive.py` | Ein Gopher-Loch rekursiv herunterladen | ✓ |
| `tftp_audit.py` | Wortlisten-Scan über eine Liste von TFTP-Hosts | smoke |
| `slp_inventory.py` | SLPv2-Diensterkennung über eine Host-Liste | smoke |
| `nntp_subjects.py` | Betreffzeilen der letzten N Artikel einer Usenet-Gruppe | smoke |
| `webdav_quota.py` | RFC 4331 `disk_usage` über WebDAV-Endpunkte | smoke |
| `cisco_collect.py` | `show running-config` + Version + Interfaces von IOS-Hosts | smoke |
| `imap_archive.py` | Jede Nachricht eines IMAP-Ordners als `.eml` herunterladen | smoke |
| `lab_smoke.py` | Smoke-Test "Ist jedes konfigurierte Backend erreichbar?" | smoke |

Die "smoke"-Zeilen kompilieren und importieren korrekt; sie werden
nicht Ende-zu-Ende geprüft, weil sie laufende Infrastruktur brauchen
(einen TFTP-Server, einen SLP-Daemon, ein IMAP-Postfach, ein
Cisco-Gerät, …), die die Standard-Testumgebung nicht mitbringt.

---

## MCP-Tool-Oberfläche

Dieselbe Scripting-Maschinerie steht MCP-Clients (Claude Desktop,
Cline, eigene Agenten) offen. Mit `--mcp-allow-scripts` werden
freigeschaltet:

| Tool | Beschreibung | Freigeschaltet durch |
|---|---|---|
| `script_list` | Namen aller gespeicherten Skripte | `--mcp-allow-scripts` |
| `script_api_schema` | Die `axross.*`-API als JSON (`axross.api_schema()`) | `--mcp-allow-scripts` |
| `script_read` | Quelltext eines gespeicherten Skripts | `--mcp-allow-scripts` |
| `script_write` | Python-Quelle als `<name>.py` speichern (Mode 0o600) | `--mcp-allow-scripts` |
| `script_run` | Ein gespeichertes Skript im eigenen Prozess ausführen (`args`, `timeout_s`); liefert Exit-Status, stdout/stderr, eine nicht gefangene Exception | `--mcp-allow-scripts` |
| `script_delete` | Ein gespeichertes Skript löschen | `--mcp-allow-scripts` |

`script_run` führt beliebigen Python-Code als Benutzer des Servers aus —
in einem Kindprozess mit leerem stdin, Wall-Clock-Timeout und eigener
Prozessgruppe, aber mit allen Rechten dieses Benutzers. Das Flag ist
deshalb **getrennt von `--mcp-write`**: Scripting nicht für einen
LLM-Client einschalten, dem man nicht ohnehin beliebige Code-Ausführung
zutraut. Sind beide Flags aus, bleibt die MCP-Oberfläche read-only.
[MCP_de.md](MCP_de.md) §2 beschreibt das Antwortformat vollständig.

---

## Skripte, die eine Maschine ausführt

Ein LLM (oder Cron, CI, jeder Aufrufer ohne Mensch an der Tastatur)
braucht ein paar Zusagen, die der REPL nie geben musste. Was die API
bietet:

- **Erst nachsehen, dann schreiben.** `axross.api_schema()` (MCP:
  `script_api_schema`; eingecheckt als
  [`scripting-api.json`](scripting-api.json)) ist die API als JSON, aus
  dem Code gebaut: Regeln und Exceptions für Skripte, die Namen nach
  Thema, je Funktion die Signatur mit Typen, der ganze Docstring, seine
  Beispiele, was sie wirft, `mutates` (kann Dateien, Remote-Zustand
  oder Einstellungen ändern) und `prompts` (kann einen Menschen
  brauchen); dazu die Methoden jeder Backend-Session und die Typen, die
  die API zurückgibt (`FileItem` und die Ergebnisse).
  `axross.api_schema(names=[])` ist nur der Index,
  `axross.api_schema(["copy"])` eine Funktion vollständig.
  `axross.docs(name)` ist der Fließtext zu einer Funktion;
  [LLM_GUIDE.md](LLM_GUIDE.md) §9 und §12 sind der kurze Weg für ein
  Sprachmodell.
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

- [USAGE.md](USAGE.md) / [USAGE_de.md](USAGE_de.md) / [USAGE_es.md](USAGE_es.md) — kompletter GUI-Durchgang
- [MCP.md](MCP.md) / [MCP_de.md](MCP_de.md) / [MCP_es.md](MCP_es.md) — MCP-Server-Referenz
- [OPSEC.md](OPSEC.md) — OPSEC-Defaults
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — adversariale Prüfung jedes Backends
