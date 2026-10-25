# axross Slideshow

Alle Screenshots von axross, jeder mit Erklärung. Zurück zur [README](README_de.md).

## Upload nach SFTP

![Upload von einem lokalen Pane nach SFTP mit dem Transfers-Dock](docs/screenshots/remote-transfer.png)

Vier Fotos vom lokalen Pane auf das NAS kopiert; das Transfers-Dock zeigt jede Datei mit Richtung, Größe und Status.

## Workspaces

![Workspaces als Tabs, ein File-Pane und eine lokale Shell nebeneinander](docs/screenshots/workspaces.png)

Benannte Pane-Layouts als Tabs - hier **Website** mit seinem File-Pane und einer lokalen Shell daneben. Ein Workspace lässt sich in ein eigenes Fenster abtrennen und kommt als Tab zurück.

## Toolbar

![Die Toolbar mit einem Icon je Werkzeug über zwei Panes und der Bookmark-Sidebar](docs/screenshots/toolbar.png)

Ein Button je Werkzeug - Agent, Analysis (sift), Terminal, Find Files, Scripts, Python-Console, Tags, Trash, Media Player, Audio & Video Settings, Treemap, Drives, Settings, Features. In einem schmalen Fenster rücken die Werkzeuge in eine zweite Zeile, statt zu verschwinden. Die Buttons sind nach Kategorie gruppiert - Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions -, mit einem Separator zwischen den Gruppen, und die Farbe jeder Kategorie liegt als dezenter Tint hinter ihren Buttons, ohne ein Icon schwer lesbar zu machen. Ein Button lässt sich per Drag and Drop innerhalb seiner Gruppe verschieben; die Reihenfolge bleibt erhalten, und das Kontextmenü der Toolbar hat Reset Toolbar Order. Edit → Settings… → Toolbar schaltet Gruppierung und Farben ab und setzt die Farbe jeder Kategorie.

## Tags

![Das Fenster Tagged Files mit den Dateien eines Tags](docs/screenshots/tags.png)

Farbige Punkte in der Name-Spalte; **Tagged Files** listet jeden Tag und seine Dateien auf jedem Backend, **Go to File** öffnet den Ordner in einem Pane.

## Text-Editor

![Der Text-Editor mit Tabs, Python-Highlighting und Find-Leiste](docs/screenshots/editor.png)

Tabs für lokale und Remote-Dateien, Pygments-Highlighting, Find und Replace mit Regex, Encoding und Line Endings in der Statusleiste.

## Find Files

![Find Files mit Typ-Presets und Treffern aus mehreren Ordnern](docs/screenshots/find-files.png)

Name, Inhalt, Größe, Datum, Tag und Typ-Presets, auch in Archiven; mit einem Klick wird die Suche zum **Smart Folder**.

## Media Player

![Das Media-Player-Panel mit Cover, Spektrum, Equalizer und Playlist](docs/screenshots/media-player.png)

Ein Extension-Panel: Cover und Titel, ein animiertes Spektrum, ein 10-Band-Equalizer mit Presets und eine Playlist, gefüllt per Drag & Drop.

## Disk-Images

![Die Partitionen eines Disk-Images, bereit für einen read-only Mount](docs/screenshots/disk-image.png)

Die Partitionen und Dateisysteme eines Images, gelesen, ohne etwas zu schreiben; **Mount Read-Only** bringt eine davon in ein Pane.

## Voice

![Settings, Seite Voice: gesprochene Antworten, Push-to-Talk und die Hold-Taste](docs/screenshots/voice.png)

Gesprochene Antworten auf Deutsch oder Englisch, eine Stimme je Sprache mit Speed, Pitch, Expressiveness, Volume und Pause (Listen spielt eine Probe), Push-to-Talk auf einer Hold-Taste, und wohin der erkannte Text geht.

## Bookmarks

![Manage Bookmarks mit Gruppen, einem Terminal-Bookmark und Remote-Orten](docs/screenshots/bookmarks.png)

Gruppen, lokale und Remote-Orte und ein Terminal-Bookmark in einem Manager; sortieren, verschieben und mehrere auf einmal bearbeiten.

## Settings

![Edit, Settings: alle Settings in einem Dialog mit Suchfeld](docs/screenshots/settings.png)

Jede Einstellung in einem Dialog, mit Suchfeld.

## Features

![Help, Features: was installiert ist, was fehlt und wie man es bekommt](docs/screenshots/features.png)

Was installiert ist und was fehlt, mit dem Befehl oder dem Download, der es nachrüstet.

## Amber Mode

![Das Layout-Preset quad-files im Amber Mode](docs/screenshots/quad-files.png)

Das Layout-Preset `quad-files`: vier Panes, jedes mit eigener Pfadleiste, Filter, Spalten für Permissions und Owner. `Ctrl+Alt+L` wechselt durch die Presets.

## Scripts-Dock

![Das Scripts-Dock mit einem eigenen Script](docs/screenshots/scripts-panel.png)

Eigene Scripts neben den read-only Beispielen, geschrieben gegen die `axross.*`-API; sie laufen im Dock oder in der Console.

## Duplicate Finder

![Der Duplicate Finder mit zwei Gruppen](docs/screenshots/duplicate-finder.png)

Identische Dateien per Content-Hash, gruppiert; die älteste Kopie jeder Gruppe steht fett.

## Metadaten

![Metadaten eines Fotos mit EXIF- und GPS-Daten](docs/screenshots/metadata.png)

EXIF-Felder und GPS-Position eines Fotos; **Remove Metadata** entfernt sie vor dem Teilen — in place oder als bereinigte Kopie (**Tools → Metadata Settings…**).

## Analysis-Dock (sift)

![Das Analysis-Dock erklärt eine CSV-Datei](docs/screenshots/analysis.png)

Das optionale Extra `sift` erklärt die gewählte Datei — hier eine CSV, ganz ohne LLM. Start per Rechtsklick → **Analyse with sift** (ein Ordner: **Analyse Folder with sift**), **Tools → Analyse with sift** oder `Ctrl+Shift+I`; Toolbar-Button und Titelleiste zeigen sifts Sieb. Edit → Settings… → Analysis (sift) schaltet die automatische Analyse ab und setzt sifts Read-Limit, Time Budget, Vision, Context, Tags, Categories, den Cache (mit *Clear Cache*) und ein eigenes LLM-Profil.

## Modern-Light-Theme

![Zwei Panes in der Thumbnail-Ansicht, helles Theme](docs/screenshots/thumbnails.png)

Zwei Panes in der Thumbnail-Ansicht im hellen Modern-Theme. Bilder, Videos und PDFs zeigen eine Vorschau-Kachel, Ordner ihr Icon; View → Thumbnail View (Strg+Shift+G) schaltet ein Pane zwischen Liste und Kacheln um, und das Theme folgt dem hellen oder dunklen Schema des Desktops.

## Log-Dock

![Das Log-Dock nach Copy und Move](docs/screenshots/log-dock.png)

Jedes Copy und Move wird mit seinem Integrity-Check (sha256) und einem Eintrag im Operation-Journal protokolliert.

## Topics

![Das Topics-Menü eines Agent-Tabs](docs/screenshots/agent-topics.png)

Fertige Aufgaben — Inventar, Services, Logs, Disk Usage, Zusammenfassung eines Ordners — füllen die Anfrage aus; jeder Tab ist eine eigene Session.

## Die Verbindung eines Panes, dem Agent geliehen

![Der Agent liest eine Datei eines Remote-Panes](docs/screenshots/agent-remote-pane.png)

Das linke Pane ist mit einem Remote-Speicher verbunden; der Agent liest `/reports/q3.txt` darüber, ohne eigenen Login.

## Sandbox-Profile

![Agent Settings, Seite Sandboxes](docs/screenshots/agent-sandboxes.png)

Engine (bubblewrap, podman, docker), Level von `lax` bis `paranoid`, erlaubte Hosts und zusätzliche Ordner — vor jeder Aufgabe angewandt.

## Access pro Tab

![Der Access-Dialog eines Agent-Tabs](docs/screenshots/agent-access.png)

Welche axross-Funktionen der Agent nutzen darf, welche Hosts er erreicht und welche Ordner er sieht, read-only oder schreibbar.

## MCP-Server

![Agent Settings, Seite MCP Servers](docs/screenshots/agent-mcp-servers.png)

Weitere MCP-Server für den Agent — hier axross selbst über stdio, getestet: 11 Tools.

## Agent Stats

![Das Agent-Stats-Fenster über dem Hauptfenster](docs/screenshots/agent-stats.png)

Die mitgelieferte Extension zählt Tasks, Tool Calls, Fehler und Tokens, für alle Tabs und den letzten.

## Agent-Profile

![Das +-Menü des Agent-Docks mit New Tab from Profile und den sieben Presets](docs/screenshots/agent-profiles.png)

Der Pfeil neben **+** öffnet einen neuen Agent-Tab aus einem Profil - sieben Presets (Files Assistant, Reverse Engineering, Forensics read-only, Network & Web Recon, Code & Secrets, Remote Ops, Research) oder ein eigenes. Der Tab nennt sein Profil und was noch fehlt, mit **Install from Catalog…**.

## Profiles-Seite

![Settings, Agent, Profiles: das Preset Reverse Engineering und was ein Tab bekommt](docs/screenshots/agent-profile-settings.png)

Ein Profil bündelt LLM, Prompt-Profil, Protection Mode, Sandbox, Tool-Gruppen, axross-Funktionen und MCP-Server nach Kategorie oder Name. Presets sind read-only, **Copy** macht ein editierbares daraus, und die Preview zeigt, was ein Tab innerhalb der Access-Seite bekommt.

## MCP-Katalog

![Add MCP Server from Catalog mit den Servern des c0decave MCP Hub](docs/screenshots/mcp-catalog.png)

Der c0decave MCP Hub bringt 17 Security-Tools - binwalk, capa, Nmap, YARA, The Sleuth Kit und mehr - als per Digest gepinnte Images; jedes läuft in podman ohne Capabilities, mit read-only Root und ohne Netzwerk, solange du es nicht freigibst. Ein Third-Party-Eintrag wie REA sagt, wer ihn pflegt.

## Cut und Paste

![Zwei Dateien in einem Pane ausgeschnitten, Paste oben im Kontextmenü des anderen](docs/screenshots/cut-paste.png)

Ctrl+X oder Rechtsklick **Cut** merkt die Dateien nur vor (gedimmt); **Paste** in einem beliebigen Pane verschiebt sie über die Transfer-Queue, und jede Quelle wird erst entfernt, wenn ihre Kopie fertig und geprüft ist. Esc leert den Filter.

## Icon-Farben

![Amber Mode mit jedem Icon in seiner eigenen Farbe und Settings, Appearance](docs/screenshots/icon-colours.png)

**Settings → Appearance → Icon colours**: der Theme-Default, eigene Farben in jedem Theme - hier im Amber Mode, dessen Default jedes Icon in Amber zeichnet - oder eine eigene Farbe.

## Self-Update

![Software Update: ein neueres axross ist da, mit Download and Install](docs/screenshots/update.png)

`axross-full` und `axross-slim` suchen einmal pro Start nach einem neuen Release, zeigen **Update to …** in der Statusleiste und ersetzen sich nach dem SHA-256-Check selbst; das alte Binary bleibt erhalten.

## Beispiele laufen direkt

![Das Scripts-Dock führt das mitgelieferte Beispiel du mit einem anpassbaren Aufruf aus](docs/screenshots/scripts-example.png)

**Run** auf einem mitgelieferten Beispiel zeigt seinen Usage-Aufruf zum Anpassen - Pfade, Hosts, Profile - und führt es aus; der Output steht darunter.

## Third-Party-Software

![Help, Third-Party Software: die Projekte, die axross nutzt oder mitliefert, mit Lizenzen](docs/screenshots/third-party.png)

**Help → Third-Party Software…** listet die 222 Projekte, die axross nutzt oder mitliefert, mit Zweck, Lizenz, wie es zu dir kommt, und Link.
