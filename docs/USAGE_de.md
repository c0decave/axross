# axross — Bedienung

Diese Anleitung beschreibt, was du mit axross tun kannst, sobald es
läuft. Installation: siehe [INSTALL.md](../INSTALL.md). Sie ist das
deutsche Handbuch von axross; *Hilfe → Handbuch* (**F1**) zeigt sie.

Sprachen: [English](USAGE.md) · **Deutsch** · [Español](USAGE_es.md)

## Auf einen Blick

axross ist ein Dateimanager für mehr als 30 Protokolle, im Stil des Total
Commander: Du arbeitest mit Servern, Cloud-Speichern und Postfächern
(SFTP, SMB, WebDAV, S3, IMAP, …) genauso wie mit den Dateien auf deinem
Rechner - im selben Fenster und mit denselben Handgriffen.

- **So viele Panes, wie du willst.** Teile das Fenster waagerecht oder
  senkrecht; jedes Pane hat seine eigene Verbindung - links dein Rechner,
  rechts ein Server, darunter ein Cloud-Bucket. Mit F5 kopierst du von
  einem Pane ins andere, mit F6 verschiebst du.
- **Dieselben Funktionen auf jeder Verbindung.** Papierkorb,
  sicheres Speichern (eine Datei ist nie nur halb geschrieben),
  verschlüsselte Dateien, frühere Versionen einer Datei und die Suche nach
  doppelten Dateien funktionieren überall - auch auf Servern, die das
  selbst nicht können.
- **Ein KI-Programm kann mitarbeiten.** axross kann ohne Fenster als
  MCP-Server laufen; ein LLM-Programm wie Claude Desktop erreicht dann
  über axross deine Verbindungen. Es darf erst einmal nur lesen -
  Schreiben erlaubst du ausdrücklich mit `--mcp-write` (siehe
  [MCP-Server](#mcp-server)).

## Handbuch und Touren

- **Hilfe → Handbuch** (**F1**)
  zeigt diese Anleitung in axross, in der Sprache der Oberfläche (Deutsch
  und Spanisch haben eine eigene, jede andere Sprache bekommt die
  englische): links das Inhaltsverzeichnis, darüber ein Suchfeld (Return
  findet den nächsten Treffer), Links zwischen den Abschnitten. Es holt
  nichts aus dem Netz und zeigt keine Bilder; Links auf die anderen
  Dokumente öffnen sie auf GitHub im Browser.
- **F1 öffnet den Abschnitt zu dem Bereich, in dem du gerade bist**: in
  einem Datei-Pane *Multi-Pane-Layout*, in seinem Adress- oder Filterfeld
  *Pfadleiste*, im Dock *Übertragungen* den gleichnamigen Abschnitt, im
  Agent-Dock *Agent-Dock*, im *Connection Manager* den Abschnitt
  *Verbindungen*, und in *Bearbeiten → Einstellungen…* den Teil zur
  gezeigten Seite (*Logging*, *Updates*, die Seiten
  des Agenten …; der Rest *Einstellungen*). Überall sonst öffnet F1 das
  Inhaltsverzeichnis. Die Liste der Tastenkürzel liegt auf **Strg+F1**
  (*Hilfe → Tastatur-Shortcuts*).
- **Hilfe → Touren…** listet geführte Touren über das
  echte Fenster: *Erste Schritte*, *Mit einem Server verbinden*, *Sicher
  kopieren und synchronisieren*, *Finden und ordnen*, *Automatisieren* und
  *Extensions und Funktionen*. Eine Tour dunkelt das Fenster um den Teil
  ab, den sie erklärt, und rahmt ihn ein - der Teil bleibt bedienbar -,
  daneben steht ein Kasten mit *Schritt k von n*, **Zurück**, **Weiter**
  und **Tour beenden**; **Esc** beendet die Tour auch. Ein Schritt, dessen
  Teil nicht im Fenster ist (ein Dock oder eine Extension ausgeschaltet,
  ein Pane geschlossen, eine Toolbar ausgeblendet), wird übersprungen, und
  der nächste Schritt sagt, welche übersprungen wurden; ein geschlossenes
  Agent-, Scripts- oder Console-Dock wird für seinen Schritt geöffnet und
  am Ende der Tour wieder geschlossen.
- **Der erste Start** bietet die Tour *Erste Schritte* einmal an, als
  Hinweis in der Statusleiste (*Tour „Erste Schritte“ starten*, *Nein
  danke*) - nie als Dialog. *Bearbeiten → Einstellungen… → Allgemein → Touren* bietet
  sie beim nächsten Start wieder an oder gar nicht (`offer_tour_at_start`
  in `settings.json`).

## Verbindungen

Im Connection Manager (Strg+Umschalt+N) legst du Profile an; die
Schnellverbindung (Strg+N) öffnet ein gespeichertes. Jedes Profil
wählt ein Protokoll und speichert Host / Username / Auth / Proxy /
protokollspezifische Optionen. Sensible Felder (Passwörter,
OAuth-Secrets, Azure-Connection-Strings) gehen in den OS-Keyring; die
Profil-JSON selbst enthält nie Klartext-Credentials.

- **Wie eine Verbindung geschützt ist.** Ein Symbol neben jeder Verbindung -
  im Pane-Kopf, im Workspace-Tab (seine schwächste Verbindung), an
  Bookmarks, in der Schnellverbindung - zeigt Klartext, nur signiert, TLS (mit einer
  Schwäche), SSH-verschlüsselt oder Ende-zu-Ende; der Tooltip sagt genau was
  und ob es auf der laufenden Verbindung ausgehandelt oder nur konfiguriert
  ist (FTP Klartext, FTPS TLS 1.3 mit geprüftem Zertifikat, SMB 3.1.1
  verschlüsselt oder nur signiert, WebDAV http oder https, NFS AUTH_SYS
  Klartext ...).

- **Fehlende Features.** *Hilfe → Funktionen…* listet jedes optionale
  Feature - Verbindungen, Dateianalyse und Archive, externe Tools wie
  ripgrep, rsync oder qemu-img, Sleuth Kit, TestDisk / PhotoRec und
  VBoxManage der Forensic- und VirtualBox-Extensions - als installiert
  oder fehlend, mit dem Weg dahin.
  *Auswahl installieren* startet `python -m pip install …` in der Python,
  die axross ausführt, nach einer Rückfrage mit dem Befehl (Ausgabe im
  Log, meist ohne Neustart); ein Frozen-Build verlinkt den
  axross-full-Download desselben Releases; ein Tool zeigt den
  Paketbefehl dieses Systems zum Kopieren. Ein Backend mit fehlenden
  Abhängigkeiten oder eine Analyse ohne sift bietet dasselbe Fenster an.
- **Host-Key-Verifizierung.** Erstkontakt bei SSH zeigt einen
  SHA-256-Fingerprint-Dialog vor dem Connect; vertraute Keys
  persistieren in `~/.ssh/known_hosts`.
- **OAuth-Flows.** OneDrive / SharePoint / Google Drive / Dropbox
  öffnen einen Browser für den Consent-Schritt (Dropbox fragt danach den
  angezeigten Code in einem Fenster ab). Der Verbindungsdialog nennt je Dienst,
  was wo anzulegen ist; Googles Client-Datei füllt beide Felder (Import Client
  JSON…). Tokens werden unter
  `~/.config/axross/<provider>_token.json` mit `0o600` ab Geburt
  gespeichert. Profil-Proxies gelten für API-/Token-Traffic, den
  axross selbst kontrolliert; die externe Browser-Consent-Seite kann
  die Proxy-Einstellungen des Browsers oder des Systems verwenden. App-Registrierung pro Anbieter:
  [OAUTH_SETUP.md](../OAUTH_SETUP.md).
- **Proxy-Support.** Per Profil SOCKS5 / SOCKS4 / HTTP-CONNECT für
  Backends mit echtem Transport-Hook. SOCKS5 löst Hostnamen
  serverseitig auf (kein DNS-Leak). SOCKS4 hängt vom Transport ab:
  Raw-Socket-Backends können SOCKS4a für serverseitige Namensauflösung
  nutzen, HTTP-SDK-Stacks können lokal auflösen. Für DNS-Leak-Schutz
  SOCKS5 verwenden. Backends ohne sauberen SOCKS/HTTP-Support warnen
  statt Proxy-Felder still zu ignorieren. S3 ist nur über HTTP-CONNECT
  proxyfähig; Rsync kann über OpenBSD `nc` `proxy_username`, aber kein
  `proxy_password` transportieren. Requests-basierte SDK-Sessions, die
  axross kontrolliert, ignorieren `HTTP_PROXY` / `HTTPS_PROXY` aus der
  Prozess-Umgebung; das Profil ist die Quelle der Route.
- **Produktionsserver.** *Produktion (destruktive Operationen mit
  Countdown bestätigen)* in der Gruppe Verbindung des Connection Managers
  markiert das Profil: das erste Löschen, Verschieben, Umbenennen oder
  Überschreiben darauf in einem Pane wartet ein paar Sekunden mit einem
  Countdown, den *Abbrechen* oder Esc abbricht. Siehe
  [DAILY_DRIVER_de.md](DAILY_DRIVER_de.md#production-tarpit).
- **OpSec-Overrides.** Profil-Felder steuern SSH-Keepalive,
  SMB-Workstation-Name, Telnet-NAWS, rsync-Metadaten-Stripping. Siehe
  [OPSEC.md](OPSEC.md) für das Threat-Modell.
- **SFTP bei verlorenem Netz.** Eine Anfrage, die der Server 60 s lang
  nicht beantwortet, scheitert mit „hat nicht rechtzeitig geantwortet“,
  statt ewig zu warten (WLAN weg, VPN getrennt); die nächste Aktion
  öffnet einen neuen Kanal. „Abbrechen“ stoppt eine SFTP- oder
  SCP-Übertragung sofort, auch während sie auf das Netz wartet; eine
  Übertragung, die hinter einer toten Leitung hängt, schließt die
  Verbindung nach weiteren 10 s (dann neu verbinden).
- **Google Drive: Docs, Sheets, Slides und geteilte Ablagen.** Ein
  Google Doc erscheint als `<Name>.docx`, ein Sheet als `.xlsx`, Slides
  als `.pptx`, eine Zeichnung als `.pdf` - ohne Größe - und wird als
  dieser Export gelesen (geöffnet, kopiert); Google exportiert höchstens
  10 MB eines Dokuments. Sie sind hier schreibgeschützt: Überschreiben
  wird abgelehnt, speichere unter einem anderen Namen. Ein Verschieben
  aus Drive heraus wird abgelehnt, bevor etwas kopiert wird - dem Export
  fehlen Kommentare, Vorschläge, Versionsverlauf und Freigaben, und das
  Verschieben würde das Original löschen: kopiere stattdessen. Ein
  gelöschtes Google Doc, Sheet oder Slides, oder ein gelöschter Ordner,
  landet im Papierkorb von Drive (dort 30 Tage wiederherstellbar); eine
  normale Datei wird gelöscht. Ein Formular oder
  eine Site hat keine Dateiform und sagt das beim Lesen. Einträge einer
  geteilten Ablage (Shared Drive), die von My Drive aus erreichbar sind
  (mit dir geteilt, der Ordner einer Verknüpfung), gehen wie alle
  anderen; die geteilten Ablagen selbst werden nicht aufgelistet (noch
  kein Ordner `/Shared drives/<Name>`) - öffne sie im Browser oder lege
  in My Drive eine Verknüpfung an.
- **Mail als Dateien (IMAP, POP3, Exchange).** Eine Nachricht heißt
  `<ID>_<Betreff>.eml`, der ganze Name höchstens 200 UTF-8-Bytes (ID und
  `.eml` ganz, ein langer Betreff an einem Zeichen gekürzt), damit sie
  sich in jeden lokalen Ordner kopieren lässt; ein Anhang behält seine
  Endung. Namen, die früher länger waren (CJK- oder Emoji-Betreffs, die
  langen ItemIds von Exchange), sind jetzt kürzer; IMAP und POP3 nehmen
  den alten Namen weiter an, und ein Mail-Dock hält die umbenannte
  Nachricht nicht für neu. Der Ordner `<UID>` neben einer IMAP-Nachricht
  listet ihre Anhänge; er lässt sich nicht für sich löschen - lösche die
  `.eml`, um die Nachricht zu löschen. POP3 verbindet sich nach einem
  Verbindungsabbruch neu; Löschungen, die über diese Verbindung gingen,
  sind nicht festgeschrieben (POP3 schreibt erst beim QUIT fest), und
  ein Fehler sagt das - ebenso, wenn das QUIT beim Trennen scheitert.
  Auf einem POP3-Server ohne UIDL wird eine Nachricht nach dem
  Neuverbinden an Headern und Größe wiedergefunden; sind zwei gleich,
  wird das Löschen abgelehnt.
- **Git-Repositories per URL.** Eine `git+https://`-Sitzung (ssh, git,
  file) ist ein zwischengespeicherter Klon, der dem Remote folgt: Beim
  Öffnen wird gefetcht, ein Branch ohne Ungepushtes folgt origin (auch
  nach einem Force-Push oder Löschen), und jedes Speichern wird sofort
  committet und gepusht (nur Fast-Forward). Scheitert ein Push, bleibt
  der Commit im Cache und das Speichern meldet es; die Statuszeile des
  Panes zeigt „nicht zu origin gepusht: main (1)“, bis das nächste
  Speichern ihn pusht. Hat jemand anderes auf den Branch gepusht, holt
  ein Speichern erst dessen Stand: Änderungen an anderen Dateien bleiben,
  deine kommt obendrauf; hat er dieselbe Datei geändert, wird das
  Speichern abgelehnt (aktualisieren und wiederholen). Noch nicht
  gepushte Commits werden auf den neuen Stand von origin gesetzt, wenn
  sie andere Dateien betreffen; sonst bleiben sie auf einem neuen Branch
  `axross/unpushed-<Datum>-<Zeit>` - die Meldung nennt ihn -, und der
  Branch zeigt den Stand von origin: Öffne den neuen Branch, um deine
  Dateien zurückzukopieren. Verloren geht so oder so nichts. Ist das
  Remote nicht erreichbar, öffnet
  sich die zwischengespeicherte Kopie schreibgeschützt, und die
  Statuszeile sagt „offline“. Skripte können `auto_push=False` übergeben
  und mit `axross.git_push()` pushen.

## Multi-Pane-Layout

- Panes anlegen durch Splitten mit **Strg+Umschalt+H** /
  **Strg+Umschalt+V**, schließen mit **Strg+W**.
- Aktives Pane bekommt blauen Rahmen; das **Ziel**-Pane (Kopierziel)
  bekommt einen grünen. Letztes fokussiertes Pane wird Ziel.
- Ein Pane wird aktiv, wenn die Maus 0,5 s darin ruht.
  **Bearbeiten → Einstellungen… → Allgemein → Pane aktivieren** stellt 0,5, 1, 2 oder
  3 s ein (*Wenn die Maus … s darauf ruht*), oder **Beim Anklicken**.
  Der Tastaturfokus folgt nur aus der Dateiliste eines anderen Panes,
  nie aus einem Textfeld.
- **Alt+Links / Alt+Rechts** durchschreiten Pane-Historie;
  **Tab** / **Umschalt+Tab** in einer Dateiliste wechseln das Pane.
- **Strg+F6** / **Strg+Umschalt+F6** (Ansicht → Nächster Bereich /
  Vorheriger Bereich) bringen den Tastaturfokus in den nächsten /
  vorherigen Bereich des Fensters: die Panes, Übertragungen und jedes
  andere sichtbare Panel. Tab hält nie in einem Panel, das hinter einem
  anderen Tab liegt.
- Drag-and-Drop zwischen Panes startet eine Übertragung (lokal↔remote,
  remote↔remote, cross-Protokoll). **Strg+X** / **Strg+V** sind Cut und
  Paste zwischen zwei beliebigen Ordnern (siehe Übertragungen).

### Workspaces — mehrere Layouts, auf mehreren Bildschirmen

Ein Workspace ist ein eigenes, benanntes Pane-Layout. **Workspace → Neuer
Workspace → Mit Dateiliste** (**Strg+Alt+N**) öffnet einen mit einem
lokalen Pane, **Mit Terminal** (**Strg+Alt+Umschalt+N**) einen mit einer
lokalen Shell; ab dem zweiten stehen die Workspaces als Tabs über den
Panes. **Strg+Alt+PgDown /
PgUp** schalten durch, und jeder behält sein eigenes Quell- und Ziel-Pane.

- **Mehrere Shells:** **Workspace → Terminal-Pane hinzufügen** (auch im
  Rechtsklick-Menü des Tabs) legt eine weitere lokale Shell in den
  Workspace, neben die Panes, die schon da sind.
- **Umbenennen:** Doppelklick auf den Tab, sein Rechtsklick-Menü oder
  **Workspace → Workspace umbenennen…**.
- **In eigenes Fenster lösen** (Workspace-Menü oder Rechtsklick auf den Tab)
  legt den Workspace in ein eigenes Fenster — etwa auf einen anderen
  Bildschirm. Schließt man das Fenster, kommt der Workspace als Tab
  zurück.
- **Pane in einen anderen Workspace schicken:** Rechtsklick auf das Pane
  → **An Workspace senden** - in der Liste eines File-Panes (auf einer
  Datei oder auf der leeren Fläche, am Ende des Menüs), auf dem Header
  eines Panes oder im Terminal - und einen Workspace oder **Neuer Workspace** wählen. Die Workspaces sind nummeriert, wie ihre Tabs
  stehen (**1: Workspace 1**, **2: Logs**; ein abgelöster trägt
  *(Fenster)*), und bei 1 bis 9 wählt die Ziffer den Eintrag, solange das
  Menü offen ist. **Workspace → Pane an Workspace senden** tut dasselbe für
  das aktive Pane; oder den Pane-Header auf ein Pane eines anderen
  Workspace oder Fensters ziehen. File-Panes und Terminal-Panes lassen
  sich gleich ziehen (ein Terminal-Pane auch über seinen ⇄-Button); ein
  Workspace, dessen letztes Pane geht, schließt; hält man ein gezogenes Pane
  eine halbe Sekunde über einen Workspace-Tab, öffnet sich dieser Tab —
  so erreicht ein Pane auch einen Workspace im Hintergrund.
- **Extension-Panels** (Media Player, Drives Overview, Markdown Preview,
  …) sind auf allen Workspaces, bis man eines auf einen Workspace legt:
  der ⇄-Button in seiner Titelleiste (oder ein Rechtsklick darauf, *An Workspace senden*) bietet jeden Workspace (der, auf dem es liegt, mit
  Haken), **Neuer Workspace** und **Alle Workspaces**, und
  **Workspace → Extension-Panel hinzufügen** (auch im Rechtsklick-Menü des Tabs)
  holt ein Panel in einen Workspace - auch das **Agent**-Dock, das dort
  wie ein Extension-Panel ein Pane wird (**Strg+Umschalt+K** holt seinen
  Workspace nach vorn). Dort ist es ein Pane: es erscheint
  nur mit seinem Workspace, geht mit, wenn der Workspace abgelöst wird,
  lässt sich an der Titelleiste auf ein anderes Pane ziehen und nimmt
  gezogene Panes an, wird über den Splitter in der Größe geändert und von
  **Pane-Größen ausgleichen** mit ausgeglichen. Sein [x] nimmt es aus dem
  Workspace; über das **Extensions**-Menü wieder eingeblendet, kommt es
  an seinen Platz zurück. Schließt der Workspace, parkt er seine Panels
  auf All Workspaces (ausgeblendet, mit ihrem Zustand); wird die
  Extension ausgeschaltet, gehen ihre Panels heraus, eingeschaltet kommen
  sie zurück.
- **Nur auf Workspace zeigen** lässt ein Dock ein Dock bleiben, bindet es
  aber an einen Workspace - jedes Dock: Agent, Log, Übertragungen, Terminal,
  Console, Scripts, Bookmarks und Analysis ebenso wie die Extension-Panels
  im Dock-Bereich (Media Player, Bluetooth …). Die Stecknadel in seiner
  Titelleiste (oder ein Rechtsklick darauf) bietet **Alle Workspaces**,
  jeden Workspace und **Neuer Workspace**; die Nadel leuchtet, solange das
  Dock gebunden ist, und ihr Tooltip nennt den Workspace. Ein gebundenes
  Dock behält seinen Platz, erscheint aber nur, solange sein Workspace im
  Fenster ist (ein abgelöster Workspace: solange er der aktuelle ist);
  wird es auf einem anderen Workspace geöffnet (Ansicht → Panels, sein
  Toolbar-Knopf), kommt sein Workspace nach vorn. Auf seinem Workspace
  geschlossen bleibt es zu; schließt der Workspace, gilt es wieder für
  alle. Die Bindung kommt beim nächsten Start wieder.
- **Workspace schließen** schließt ihn mit seinen Panes (nach Rückfrage);
  schließt das letzte Pane eines Workspace, geht der Workspace mit. Ein
  Workspace bleibt immer.
- **Pane-Größen ausgleichen** (**Strg+Umschalt+E**) gleicht den Workspace auf
  dem Bildschirm aus — auch einen, der nur Terminals oder
  Extension-Panels hält.
- Ein Layout-Preset (**Ansicht → Layout-Preset**) ersetzt nur die Panes
  des aktuellen Workspace.
- Alle Workspaces — Namen, Reihenfolge, der aktuelle, Layouts mit ihren
  Terminals und Ordnern, welche abgelöst sind und wo ihre Fenster stehen
  — kommen beim nächsten Start zurück (siehe unten).

### Das Layout kommt beim Start zurück

Beim Beenden speichert axross das Layout in `session.json`; der
nächste Start baut es automatisch wieder auf:

- den Splitter-Baum mit seinen Größen, die Window-Geometry, das
  Dock-Layout (welche Docks offen sind und wo, und welche Tabs axross
  selbst gemacht hat) und das Theme;
- lokale Panes auf ihren Ordnern — ein inzwischen gelöschter Ordner
  öffnet stattdessen den Home-Ordner, ohne Dialog;
- lokale Terminal-Panes als frische Shell an derselben Stelle, im
  Ordner, in dem die alte Shell stand (Home, wenn er fehlt).

**Ein Start verbindet nie.** Ein Pane oder Terminal eines gespeicherten
Connection-Profils kommt als Placeholder zurück, *Not connected —
&lt;Profil&gt;*, mit einem **Neu verbinden**-Button. Bei einem File-Pane
verbindet Reconnect genau wie das Öffnen des Profils über die Schnellverbindung
(Passwort-Prompt, Host-Key-Prüfung) und setzt das Pane an die Stelle
des Placeholders, auf seinen gespeicherten Ordner. Bei einem Terminal
öffnet es das Terminal des Profils wie ein Layout-Preset (gespeichertes
Passwort, kein Prompt). Der Restore führt keine Scripts und keine
Extensions aus, und der Paranoid Security Mode bleibt unberührt.

*Beim Start das Layout der letzten Session wiederherstellen* (**Bearbeiten → Einstellungen… →
Allgemein**, standardmäßig an) schaltet das ab;
die Wahl landet sofort in `session.json`, und ein Start zeigt dann das
Default-Layout mit einem Pane. Eine fehlende, unlesbare oder ungültige
`session.json` startet ebenfalls mit dem Default-Layout; der Grund steht
im Log. **Datei → Letzte Session wiederherstellen** (**Strg+Umschalt+R**) baut das
gespeicherte Layout weiterhin auf Wunsch auf, und dort verbinden
Remote-Panes.

### Docks: die rechte Spalte und automatische Tabs

- Die rechte Dock-Spalte (Analysis, Agent, abgelöste Konversationen,
  Extension-Panels wie der Media Player) reicht bis zur Unterkante des
  Fensters; der untere Bereich (Übertragungen, Terminal, Log, Console,
  Scripts) ist so breit wie die Panes und die Bookmarks-Spalte. Die
  Bookmarks-Spalte endet über dem unteren Bereich, so bleiben dessen
  Tabellen und Terminal-Zeilen breit.
- Brauchen die Docks einer Spalte mehr Höhe, als die Spalte hat - jedes
  einen brauchbaren Teil seines Inhalts (200 px, oder alles, wenn es
  weniger braucht), nicht nur seine Titelleiste -, werden benachbarte
  Docks zu Tabs zusammengelegt, bis sie passen; die Tabs stehen unten
  an der Gruppe. Nichts überlappt, auch wenn ein Window Manager das
  Fenster kleiner hält (Tiling, maximiert).
- Ist wieder Platz (größeres Fenster, ein Dock geschlossen, gefloatet
  oder weggezogen), stehen die Docks, die axross getabbt hat, wieder
  untereinander, wo sie waren. Docks, die du selbst getabbt hast,
  bleiben Tabs, und ein Dock, das du aus einer automatischen Tab-Gruppe
  ziehst, wird dafür nicht wieder getabbt - nur wenn die Spalte nicht
  einmal die Titelleisten der Docks fassen könnte.
- Solange eine Maustaste gedrückt ist (ein Separator oder ein Dock wird
  gezogen), bewegt sich nichts; geprüft wird, wenn das Resize zur Ruhe
  gekommen ist. Panels, die auf einem Workspace liegen, sind dort Panes
  und gehören zu keiner Spalte.
- Welche Tabs axross gemacht hat, steht mit dem Dock-Layout in
  `session.json`; nach einem Neustart gehen sie bei genug Platz wieder
  auseinander.

## Übertragungen

Bevor eine Kopie oder ein Verschieben (F5, F6, Drag & Drop) in die
Warteschlange kommt, prüft axross das Ziel im Hintergrund und fragt bei
jedem Namen, den es dort schon gibt: *Überschreiben*, *Überschreiben,
wenn neuer*, *Überspringen*, *Umbenennen* (`name (1).ext`), jeweils
wahlweise für alle weiteren Konflikte, oder *Abbrechen* (nichts wird
kopiert). Ordner werden zusammengeführt; gefragt wird nach den Namen
darin. Ein übersprungenes Verschieben behält seine Quelle, und eine
Datei, die nach der Rückfrage am Ziel auftaucht, lässt ihren Job
scheitern, statt überschrieben zu werden. Ein Verschieben entfernt seine
Quelle nur, wenn sie noch die Größe hat, die sie vor dem Kopieren hatte;
eine, die sich inzwischen geändert hat (ein Log, in das noch geschrieben
wird), lässt ihren Job scheitern und bleibt erhalten.

**Ausschneiden und Einfügen.** *Ausschneiden* (Strg+X oder Rechtsklick)
merkt sich nur die ausgewählten Einträge – nichts wird entfernt; solange
sie auf das Einfügen warten, sind sie abgeblendet. *Einfügen* (Strg+V
oder Rechtsklick, auch auf freier Fläche) in einem beliebigen Pane –
anderer Ordner, andere Verbindung – verschiebt sie über die
Übertragungen in dessen Ordner: mit derselben Prüfung auf vorhandene
Namen wie bei F5 / F6, und jede Quelle wird erst entfernt, wenn ihre
eigene Kopie fertig und geprüft ist; eine fehlgeschlagene, abgebrochene
oder unvollständige Übertragung lässt sie stehen. Ausschneiden ohne
Einfügen entfernt nichts: erneutes Ausschneiden ersetzt die Auswahl,
Esc in ihrem Pane verwirft sie, ebenso das Schließen des Panes oder ein
Wechsel seiner Verbindung. Einfügen in den Ordner, aus dem die Einträge
stammen, tut nichts; ein Ordner in sich selbst wird abgelehnt. Sobald
das Verschieben in der Warteschlange steht, ist das Ausschneiden
erledigt.

Jede Kopie und jedes Verschieben zwischen zwei Panes kommt in die
Warteschlange der Übertragungen. Das untere Dock *Übertragungen* zeigt
Fortschritt, Datenrate und Restzeit. Übertragungen laufen in eigenen
Threads und überstehen einen abgelehnten Dialog oder ein geschlossenes
Pane. Wer axross beendet, während Übertragungen laufen oder warten, wird
vorher gefragt (Beenden bricht sie ab); ein Ordner, der beim Durchlaufen
nicht lesbar ist, wird zu einer fehlgeschlagenen Zeile der Liste, und
ein Durchlauf, der mittendrin abbricht, sagt, wie viel eingereiht wurde.

- **Atomares Schreiben.** Jeder Schreibvorgang geht in eine versteckte
  temporäre Datei daneben (`.<name>.part-<job>-<fingerprint>`), die am
  Ende umbenannt wird. Auf S3 / Azure / Dropbox / GDrive / OneDrive /
  IMAP / Rsync ist schon der Upload selbst atomar; sonst macht erst das
  Umbenennen die Datei gültig.
- **Fortsetzen.** Fehlgeschlagene Übertragungen lassen sich fortsetzen;
  die schon übertragenen Bytes am Ziel werden weiterverwendet. Eine
  Übertragung, die an einem vollen Ziel scheitert, löscht ihre
  Teildatei.
- **Wiederholen.** *Fehlgeschlagene wiederholen* startet jede
  fehlgeschlagene Übertragung der Warteschlange erneut, jede genau
  einmal.
- **Alle abbrechen** stoppt auch eine Kopie oder ein Verschieben, dessen
  Ordner noch durchlaufen wird: keine seiner Dateien kommt in die
  Warteschlange.
- **Verschieben auf einem Server.** Ein Verschieben, dessen Quelle und
  Ziel auf derselben Verbindung liegen (Ablegen auf einem Ordner im
  selben Pane, F6 zwischen zwei Panes einer Verbindung, Ausschneiden und
  Einfügen), benennt jede Datei auf dem Server um (SFTP RENAME, FTP
  RNFR/RNTO, WebDAV MOVE, SMB, serverseitige S3-Kopie): kein Byte läuft
  durch axross. Ein Name, den die Antworten auf einen Konflikt
  überschreiben lassen, ein Link oder ein Umbenennen, das der Server
  ablehnt, geht stattdessen über die normale Kopie.
- **Änderungszeiten.** Eine Kopie behält die Änderungszeit der Quelle
  auf lokalen Platten, SFTP (ganze Sekunden), SMB und FTP-Servern, die
  `MFMT` anbieten. WebDAV und S3 können sie nicht setzen: Die Kopie dort
  trägt die Upload-Zeit, die *Panes vergleichen* und *Überschreiben, wenn
  neuer* als die neuere lesen. *Überschreiben, wenn neuer* vergleicht
  ganze Sekunden.
- **Was passiert ist.** Ist eine Kopie oder ein Verschieben fertig, fasst
  die Statusleiste zusammen: „2 kopiert, 1 übersprungen (Ziel
  behalten)“, „3 übersprungen (Ziele nicht älter)“, Fehler mitgezählt.
  Der Gesamtbalken des Docks endet nur dann auf *Fertig*, wenn jeder Job
  des Durchgangs gut ausging, sonst rot auf „N fehlgeschlagen“ /
  „N abgebrochen“.
- **Widerrufen.** *Bearbeiten → Letzte Aktion widerrufen* (`Strg+Z`)
  macht das neueste Verschieben oder *In den Papierkorb verschieben*
  rückgängig, dessen Verbindung offen ist, und zwar ganz: ein F5 / F6 /
  Ablegen / Einfügen oder ein *In den Papierkorb verschieben* einer
  Auswahl ist eine Aktion und eine Frage. Ein verschobener Ordner kommt
  mit seinen Ordnern zurück (die das Verschieben angelegt hat, werden
  entfernt, wenn sie leer sind, die Quellordner neu angelegt) und mit
  seinen Tags; ein Name, der wieder da ist, stoppt das Widerrufen, bevor
  sich etwas bewegt, und was nicht zurückkam, bleibt für das nächste
  `Strg+Z`. Eine Kopie lässt sich nicht rückgängig machen.
- **Produktions-Verbindungen.** Jeder Schreibvorgang, der auf einer als
  *Produktion* markierten Verbindung überschreibt oder löscht, wartet
  zuerst den Countdown ab: F5 / F6 / Drag & Drop / Einfügen mit
  Überschreiben, ein Verschieben von ihr weg oder auf sie, und *Panes
  vergleichen* → *Abgleich* für jede Seite, die der Abgleich
  überschreibt.
- **Prüfen.** Das Job-Flag `verify_checksum` berechnet die Prüfsumme des
  Ziels nach dem Upload neu und verwirft das Ergebnis, wenn sie nicht
  passt.
- **Parallele Übertragungen.** *Bearbeiten → Einstellungen… → Dateien &
  Panes → Parallele Übertragungen* (1–8, vorgegeben 1) lässt mehrere Jobs
  nebeneinander laufen, gestartet in der Reihenfolge der Warteschlange;
  das überdeckt die Wartezeit vieler kleiner Dateien auf einer langsamen
  Leitung. Eine Verbindung, die keine zwei Jobs zugleich tragen kann (SCP
  und jedes andere Protokoll außer lokalen Dateien, RAM-Workspaces,
  SFTP, SMB, FTP, WebDAV und S3), arbeitet ihre Jobs weiter einzeln ab,
  und zwei Jobs schreiben nie zugleich dasselbe Ziel. Eine Änderung gilt
  für die Jobs, die danach starten. Jeder SFTP-Job läuft auf einem
  eigenen SSH-Kanal, und Server begrenzen die Kanäle pro Verbindung
  (OpenSSH `MaxSessions`, vorgegeben 10). Jede FTP-Übertragung läuft auf
  einer eigenen Steuerverbindung; Server begrenzen oft die Verbindungen
  pro Benutzer oder Adresse, und eine FTP-Verbindung, deren Server eine
  zweite Anmeldung ablehnt, arbeitet ihre Jobs einzeln ab.

## Backend-übergreifender Feature-Layer

Diese Module funktionieren auf **jedem** Backend – auch dort, wo das
native Protokoll sie nicht kennt.

| Modul | Was es liefert |
|---|---|
| `core.atomic_io` | `atomic_write(backend, path, data)` – auf S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync nativ atomar; überall sonst erst eine temporäre Datei, dann Umbenennen. |
| `core.atomic_recovery` | Räumt nach einem Absturz verwaiste `.tmp-*.tmp`-Dateien auf: beim Navigieren eines Panes werden Reste entfernt, die älter als 1 h sind. Das alte Präfix `.axross-atomic-*.tmp` wird weiter erkannt. |
| `core.server_ops` | `server_side_copy` / `server_side_move`, mit automatischem Rückgriff auf `open_read` + `open_write`, wenn das Backend selbst nicht kopieren kann. |
| `core.watch` | API zum Beobachten von Dateien: nativ inotify auf LocalFS (mit watchdog), sonst Polling. Ein- und ausschaltbar in der Pfadleiste. |
| `core.trash` | Ein Papierkorb für jedes Backend: `trash` / `list_trash` / `restore` / `empty_trash`. Die Metadaten liegen in einer Begleitdatei je Eintrag, es gibt kein zentrales Verzeichnis. |
| `core.xlink` | Protokollübergreifende Symlinks über `.axlink`-Dateien, die als JSON auf ihr Ziel zeigen. |
| `core.encrypted_overlay` | Verschlüsselung gespeicherter Dateien mit AES-256-GCM, Schlüssel per PBKDF2-HMAC-SHA256 mit 200 k Iterationen. |
| `core.cas` | Inhaltsadressierte Schicht: SQLite-Index `(backend, path) → checksum`, Erkennung von Duplikaten, `ax-cas://<algo>:<hex>`-URLs. |
| `core.snapshot_browser` | Eine einheitliche Versionshistorie über S3, Dropbox, GDrive, OneDrive und Azure Blob. |
| `core.metadata_index` | Offline-Suche in SQLite nach Name / Endung / Größe / Änderungszeit. Eine Datei: `$AXROSS_METADATA_DB`, sonst `$XDG_DATA_HOME/axross/metadata.sqlite`, sonst `~/.local/share/axross/metadata.sqlite` (ein Index, der schon dort liegt, bleibt in Gebrauch). Gefüllt nur über *Aktiven Ordner indizieren…*, nicht durchs Browsen – siehe *Der Offline-Index* unter *Dateien finden*. |
| `core.file_search` | Die Suche von *Dateien finden*: Name / Typ / Inhalt / Größe / Datum in Ordnern jedes Backends, auch in Archiven, mit laufenden Ergebnissen und abbrechbar; lokal mit `fd` / `rg`, wenn installiert. |
| `core.file_categories` | Die Typ-Vorgaben von *Dateien finden* (Bilder, Datenträger- & VM-Images, Krypto-Wallets, Schlüssel & Zertifikate, …) nach Name, Ordner und Merkmalen im Inhalt. |
| `core.previews` | Lokale Bild-Thumbnails mit strenger MIME-Allowlist, Größengrenzen und einer Sperre für zu große Qt-Speicheranforderungen. F3 / Doppelklick. |
| `core.archive` | Sicheres Entpacken von zip / tar / 7z und einzelnen komprimierten Dateien (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .tar.zst .tzst .7z .gz .bz2 .xz .zst`). Schutz vor Zip-Slip, Archivbomben und falschen Größenangaben; Symlink- und Hardlink-Einträge (tar, und ZIP-Symlinks) werden ausgelassen – nie angelegt oder verfolgt –, und das Ergebnis nennt sie; `.7z` braucht das Extra `[archive]`, zstd Python 3.14 oder dieses Extra. |
| `core.packer` | Rechtsklick → **Packen**: zip, tar.gz / .zst / .xz / .bz2, 7z (wahlweise AES-256 mit verschlüsselten Dateinamen) oder eine einzelne Datei als .gz / .zst / .xz / .bz2 – von jedem Backend, ohne zu überschreiben (`name (2).zip`) und ohne je ein halb geschriebenes Archiv zu hinterlassen. |
| `core.elevated_io` | Lokales Lesen von `/etc/shadow` & Co. über `pkexec` – axross hält selbst nie Root-Rechte. Eintrag *Als root öffnen…* im Kontextmenü. |
| `core.fuse_mount` | Jedes Backend als FUSE-Mount. Standardmäßig read-only; `writeable=True` erlaubt create / write / unlink / mkdir / rename. Optionales Extra `[fuse]`. |
| `core.mcp_server` | MCP-Server mit JSON-RPC über stdio, der das eingestellte Backend als Tools anbietet. `--mcp-write` ergänzt Tools, die Dateien ändern, beschränkt auf einen Root, aus dem kein Pfad hinausführt. |

## Rechtsklick-Aktionen

Das Rechtsklick-Menü ist eine Spalte. **Öffnen** steht oben (ein Ordner
öffnet sich im Pane, eine Datei in ihrem Viewer, wie mit `Enter`), dann
*Öffnen mit ▸* (als Text, als Hex, als root, Ausgewählte Medien ansehen…,
Archiv-Preview) und bei einem Archiv *Entpacken…*; dann *Kopieren*
(`Strg+C`), *Ausschneiden*, *Einfügen*, *Umbenennen*; *Ins Ziel-Pane
kopieren*, *Ins Ziel-Pane verschieben*, *Packen ▸*; *In den Papierkorb
verschieben* (`Entf`) und *Endgültig löschen* (`Umschalt+Entf`); *Neuer
Ordner*, *Neue Datei…*; *Eigenschaften…*, *Analysieren ▸* (Dateityp,
Disk-Image, Prüfsumme, Versionen, Größe, sift, Duplicate Finder, In diesem
Ordner suchen) und *Weitere ▸*: *Aktualisieren*, Ansicht, Medien ansehen…,
Bookmark, Papierkorb anzeigen…, *Pfad kopieren*, *Links ▸* (Link-Ziel, neuer
Symlink / Hardlink / XLink), *Metadaten ▸*, *Tags ▸*, Terminals, FUSE,
Berechtigungen…, Ver- und Entschlüsseln, der Agent und am Ende *An
Workspace senden ▸* für das Pane selbst. Die oberste Ebene bleibt auch auf
einem Bildschirm mit 1024x600 eine Spalte. Mehr als drei Einträge von
Extensions kommen in *Extensions ▸*. Die Tabelle nennt jeden Eintrag mit
seiner Beschriftung.

| Aktion | Aufruf | Was passiert |
|---|---|---|
| Disk-Image… | Rechtsklick (eine `.img .raw .dd .iso .qcow2 .vdi .vmdk .vhd(x) .e01 …`-Datei) | Container (qcow2, VDI, VMDK, VHD/VHDX, E01), Partitionstabelle (MBR mit logischen Partitionen, GPT) sowie Dateisystem und Label jedes Volumes, in reinem Python über jedes Backend gelesen. Ein lokales Image mountet ein Volume über ein Loop-Device genau über dessen Bytes: zuerst `udisksctl` ohne Abfrage (wo polkit es erlaubt), dann `sudo`, dann `pkexec`, zuletzt `udisksctl` mit polkit-Abfrage. Das sudo-Passwort wird einmal gefragt und im Speicher gehalten, solange axross läuft (nie auf Platte, nie auf einer Kommandozeile); *Das sudo-Passwort merken* (*Bearbeiten → Einstellungen… → Sicherheit*) schaltet das ab, dann gilt wieder `udisksctl` (polkit fragt), `pkexec`, `sudo` mit Abfrage jedes Mal. Im paranoiden Sicherheitsmodus wird es nie gemerkt. sudo, pkexec und udisksctl laufen nur aus root-eigenen Systemordnern, nie aus `$PATH`. **Nur lesend**, außer *Schreiben erlauben* ist angehakt und bestätigt. Der Mount-Ordner öffnet sich in einem neuen Pane; *Unmounten* gibt das Loop-Device zurück. Von axross angelegte Mounts bleiben über Neustarts bekannt (`~/.config/axross/mounts.json`, nur noch gemountete kommen zurück). *Dateityp erkennen…* erkennt Disk-Images auch am Inhalt (GPT, MBR, virtuelle Disks) und bietet für so eine Zeile *Disk-Image…* an, egal wie die Datei heißt. qcow2 / dynamisches VDI / VMDK erst konvertieren (`qemu-img convert -O raw`); ein festes VDI mountet direkt. |
| Tags ▸ | Rechtsklick auf eine Auswahl | Einen farbigen Tag anhaken (Wichtig und Später ansehen gibt es; Neuer Tag… legt einen an) für jede gewählte Datei auf jedem Backend; Punkte in der Namensspalte, die Tags im Tooltip; `tag:<name>` im Filterfeld zeigt nur diese Dateien; *Ansicht → Getaggte Dateien…* listet die Dateien jedes Tags und springt hin. Gespeichert in `~/.config/axross/tags.json`. |
| Neuer Ordner | Rechtsklick | `backend.mkdir(path)` auf jedem schreibfähigen Backend. |
| Neue Datei… | Rechtsklick | Leere Datei (0 Byte) über `backend.open_write(path).write(b"")`. |
| Neuer Symlink… | Rechtsklick | Zwei Abfragen. Nur sichtbar auf Backends mit `supports_symlinks=True`. |
| Neuer Hardlink… | Rechtsklick | Ebenso; ein Hardlink über Gerätegrenzen hinweg endet mit `OSError(EXDEV)`. |
| Im Index suchen | `Strg+Umschalt+F` | Sucht im Offline-Index nach Name / Endung / Größe. |
| In diesem Ordner suchen… | Rechtsklick (auch auf freie Fläche) | Dateien finden mit diesem (oder dem gewählten) Ordner angehakt — siehe *Dateien finden*. |
| Größe berechnen (N Ordner) | Rechtsklick auf Ordner | Gesamtgröße, Datei- und Ordnerzahl jedes gewählten Ordners, im Hintergrund über die Verbindung gezählt (*Abbrechen* in der Statuszeile); die Ergebnistabelle sortiert, und die Größen stehen in der Spalte *Größe* des Panes, bis der Ordner neu geladen wird. **Versteckte Dateien zählen mit**: Dotfiles, versteckte Ordner und Einträge, die das Backend als versteckt markiert, werden wie jeder andere Eintrag summiert – wie bei `du` –, egal ob das Pane sie anzeigt. Ein Link zählt mit seiner eigenen Größe und wird nie verfolgt; ein Ordner, der sich nicht lesen lässt, wird im Ergebnis genannt und übersprungen. |
| Dateien in diesem Ordner identifizieren… | Rechtsklick (auch auf freie Fläche); der Button im Fenster *Dateityp erkennen* | Jede Datei direkt im Ordner (ein gewählter Ordner, sonst der angezeigte; Unterordner werden gezählt, nicht betreten; versteckte Dateien eingeschlossen) wie bei *Dateityp erkennen…* am Inhalt erkannt, im Hintergrund und über die Verbindung – also auch in Remote-Panes. Begrenzt: höchstens 2000 Dateien, 64 KiB je Datei, 15 s Zeitlimit je Lesevorgang, *Abbrechen*; `file(1)` wird nicht gefragt. Die Spalten sortieren: Name, erkannter Typ, MIME-Typ, das Urteil *Abweichung*, Größe, eine Notiz – bei einem Disk-Image Container, Partitionstabelle und Partitionszahl (`Raw disk image, MBR, 2 partitions, 4.0 MiB`; dafür höchstens 4 MiB gelesen) – und für lokale Dateien mit installiertem `sift`-Extra die Art laut sift. Eine Zeile öffnet *Disk-Image…* (Disk-Images) oder *Eigenschaften…*; Doppelklick nimmt das Passende. |
| Mit sift analysieren / Ordner mit sift analysieren | Rechtsklick (der Ordner-Eintrag auch auf freie Fläche), das Menü Aktionen, *Tools → Mit sift analysieren* | Öffnet das Dock *Analyse (sift)* (sifts Sieb-Icon, `Strg+Umschalt+I`) und erklärt die Datei dort ohne Modell. Mehrere gewählte Dateien oder ein Ordner (der gewählte, sonst der angezeigte) werden als ein Batch für das aktive LLM-Profil angeboten; *Tools → Mit sift analysieren* nimmt die Auswahl, ohne Auswahl den angezeigten Ordner. sifts eigene Ordner-Zusammenfassung (`sift --dir-summary`, ab sift 0.1.96) gehört nicht zum Dock: ein Ordner wird Datei für Datei analysiert. Ohne sift (axross-slim oder eine Installation aus dem Quellcode ohne das Extra `sift`) sagt jeder Eintrag, dass sift in axross-full oder im Extra `axross[sift]` steckt, mit Link auf *Hilfe → Funktionen…*. |
| Dateityp erkennen… | Rechtsklick (Auswahl) | Eine Zeile pro Eintrag: der echte Typ laut Inhalt (Magic Bytes über Qts MIME-Datenbank, puremagic, eine eingebaute Signaturtabelle), der MIME-Typ, was die Endung behauptet, und eine hervorgehobene *Abweichung*, wenn sie sich widersprechen, Größe, bei Text die Zeichenkodierung und die Zeilenenden. Liest höchstens 64 KiB je Datei über das Backend, außerhalb des GUI-Threads, mit 15 s Zeitlimit je Datei – ein Server, der nicht antwortet, ergibt eine Zeile „timed out“. Lokale Dateien zeigen auch die Beschreibung von `file(1)`, wenn es installiert ist. Skripte: `axross.file_type(b, path)`. |
| Terminal hier öffnen | Rechtsklick (auch auf freie Fläche) | Öffnet eine Shell im Terminal-Dock im Ordner: ein gewählter Ordner, sonst der angezeigte. Lokale Panes bekommen eine lokale Shell, die in dem Ordner startet; SFTP-/SCP-Panes eine Shell auf derselben SSH-Verbindung, gefolgt von `cd -- '<ordner>'` (mit `shlex.quote` maskiert). Ausgegraut, mit dem Grund als Tooltip, bei Protokollen ohne Shell. |
| Externes Terminal hier öffnen | Rechtsklick (lokale Panes) | Startet `$TERMINAL`, sonst das erste installierte von x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, alacritty, kitty, foot, wezterm, xterm – mit dem Ordner als Arbeitsverzeichnis, eigenständig, ohne Shell dazwischen. |
| Duplicate Finder | Menü Ansicht, `Strg+Umschalt+D` | Gruppiert indizierte Dateien nach Inhalts-Hash und verschiebt überzählige Kopien in den Papierkorb – siehe *Duplicate Finder* unter *Werkzeuge*. |
| Medien ansehen… / Ausgewählte Medien ansehen… | Rechtsklick, Menü Ansicht | Bilder, PDFs und Videos des Ordners (optional rekursiv) oder der Auswahl als Übersichtsraster, Viewer zum Durchklicken oder Diashow – siehe *Editoren und Viewer*. |
| Metadaten anzeigen… / entfernen… / exportieren… | Rechtsklick | EXIF / GPS / XMP / IPTC, Office-Eigenschaften, PDF-Info, Audio-/Video-Tags der Auswahl – oder des ganzen Ordners, wenn nichts ausgewählt ist (Unterordner optional) – siehe *Datei-Metadaten*. |
| Kopieren / Ausschneiden / Einfügen | Rechtsklick (Einfügen auch auf freier Fläche), `Strg+C` / `Strg+X` / `Strg+V` | Kopieren merkt sich die Auswahl für Einfügen und legt ihre Pfade als Text für andere Programme in die Zwischenablage; Ausschneiden merkt sich die Auswahl und entfernt nichts (die Einträge sind abgeblendet); Einfügen in einem beliebigen Pane kopiert die kopierten Einträge oder verschiebt die ausgeschnittenen über die Übertragungen in dessen Ordner – siehe *Übertragungen*. Ausgeschnitten, aber nie eingefügt, bleibt alles, wo es ist. *Weitere ▸ Pfad kopieren* legt nur die Pfade in die Zwischenablage. |
| In den Papierkorb verschieben | Rechtsklick, `Entf` | Ein Papierkorb auf jeder Verbindung (ein Ordner `.axross-trash` im Home der Verbindung, er geht also überall, wo die Verbindung umbenennen kann; *Papierkorb anzeigen…* holt die Einträge zurück). Nur lesende Protokolle und solche ohne Umbenennen – Gopher, LDAP, NNTP, PJL, POP3, SLP, SVN, TFTP, WMI – haben keinen; dort fragt `Entf` stattdessen, ob endgültig gelöscht werden soll. Läuft wie *Endgültig löschen*: im Hintergrund, mit derselben zweiten Rückfrage für versteckte Einträge. |
| Endgültig löschen | Rechtsklick, `Umschalt+Entf` | Zählt zuerst abseits des GUI-Threads, was wegfällt (Ordner, Dateien, Bytes, versteckte Einträge), dann die Rückfrage – mit **Nein** als Standardknopf, `Enter` behält also die Dateien. Ein ausgewählter Ordner mit versteckten Einträgen (Dotfiles oder vom Backend als versteckt markiert) – oder einer, den die Prüfung nicht vollständig lesen konnte – braucht ein zweites OK mit *Nein* als Standard. Das Löschen läuft im Hintergrund: die Statuszeile zeigt den Fortschritt, *Abbrechen* hält beim nächsten Eintrag an – auch innerhalb eines Ordners, der lokal, per SMB, SFTP oder FTP gelöscht wird (SFTP entfernt die Dateien eines Ordners in Gruppen von 16 gleichzeitigen Anfragen und hält nach der laufenden Gruppe an); die Statuszeile sagt dann, wie viel von diesem Ordner schon weg ist (Gelöschtes bleibt gelöscht; ein Server, der einen ganzen Ordner mit einer Anfrage löscht, etwa WebDAV oder S3, löscht diesen Ordner zu Ende) – Fehler werden je Eintrag gemeldet, danach wird der Ordner neu geladen. Ein Pfad, der gerade gelöscht wird, wird abgewiesen, auch aus dem anderen Pane. |
| Papierkorb anzeigen… | Rechtsklick | Dialog zum Wiederherstellen und endgültigen Löschen. |
| Versionen anzeigen… | Rechtsklick | Versionsliste – *Version speichern unter…*, *Als aktuelle wiederherstellen*. |
| Prüfsumme anzeigen… | Rechtsklick | Die Prüfsumme, die der Server selbst liefert (S3 ETag, Drive md5, ssh sha256sum…), sonst ein Hash über die gelesenen Daten. |
| Entpacken… | Rechtsklick auf Archiv | In einen gleichnamigen Ordner daneben, abbrechbar, mit den Schutzprüfungen von `core.archive`. Nur lokale Backends. |
| Mit Passphrase verschlüsseln… / entschlüsseln… | Rechtsklick | AES-256-GCM. |
| Als root öffnen… | Rechtsklick | Nur lokal; läuft über `pkexec`. Ausgeblendet, wenn polkit/pkexec fehlen. |
| XLink erstellen… | Rechtsklick | Protokollübergreifende Verweisdatei. |
| Als FUSE mounten (read-only / read-write)… | Rechtsklick | Zwei Menüeinträge, damit der Mount-Modus von vornherein sichtbar ist. Solange gemountet, heißt der Eintrag *FUSE unmounten*. |
| Mehrere umbenennen… | Rechtsklick (Mehrfachauswahl) | Suchen und Ersetzen oder regulärer Ausdruck, mit Live-Vorschau und atomarem Umbenennen. |
| Berechtigungen… | Rechtsklick | chmod-Dialog mit einem Raster aus Kästchen und oktaler Eingabe. |

## Dateien finden

**Bearbeiten → Dateien finden…** (`Alt+F7` oder `Strg+Alt+F`; im Rechtsklick eines
Panes *In diesem Ordner suchen…*) durchsucht Ordner auf allen offenen
Verbindungen gleichzeitig — lokal, SFTP, SMB, S3, … — und auf Wunsch den
Offline-Index. `Strg+F` bleibt der Live-Filter des Panes.

| Feld | Was es tut |
|---|---|
| Name | Text ohne `* ? [ ]` passt irgendwo im Namen (`report` findet `Q3-report.pdf`); ein Muster (`*.jpg`, `IMG_????.*`) auf den ganzen Namen. Groß-/Kleinschreibung zählt nicht. *Regex* nimmt stattdessen einen regulären Ausdruck. |
| Contains | Text in der Datei, Zeile für Zeile, in den ersten 32 MiB jeder Datei; *Regex* und *Groß-/Kleinschreibung beachten* wie üblich. |
| Types | Eine der angehakten Vorlagen: Bilder, Videos, Audio, Dokumente, Archive, Disk- & VM-Images (dd / raw / img, ISO, qcow2, VDI, VMDK, VHD(X), E01 / AFF, DMG, LUKS…), Krypto-Wallets (Bitcoin Core / Litecoin `wallet.dat`, Electrum, Ethereum-`UTC--…`-Keystores, Exodus, Monero, MultiBit / Armory, Wasabi, Atomic, Ledger Live, MetaMask / Phantom / … Browser-Wallets), Schlüssel & Zertifikate (PEM / DER, `.p12` / `.pfx`, Java-Keystores, SSH- und PuTTY-Schlüssel, KeePass), Quellcode, E-Mail, Datenbanken. Entschieden nach Name und Ordner; bei lokalen Dateien, deren Endung nichts sagt (`blob`, `wallet.dat`, `UTC--…`), auch nach den ersten Bytes und — mit dem Extra `sift` (`axross[sift]`) — durch sift. Types benennen Datei-*Arten*: nichts sucht in Dateien nach Passwörtern oder Schlüsseln. |
| Size / Modified | `10K`, `1.5M`, `2G`; ein Zeitraum. |
| Inside archives | Sucht auch in zip, tar, tar.gz / .bz2 / .xz / .zst, einzelnen .gz / .bz2 / .xz / .zst-Dateien und darin verschachtelten Archiven (3 Ebenen); in 7z und rar nach Member-Namen. Ein Treffer heißt `archive.zip!/ordner/datei.txt`. Begrenzt: 10 000 Member und 1 GiB entpackt pro Archiv, 64 MiB pro verschachteltem Archiv, das 100:1-Zip-Bomb-Verhältnis des Entpackens; ein entferntes Archiv wird zuerst (höchstens 256 MiB) in eine private Temp-Datei kopiert. |
| Tag | Nur Dateien mit dem gewählten Tag (Rechtsklick → *Tags*); ein getaggtes Archiv gilt für seine Member. Ein Smart Folder behält den Tag. Offline-Index-Treffer werden ebenso gefiltert. |
| Hidden files, Skip .git / node_modules / caches, depth | Was der Durchlauf einschließt. Symlink-Ordnern wird nie gefolgt. |
| Look in | Der Ordner jedes offenen Panes (der aktive angehakt), *Ordner hinzufügen…* und *Auch den Offline-Index durchsuchen* (Namen, Größen, Daten; kein Inhalt). |

Treffer erscheinen, während die Suche läuft; *Stopp* oder Schließen des
Fensters bricht sie ab. Die Spalten sortieren; Doppelklick oder `Enter`
zeigt die Datei markiert in einem Pane (ein Archiv-Member öffnet die
Archiv-Ansicht), das Kontextmenü hat *Öffnen*, *Im Pane zeigen*, *Pfad kopieren*
und *An den Agenten senden*. Würden der Filter des Panes oder die Einstellung für
versteckte Dateien den gezeigten Eintrag verbergen, leert Reveal den
Filter oder blendet versteckte Einträge in diesem Ordner ein (bis das
Pane in einen anderen wechselt), und die Statuszeile sagt es.

In einem lokalen Ordner listet die Suche Dateien mit
[`fd`](https://github.com/sharkdp/fd) und durchsucht ihren Inhalt mit
[`ripgrep`](https://github.com/BurntSushi/ripgrep) (`rg`), wenn sie
installiert sind (im `PATH`, `fdfind` unter Debian / Ubuntu, oder `bin/`
neben einem gefrorenen Build); ohne sie liefert ein eingebauter Walker
dieselben Ergebnisse, nur langsamer. Entfernte Ordner werden über die
Verbindung durchlaufen.

**Als Smart Folder speichern…** legt die Suche bei den Bookmarks ab (Sidebar und
Bookmarks-Menü, mit Lupen-Icon); ein Klick führt sie erneut auf den
Ordnern aus, deren Verbindung offen ist. Gespeichert wird sie in
`bookmarks.json` bei den anderen Bookmarks.

**Bearbeiten → Aktiven Ordner indizieren…** trägt Namen, Größen und Daten unterhalb
des Ordners des aktiven Panes in den Offline-Index ein — nur so wird er
gefüllt. *Ansicht → Im Index suchen…* (`Strg+Umschalt+F`) durchsucht ihn; das
Fenster zeigt die Index-Datei.

### Der Offline-Index

- **Was er speichert.** Eine SQLite-Datei mit einer Zeile pro Datei und
  Ordner: die Verbindung, der volle Pfad, Name, Größe, Ordner oder nicht,
  Endung, Änderungszeit und wann indiziert wurde. Kein Dateiinhalt und
  keine Prüfsummen — die liegen im Duplikat-Index (`cas.sqlite`, daneben).
- **Wo.** `$AXROSS_METADATA_DB`; sonst `$XDG_DATA_HOME/axross/metadata.sqlite`,
  wenn `XDG_DATA_HOME` ein absoluter Pfad ist; sonst
  `~/.local/share/axross/metadata.sqlite`. Ein Index am alten Ort bleibt in
  Gebrauch, solange es am neuen keinen gibt — `XDG_DATA_HOME` zu setzen
  verwaist also nichts. `cas.sqlite` folgt denselben Regeln
  (`$AXROSS_CAS_DB`). *Bearbeiten → Einstellungen… → Suche* zeigt beide Pfade.
- **Wie er gefüllt und aktualisiert wird.** *Bearbeiten → Aktiven Ordner indizieren…*
  (oder *Aktuelles Pane indizieren…* in *Im Index suchen*) durchläuft den Ordner des
  aktiven Panes rekursiv über seine Verbindung — jedes Backend, versteckte
  Einträge eingeschlossen, höchstens 50 Ebenen und 1 000 000 Einträge pro
  Lauf, in Paketen zu 500 geschrieben, abbrechbar (was indiziert ist,
  bleibt). Browsen indiziert nie. Denselben Ordner erneut zu indizieren
  aktualisiert seine Zeilen und entfernt die Zeilen inzwischen gelöschter
  Dateien — nur nach einem vollständigen Lauf: ein abgebrochener oder einer,
  der an die Grenze der Einträge stieß, entfernt nichts, und Zeilen unter
  einem Ordner, dessen Auflistung scheiterte, bleiben. Das MCP-Tool
  `index_build` fügt nur hinzu; mit `prune` fragt es zusätzlich das Backend
  nach jedem indizierten Pfad unter dem Ordner und entfernt die Zeilen,
  deren Datei fehlt.
- **Wie er durchsucht wird.** Teilstring im Namen (ohne Groß/Klein in
  jeder Schrift: „ärger“ findet `Ärger.txt`, „strasse“ findet `Straße.pdf` -
  auch im MCP-Werkzeug `search`), Endung, Größen- und Zeitraum, eine
  Verbindung. Endung, Größe und Datum nutzen SQLite-Indizes; ein
  Namens-Teilstring (`LIKE '%…%'`) kann keinen nutzen und liest jede Zeile.
  Die Suche läuft im Hintergrund, das Fenster listet die ersten 5000
  Treffer (und sagt, wenn es mehr gibt).
- **Wie schnell — gemessen** auf dem Entwicklungsrechner mit `/usr`
  (290 872 Einträge, lokale Platte, Rechner unter anderer Last): erster Lauf
  125 s (etwa 2 300 Einträge/s), zweiter Lauf über denselben Baum 53 s,
  Index-Datei 98 MiB; eine Namenssuche 0,4–1,2 s (jede Zeile wird gelesen;
  viele Treffer dauern länger), eine Endungssuche 37 ms. Gut für „wo war
  diese Datei“ über Verbindungen, die gerade offline sind; keine
  Inhaltssuche (das ist *Dateien finden → Enthält*, live).

### Dateien finden und sift

sift (das optionale Extra `sift`) ist ein Datei-*Analysierer*, keine
Suchmaschine: es baut keinen Index und hat keine Suche — seine
Kommandozeile und API fassen Dateien zusammen, und sein einziger Speicher
ist ein Cache dieser Zusammenfassungen, nach dem Inhalts-Hash der Datei.
Ordner durchsuchen, nach Art und in Archiven, ist axross' eigenes Dateien
finden (`core.file_search`, `core.file_categories`, `core.archive`).

- **Wofür Dateien finden sift nutzt.** Mit installiertem Extra fragt der Filter
  *Typen* `sift.detect` nach lokalen Dateien, deren Name nichts sagt (keine
  Endung, die eine Vorlage beansprucht), und ordnet die erkannte Art —
  Bild, PDF, DOCX, Archiv, SQLite, E-Mail, Quellcode, … — einer Vorlage zu.
  Entfernte Dateien und Archiv-Member werden nur nach Name und Ordner
  eingeordnet. Es gibt keinen Schalter: Dateien finden nutzt sift, wenn es da ist.
- **In Archiven.** sift listet die Member eines Archivs in seiner
  Zusammenfassung (das Analysis-Dock), durchsucht sie aber nicht. *Dateien
  finden → In Archiven* tut es: zip, tar.*, Einzeldatei-Kompressoren und
  darin verschachtelte Archive (3 Ebenen), 7z und rar nach Member-Namen.
- **Wo sifts Optionen und Funktionen sind.** *Ansicht → Panels → Analyse (sift)*
  (`Strg+Umschalt+I`; Rechtsklick → *Mit sift analysieren*) erklärt die gewählte
  Datei: ohne Modell automatisch, mit dem aktiven LLM-Profil über *Mit LLM analysieren*. Der Knopf *LLM…* des Docks öffnet *Bearbeiten → Einstellungen… → LLM-
  Profile*, wo die Modell-Server eingestellt werden; *Bearbeiten → Einstellungen… →
  Analyse (sift)* hält sifts eigene Optionen (automatische Analyse,
  Lese-Limit, Zeitbudget, Vision, Kontext, Tags, Kategorien, den Cache) und
  das Profil, das die Analyse nutzt. *Hilfe → Funktionen…* zeigt, ob das Extra
  sift installiert ist, und bietet die Installation an
  (`pip install axross[sift]`; ein gefrorener Build bietet stattdessen den
  axross-full-Download an). *Dateien in diesem Ordner identifizieren…* zeigt sifts
  Art lokaler Dateien als eigene Spalte.

## Pfadleiste

- **Auto-Refresh ◉** abonniert das Pane auf `core.watch`; debounced
  Refresh bei Backend-Änderungen.
- **Live-Filter** in der Pfadleiste filtert die Liste in Echtzeit.
  **Strg+F** springt ins Filterfeld; **Esc** dort löscht den Filter und
  kehrt zur Liste zurück. Esc in der Liste stoppt zuerst einen laufenden
  Load, löscht dann einen aktiven Filter, dann die Auswahl, dann einen
  wartenden Cut dieses Panes.
- **Bookmarks** als linkes Dock; F8 setzt Bookmark, F12 toggelt das
  Dock. Ordner, die aus einem Pane ins Dock gezogen werden (freie
  Fläche, Gruppe oder zwischen zwei Einträge), werden dort zu Bookmarks,
  Remote-Ordner mit ihrem Connection-Profile. Dateien und Ordner, die
  *auf* ein Bookmark fallen, werden in dessen Ordner verschoben (Strg
  kopiert), mit derselben Prüfung auf vorhandene Namen wie F5 / F6;
  ein fehlender Ordner oder ein Remote, das nicht antwortet, wird
  gemeldet und nichts eingereiht, ein Remote-Bookmark ohne offene
  Connection verbindet zuerst und überträgt dann.
- **Terminal-Bookmarks** öffnen eine Shell statt eines Ordners: eine
  lokale Shell, eine auf einem SSH-Profile (SFTP/SCP) oder eine auf einem
  bloßen Host — *SSH-Host (ohne Profil)*: Host oder IP-Adresse, Port (22),
  User, optional eine Key-Datei —, optional mit Arbeitsverzeichnis, in
  das gewechselt wird. Angelegt über den ☆-Button eines Terminal-Panes
  (*Bookmark für dieses Terminal*) oder *Neues Terminal-Bookmark…* im
  Rechtsklickmenü der Sidebar; ein Klick öffnet ein Terminal-Pane neben
  dem aktiven Pane. Ein Bookmark enthält nie ein Credential: ein
  Profile-Bookmark nennt das Profile; ein Host-Bookmark verbindet wie
  die Schnellverbindung — im Hintergrund, fragt bei unbekanntem Host-Key, ob er
  vertraut werden soll (known_hosts, nie stillschweigend), nimmt die
  Key-Datei oder einen laufenden ssh-agent, fragt das Passwort, wenn das
  nicht reicht, und die Passphrase eines verschlüsselten Keys; nichts
  Eingetippte wird gespeichert, der Proxy aus *Einstellungen → Netzwerk & Proxy*
  gilt. Ein fehlendes Profile, eines ohne Shell oder ein Host, der kein
  Hostname ist, wird gemeldet, und nichts öffnet sich. Die Shell eines
  Host-Bookmarks gehört nicht zum gespeicherten Layout.

## Editoren und Viewer

Jeder Viewer, Editor, Dialog und jedes Zusatzfenster hat seine eigene
Titelleiste: Symbol und Name, dann `_` (in die Dock-Leiste legen), den
Maximize-Button und [x]. Der Fenstermanager zeichnet keine eigene (das
Fenster ist rahmenlos): Ziehen an der Titelleiste verschiebt das Fenster,
ein Doppelklick maximiert oder stellt es wieder her, die schmalen Ränder
ändern die Größe. *Einstellungen → Darstellung → Eigene Titelleisten von axross*
schaltet zurück auf Titelleiste und Knöpfe des Fenstermanagers, für offene
Fenster sofort. [x] schließt das Fenster, der Button links daneben maximiert ihn über den ganzen
Bildschirm und stellt die vorherige Größe wieder her. `Strg+M` tut
dasselbe, ebenso der Maximize-Button der Titelleiste. Im Dialog
verschiebt ein Ziehen mit der linken Maustaste auf dem Rest dieser
oberen Zeile den Dialog, auf der Titelleiste eines floating Panels das
Panel - auch wo der Window Manager keine Titelleiste zeichnet
(spectrwm, andere Tiling-Setups) oder das Fenster maximiert hält
(spectrwm-Layout `fullscreen`), und unter Wayland: axross lässt es dann
vom Window Manager verschieben. Ein Doppelklick auf die Titelleiste
eines floating Panels dockt es wieder an.

- **Texteditor** (built-in) — jede zum Bearbeiten geöffnete Datei ist
  ein Tab eines Editor-Fensters (*Bearbeiten* / F4 im Pane, lokal oder
  remote): Syntax-Highlighting (Pygments; die Sprache nach Name oder
  `#!`-Zeile, in der Statusleiste änderbar), Zeilennummern, Suchen und
  Ersetzen mit Regex, Case und ganzem Wort (Strg+F / Strg+H, F3), Gehe
  zu Zeile (Strg+G), Umbruch, Zoom, Zeilenenden (LF / CRLF / CR) und
  Encoding (UTF-8, UTF-8 BOM, Latin-1, UTF-16) unter *Format*, Save /
  Save All. *Datei → Neu* (Strg+N) öffnet einen Tab ohne Datei, *Open…*
  (Strg+O) lokale Dateien (Remote-Dateien öffnet ihr Pane), *Save As…*
  (Strg+Umschalt+S) schreibt einen lokalen Tab in eine lokale Datei und
  einen Remote-Tab in einen Pfad auf seinem Backend und fragt, bevor er
  eine Datei ersetzt; Save All ist Strg+L. Enter übernimmt die
  Einrückung der Zeile, nach `:` (Python, YAML) oder `{`
  (Klammer-Sprachen) eine Ebene mehr. *Tools → Text-Editor* öffnet das
  Fenster ohne Datei. Ein Save behält das Zeilenende jeder unberührten Zeile, ein
  BOM und geschützte Leerzeichen, schreibt atomar und fragt nach, wenn
  die Datei seit dem Öffnen geändert wurde; das Pane mit dem Ordner
  wird aktualisiert. Schließen mit ungespeicherten Änderungen fragt Save
  / Discard / Cancel; der letzte geschlossene Tab schließt das Fenster,
  rechts in der Menüleiste sitzen Maximize und [x]. Geöffnet werden Dateien bis zum Open-Size-Limit
  (32 MB vorgegeben, *Bearbeiten → Einstellungen… → Dateien & Panes*).
- **Hex-Editor** — nützlich für Triage auf Remote-Dateien.
- **Bild-Viewer** — F3 / Doppelklick, MIME-Allowlist, Größen-
  kappen.
- **PDF** — F3 / Doppelklick öffnet das PDF allein im Media Viewer
  (braucht QtPdf; ohne QtPdf oder im Security-Mode `paranoid` öffnet
  stattdessen der Hex-Editor, das Log nennt den Grund).
- **Media Viewer** — *Ansicht → Medien ansehen…* oder Rechtsklick → *Medien
  ansehen…* auf den Ordner (*Ausgewählte Medien ansehen…* für ausgewählte
  Dateien und Ordner). Wählbar sind die Typen (Bilder inkl. SVG,
  PDFs, Videos über QtMultimedia), ob Unterordner einbezogen werden
  (Tiefe 1–32; höchstens 5000 Dateien, Symlink-Ordner werden nicht
  verfolgt, unlesbare Ordner übersprungen und gezählt) und der
  Start: **Zuerst die Übersicht** (Thumbnail-Grid mit Filter, Sortierung
  nach Name / Datum / Ordner und Größen-Slider; Enter oder
  Doppelklick öffnet), **Diashow starten** oder **Durchklicken**.
  Im Viewer: Links / Rechts / PageUp / PageDown / Space gehen zur
  vorigen / nächsten Datei (Stopp am ersten und letzten Element; auch
  im PDF, und die Slideshow blättert nur in einem allein geöffneten PDF). Ein PDF mit
  mehr als einer Seite bekommt eine Seitensteuerung `← n / m →` in der
  Button-Leiste; Hoch / Runter blättern seine Seiten. Home / End, F11 Fullscreen,
  Strg+M Maximize / Restore (das Fenster merkt sich Größe, Position
  und Maximize-Zustand für das nächste Öffnen),
  Mausrad oder `+` / `-` Zoom, `F` Fit, `1` 100 %, `R` drehen, `S`
  Slideshow (Intervall in Sekunden; die Slideshow läuft im Kreis,
  ein Video spielt bis zum Ende), Esc zurück zur Overview, nochmal
  Esc schließt. **Entf** (Delete) löscht die gezeigte Datei (oder
  das ausgewählte Tile) nach einer Rückfrage; das Bild oder ein Tile
  auf eine Pane ziehen verschiebt es dorthin, mit Strg wird kopiert -
  wie ein Drag aus der Pane, aus der der Viewer kam (in einem
  hineingezoomten Bild pannt der Drag stattdessen). Der
  Bild-Viewer kann beides auch. Funktioniert auf jedem Backend: Remote-Dateien
  werden bis zum *Größenlimit beim Öffnen* in ein privates Temp-Verzeichnis
  kopiert und danach gelöscht; zu große, verschlüsselte oder kaputte
  Dateien zeigen den Grund statt des Inhalts. SVG wird nur ohne
  DOCTYPE/Entities, Skripte und Verweise nach außen gerendert. Der
  `paranoid`-Mode sperrt den Viewer.
  `I` (oder der *Info*-Button) zeigt die Metadata des aktuellen
  Elements in einem Side-Panel, mit *Metadaten entfernen* — auch im
  Bild-Viewer.
- **Media Player** (mitgelieferte Extension; ihr Werkzeugleisten-Knopf
  oder *Extensions → Media Player* bietet an, sie einzuschalten) — ein Dock, das MP3, WAV, Ogg Vorbis, FLAC, Opus, AAC
  und mehr abspielt - und Internetradio: *URL…* fügt einen Stream über
  seine http-/https-Adresse hinzu (die .m3u-Playlist eines Senders nennt
  sie auch; in einem Stream gibt es keine Position zum Spulen). Tracks kommen per Rechtsklick → *Im Media Player abspielen*, *Hinzufügen…* oder per Drag & Drop von Dateien und Ordnern aus
  einem Datei-Pane oder vom Desktop auf die Playlist dazu (Ordner
  liefern ihre Audiodateien sortiert, höchstens 2000, 6 Ebenen tief,
  Links auf Ordner werden einmal verfolgt; auch .m4b, .wv, .webm und
  weitere Formate, die die Engine abspielt, zählen; was keinen Track
  ergibt - kein Audio, nicht lesbar, zu tief -, nennt der Hinweis mit
  Anzahl, Dateien neben gefundenen Tracks wie Cover nicht; Remote-Dateien
  werden abseits des GUI-Threads in einen temporären Ordner kopiert,
  je Datei höchstens 512 MB, je Drop 2 GB). Zeilen lassen sich per
  Drag umsortieren; der laufende Track (fett, Play-Icon, im
  Dock-Titel) spielt weiter. Spulen mit dem Positions-Slider (Klick
  oder Ziehen, `1:23 / 4:56`). ⏮ startet den Track nach 3 s neu,
  sonst geht es zurück; Shuffle spielt jeden Track einmal pro Runde,
  Repeat ist off / all / one. Ein nicht abspielbarer Track wird
  markiert und übersprungen. *M3U* → *Playlist laden…* / *Playlist speichern…* lesen und schreiben
  M3U-/M3U8-Playlists (UTF-8, relative Pfade für Tracks unter dem
  Ordner der Playlist, `#EXTINF`-Titel und -Längen; http-/https-Streams bleiben, andere URLs, fehlende
  oder Nicht-Audio-Einträge werden übersprungen, Dateien über 1 MiB
  oder mit NUL-Bytes abgelehnt; temporäre Kopien von Remote-Tracks
  werden nicht gespeichert). Liste, aktueller Track samt Position,
  Lautstärke, Mute, Shuffle und Repeat kommen beim nächsten Start
  wieder (`~/.config/axross/media_player.json`, Mode 0600). Die
  Lautstärke folgt einer wahrnehmungsgerechten (kubischen) Kurve;
  Mute-Button. Output-Device und Output-Volume aus *Bearbeiten → Einstellungen… →
  Audio* gelten obendrauf (eine Änderung dort erreicht einen laufenden
  Track sofort). Startet das Audio nicht, sagt das Panel warum:
  *Erneut versuchen* prüft noch einmal und startet den Player, sobald das
  Audio antwortet, *Audio-Einstellungen…* öffnet die Audio-Seite (anderes
  Backend oder Device). Tasten, solange der Player den Fokus hat: Space
  Play/Pause, Enter spielt die markierte Zeile, Delete entfernt die
  markierten Zeilen, Links / Rechts spulen 5 s (mit Shift 30 s),
  Strg+Links / Strg+Rechts vorheriger / nächster Track, M Mute,
  + / - Lautstärke. Mit numpy: 10-Band-Equalizer mit Presets (der
  Pfeil links von *Equalizer* klappt die Band-Slider ein und gibt der
  Playlist den Platz; es ist der eine Equalizer von axross - auch die
  Stimme des Agents läuft hindurch, er steht in `audio.json` und kommt
  beim nächsten Start wieder). Der Knopf **…** rechts der Lautstärke:
  *Ausgabe* spielt den Media Player auf einem eigenen Gerät (*Wie die Ausgabe*, oder z. B. das Headset, während die Stimme auf den
  Lautsprechern bleibt - sein Kanal im Audio Mixer), *Sleep-Timer* pausiert
  nach 15 bis 90 Minuten mit 8 Sekunden Ausblenden oder am Ende des Tracks
  (die Restzeit steht neben der Lautstärke), *Audio Mixer…* öffnet den
  Mixer. Dazu eine animierte Visualisierung: Spektrum,
  gespiegeltes Spektrum, radiales Spektrum, Oszilloskop, Stereo-VU-
  Meter, Linien-Spektrum (logarithmische Frequenzachse), Waterfall
  (Spektrogramm), Polar-Spektrum, Stereo-Scope (Goniometer: L gegen R),
  ein Starfield, das mit dem Bass schneller wird, *LED equalizer*
  (Blöcke mit fallendem Peak-Block), *Particle columns* (Punkte, aus
  denen im Beat Funken aufsteigen), *Wave ribbon* (ein Band aus Linien,
  das sich mit dem Beat dreht), *Ridgelines* (die History des Spektrums
  in der Tiefe unter einer gestreiften Sonne), *Spectrum terrain* (die
  History als Wireframe-Landschaft), *3D ring* (Balken auf einem
  gekippten Ring), *Kaleidoscope* (gespiegelte Blüten aus Bass, Mitten
  und Höhen) oder *Bell curves* (eine Glockenkurve je Band) - ein Klick
  darauf wechselt zur nächsten. Ihr Rechtsklick-Menü listet jede
  Visualisierung und jedes Farbschema (Classic, Fire, Ice, Neon, Mono,
  *Follow the theme*, *Custom*), die Anzahl der Balken und das
  Frame-Rate-Limit; *Visualizer-Einstellungen…* (auch *Extensions → Media-Player-Visualisierung…*) ergänzt die eigenen Farben (Hintergrund, leise
  und laute Balken, Peaks - eine Peak-Farbe ohne 3:1-Kontrast zum
  Hintergrund wird angepasst), Peak-Fall-Speed und Smoothing.
  *Vollbild* (Menü, Doppelklick oder F11 auf der Visualisierung) zeigt
  sie allein auf dem Bildschirm wie einen Screensaver - Esc, F11 oder
  ein Doppelklick beenden das, der Mauszeiger verschwindet nach 2,5 s
  ohne Bewegung (abschaltbar); *In eigenes Fenster lösen* legt sie in ein
  eigenes Fenster beliebiger Größe, das weiterläuft, *Ans Panel andocken* oder das Schließen des Fensters holt sie zurück. Der Pfeil links
  von *Playlist* (oder *Playlist anzeigen* im Menü) klappt die Playlist ein:
  das Panel ist dann Steuerung und Visualisierung, die Tasten wirken
  weiter, und auf das Panel gezogene Dateien landen weiterhin in der
  Playlist. Visualisierung, ihre Farben und Optionen, eingeklappter
  Equalizer und eingeklappte Playlist kommen beim nächsten Start wieder.
- **Chat** (mitgelieferte Extensions IRC, Matrix und XMPP: unter
  *Extensions → Extensions verwalten…* einschalten, dann zeigt und
  verbirgt das Extensions-Menü das Panel jeder einzelnen; Matrix und XMPP
  brauchen das Extra `chat`, das *Hilfe → Funktionen…* anbietet) — der
  Konto-Editor bietet bekannte öffentliche Server
  in einer editierbaren Liste an (eigene jederzeit eintippbar): ein Stand
  liegt axross bei, *Liste aktualisieren* holt die öffentlichen Verzeichnisse
  (irssis Netzwerkliste, joinmatrix.org, die XMPP-Providers-Liste) über den
  Proxy und speichert sie. Verbunden öffnet *Channel List* / *Room
  Directory* / *Group Chats* rechts die öffentlichen Kanäle des Servers -
  Filter, Sortierung, Doppelklick tritt bei (IRC LIST in Portionen, höchstens
  100 000 Kanäle). Ein Schloss an jedem Konto und Gespräch zeigt den Schutz:
  TLS zum Server, Ende-zu-Ende verschlüsselt (alle Schlüssel geprüft oder
  nicht) oder Klartext.
- **Bluetooth** (mitgelieferte Extension; *Tools → Bluetooth* bietet
  an, sie einzuschalten) — ein Panel, um Lautsprecher, Kopfhörer und andere
  Bluetooth-Geräte über BlueZ (`bluetoothd`) am System-D-Bus zu
  verbinden; es startet kein Programm. Es zeigt den Adapter (bei
  mehreren: auswählen) mit dem Schalter *Eingeschaltet*, und *Scannen* listet, was
  in Reichweite ist: Name, Adresse, Typ (Lautsprecher, Headset, Telefon,
  Tastatur, Uhr, Tracker, Sensor …), Funk (Classic, BLE oder beides),
  Signalstärke in dBm während des Scans, den Hersteller, den ein
  BLE-Gerät aussendet, Akkustand, wo das Gerät ihn meldet, wann es
  zuletzt zu hören war (*jetzt*, *vor 12 s*) und Verbunden / Gekoppelt /
  Vertraut. **Gerät hinzufügen…** fügt ein neues Gerät in einem Zug hinzu: schaltet
  den Adapter auf Nachfrage ein, scannt, solange der Dialog offen ist,
  listet die neuen Geräte in der Nähe (benannte zuerst, stärkstes Signal
  oben, *Unbenannte zeigen* für Beacons), und *Hinzufügen* pairt, vertraut und verbindet
  das gewählte Gerät und macht einen Lautsprecher oder ein Headset mit
  angehaktem *Als Audioausgabe nutzen* zum Ausgang von axross - jeder Schritt
  wird abgehakt oder scheitert mit Grund; *Abbrechen* bricht ein Pairing ab,
  Schließen stoppt den gestarteten Scan. Neben *Scannen* wählst du, wonach ein
  Scan sucht - *Classic +
  BLE*, *Classic only* (Lautsprecher, Telefone, Tastaturen) oder *BLE
  only* (Uhren, Tracker, Sensoren) - und das schwächste Signal, das er
  listet (*-70 dBm or stronger* bleibt bei den Geräten in der Nähe); ein
  laufender Scan behält seine Wahl. Die Zeile darunter filtert die Liste
  ohne neuen Scan: Wörter gegen Name, Adresse, Typ, Hersteller und
  Dienste, *All radios* / *Klassisch* / *BLE* und *Nur mit Namen* (blendet die
  namenlosen Beacons und Tracker aus, die ein BLE-Scan dutzendweise
  findet). Der Tooltip eines Geräts nennt seine Dienste. *Details…* (oder
  ein Doppelklick) zeigt alles, was BlueZ über ein Gerät weiß - Adresse
  und ihren Typ, Art, Funk, Hersteller, Klasse und Appearance, Signal und
  Sendeleistung, Akku, wann es zuletzt zu hören war, seinen Zustand und
  die rohen Advertising-Daten - und unter *Dienste* die Dienste und
  Profile, die es anbietet. Für ein verbundenes BLE-Gerät (*Verbinden*
  steht gleich daneben) kartiert es die GATT-Dienste, die BlueZ
  aufgelöst hat, mit ihren Characteristics: *Lesen* oder *Alle lesen* holt
  ihre Werte, *Beobachten* zeigt jeden neuen Wert einer meldenden
  Characteristic (Puls, Sensor) bis *Beobachten beenden* oder bis der Dialog
  schließt. Bekannte Werte werden dekodiert (Gerätename, Akkustand,
  Appearance, Puls, Temperatur, Luftfeuchte, Luftdruck), andere als Text
  oder Hex. Der Tab *Karte* neben *Liste* zeichnet die Geräte in der Nähe
  um diesen Computer herum in ihrer geschätzten Entfernung - aus dem
  Signal und, wo ein Gerät sie aussendet, seiner Sendeleistung, geglättet
  über die letzten Messungen; Ringe markieren 1, 3, 10 und 30 m.
  Bluetooth verrät keine Richtung, der Winkel eines Geräts ist nur sein
  fester Platz auf der Karte. Die Farbe ist der Funk (Classic, BLE,
  beides), ein gefüllter Punkt ein gepairtes Gerät, ein Ring ein
  verbundenes; die nächsten Geräte mit Namen sind beschriftet, Hovern
  zeigt Signal und Entfernung jedes Geräts, ein Klick wählt es in der
  Liste und ein Doppelklick öffnet seine Details (deren *Signalverlauf*
  die letzten Messungen zeigt). Die Filterzeile gilt auch für die Karte.
  Eine Entfernung ist eine grobe Schätzung - Wände und Körper halbieren
  oder verdoppeln sie leicht. *Test…* (oder der Tab *Verbindung* der
  Details) enthält die Verbindungsoptionen und Tests: ein einzelnes Profil
  verbinden oder trennen (*Audio playback (A2DP)*, *Headset with
  microphone (HFP)*, *Media controls*, HID, PAN, serielle Schnittstelle -
  die das Gerät anbietet); *Automatisch neu verbinden, wenn die Verbindung abbricht* (axross verbindet das Gerät nach 2, 5, 15, 30 und 60 s wieder,
  solange es läuft; ein Trennen, das du auslöst, ist kein Abbruch;
  gespeichert in `~/.config/axross/bluetooth.json`); *Verbindung testen* -
  verbindet bei Bedarf und berichtet, jeweils mit Zeit: die Verbindung,
  das Auflösen der Dienste, die Antwortzeit einiger GATT-Lesezugriffe
  (BLE) und bei Lautsprecher oder Headset das Erscheinen seines
  Audioausgangs; für Lautsprecher und Headsets *Testton abspielen* (zwei
  kurze Töne auf dem eigenen Ausgang des Geräts, egal welcher Ausgang in
  axross gewählt ist) und *Mikrofon testen* (Pegelanzeige für 5 s - das
  Mikrofon eines Headsets gibt es nur in seinem Headset-Profil, das Panel
  sagt, welches zu verbinden ist). Ein Scan endet nach
  2 Minuten von selbst. Für das gewählte Gerät: *Koppeln* (*Kopplung abbrechen*,
  solange es läuft), *Vertrauen* / *Nicht mehr vertrauen* (ein Trusted-Gerät darf sich
  selbst wieder verbinden), *Verbinden*, *Trennen*, *Entfernen* (nach einer
  Rückfrage). Bei Lautsprechern und Kopfhörern läuft das Pairing meist
  ohne Frage; will ein Gerät einen Passkey bestätigt, eine PIN oder einen
  Passkey, fragt ein Dialog - nichts wird ohne deine Antwort angenommen, Schließen ist
  ein Nein. *Als Audioausgabe verwenden* verbindet einen Lautsprecher oder ein
  Headset bei Bedarf, wartet bis zu 20 s, bis sein Ausgang im Soundserver
  erscheint, und macht ihn zum Ausgang von *Bearbeiten → Einstellungen… → Audio*,
  dem der Media Player und die anderen Player sofort folgen; erscheint
  kein Ausgang (das A2DP-Profil fehlt, z. B. weil PipeWire oder
  PulseAudio ohne Bluetooth-Unterstützung läuft), sagt das Panel es und
  bietet *Audio-Einstellungen…* an. Fehler von BlueZ werden zu Sätzen (Adapter
  aus, per rfkill blockiert, falsche PIN, Gerät außer Reichweite, Profil
  nicht verfügbar). Ohne System-D-Bus, ohne laufenden `bluetoothd` oder
  ohne Adapter sagt das Panel das und bietet nichts weiter an; es merkt,
  wenn der Dienst startet oder ein Adapter eingesteckt wird. Nur Linux.
- **Audio-Mixer** (mitgelieferte Extension, **Tools → Audio-Mixer**
  bietet an, sie einzuschalten) — alle Sound-Einstellungen in einem Panel.
  *axross*: die Master-Lautstärke mit Mute und Ausgabegerät und je Quelle
  — Media Player, Agent voice, Media preview — ein Kanal mit eigener
  Lautstärke, Mute und Ausgang (*Wie die Ausgabe* oder ein eigenes
  Gerät: die Stimme auf das Headset, die Musik auf die Lautsprecher).
  *Equalizer*: der eine 10-Band-Equalizer von axross mit Presets (die
  Equalizer-Zeile des Media Players zeigt dieselbe Einstellung, die
  Stimme des Agents läuft hindurch; hörbar mit numpy). *System*: der
  Soundserver über `pactl` (PipeWire oder PulseAudio) — Outputs und Inputs
  mit Lautstärke (bis 150 %), Mute und *Standard*, die Programme, die
  abspielen oder aufnehmen, mit Lautstärke und Gerät (ein anderes wählen
  verschiebt sie; die eigenen Streams von axross sind markiert), und das
  Profil jeder Karte (ein Bluetooth-Headset: A2DP für Musik, das
  Headset-Profil für sein Mikrofon). Ohne `pactl` oder Soundserver sagt
  der Tab warum und bietet *Erneut versuchen*. Alles steht in `audio.json` wie
  bei **Bearbeiten → Einstellungen… → Audio** (dort bleiben Backend, Eingabegerät und
  die Tests), laufende Player folgen sofort.
- **Systeminformationen** (mitgelieferte Extension) — siehe
  *Systeminformationen* unter *Mitgelieferte Extensions*.
- **SSH-Terminal** — Tab-Dock neben den Übertragungen. Lokales PTY
  (`pty.fork()`) und remote-SSH-über-paramiko stehen beide bereit;
  die SSH-Variante reused die bestehende Verbindung.

## Datei-Metadaten

Rechtsklick → **Metadaten anzeigen…**, **Metadaten entfernen…** oder **Metadaten
exportieren…** wirkt auf die ausgewählten Dateien und Ordner, ohne Auswahl
auf den Ordner selbst. Das Metadaten-Fenster zeigt je Datei eine Zeile,
ihre Felder hintereinander als `key: value`; Doppelklick oder Rechtsklick
→ *Eigenschaften…* öffnet alle Felder dieser Datei, gruppiert und eins pro
Zeile, Rechtsklick → *Metadaten entfernen* bereinigt nur die ausgewählten
Dateien. Dazu Filter, *Kopieren* (die Felder der ausgewählten Dateien als
Text), *Exportieren…* (JSON oder CSV) und *Metadaten entfernen* für alle
gelisteten Dateien. Ordner werden flach gelesen;
*Unterordner einbeziehen* geht tiefer (höchstens 5000 Dateien, Tiefe 8,
Symlink-Ordner werden nicht verfolgt). Lesen und Entfernen laufen im
Hintergrund mit Fortschritt und *Abbrechen*. In Bild- und Media-Viewer
öffnet `I` dieselbe Information als Side-Panel.

| Art | Lesen | Entfernt | Bleibt |
|---|---|---|---|
| JPEG, PNG, WebP, GIF | eingebaut | EXIF (GPS, Kamera, Seriennummern, Zeiten, Autor, Software), eingebettete Thumbnails, XMP, IPTC, Kommentare, PNG-Text-Chunks, Daten hinter dem Bild | EXIF-Orientation, ICC-Farbprofil; die Pixel werden nie neu kodiert und auf Gleichheit geprüft |
| TIFF | eingebaut | dasselbe, über verlustfreies Neuspeichern | Orientation, ICC-Profil; JPEG-komprimiertes TIFF wird abgelehnt |
| docx / xlsx / pptx, odt / ods / odp | eingebaut | `docProps/core.xml`, `app.xml`, `custom.xml`, ODF-`meta.xml`, der Zip-Kommentar | alle anderen Teile, die zu denselben Bytes entpacken |
| PDF | pypdf, sonst QtPdf | Info-Dictionary, XMP-Streams, PieceInfo, frühere Revisionen (komplettes Neuschreiben) | — braucht das Extra `[metadata]` (`pip install 'axross[metadata]'`) |
| Audio / Video | `ffprobe` | alle Tags und Kapitel, Data-Streams (GPS-Spuren von Kameras), das Cover-Bild von Audio-Dateien (`ffmpeg -c copy`, keine Neukodierung) | die Streams |

**Wie geschrieben wird** — *Bearbeiten → Einstellungen… → Metadaten* (*Tools →
Metadaten-Einstellungen…* öffnet sie):

- **Die Datei ersetzen** (Standard): die Datei wird atomar ersetzt, das Original
  bleibt im axross-Papierkorb. Ein Lauf — eine Datei oder ein ganzer
  Ordner — ist ein Eintrag für *Bearbeiten → Letzte Aktion widerrufen* (`Strg+Z`),
  der jedes Original Byte für Byte zurückholt, aber nur solange die
  Datei noch genau das enthält, was das Entfernen geschrieben hat.
- **Eine bereinigte Kopie daneben schreiben**: `name.clean.ext` neben dem Original
  (`name.clean (1).ext`, wenn es das schon gibt); nichts wird
  überschrieben.

Eine Nachfrage gibt es nur, wenn dort *Vor dem Entfernen von Metadaten fragen*
angehakt ist. Remote-Dateien gehen über eine private Temp-Kopie bis zum
*Größenlimit beim Öffnen* und zurück über den atomaren Schreibweg des Backends;
eine Verbindung, deren Papierkorb nicht beschreibbar ist, bekommt
stattdessen eine bereinigte Kopie, und das Ergebnis sagt es. Eine Datei,
die sich während des Bereinigens ändert, bleibt unangetastet. Im
`paranoid`-Mode funktionieren Lesen und Entfernen, außer bei Audio /
Video: das hieße ffprobe / ffmpeg auf den Dateiinhalt loszulassen.
Skripte: `axross.metadata`, `axross.remove_metadata`,
`axross.export_metadata` (siehe [SCRIPTING_de.md](SCRIPTING_de.md)).

## Werkzeuge

Fenster der Menüs *Ansicht* und *Tools*, die kein Panel sind. **F1** in
jedem von ihnen öffnet seinen Teil dieses Abschnitts.

### Duplicate Finder

*Ansicht → Duplicate Finder…* (`Strg+Umschalt+D`; im Pane Rechtsklick →
*Doppelte Dateien finden…*) arbeitet mit dem Duplikat-Index (`cas.sqlite`,
siehe *Der Offline-Index*).
Er gruppiert indizierte Dateien nach Content-Hash, die größte Verschwendung zuerst: jede Gruppe zeigt den Platz, den sie freigäbe, die Statuszeile die Summe. Leere Dateien und Gruppen, die nur Hardlinks einer Datei sind, bleiben verborgen, solange *Leere Dateien* / *Hardlinks* nicht angehakt ist. *Filter* (Text oder Muster wie `*.jpg *.png`; `Strg+F`), *Mindestens* (eine Größe) und *Sortieren* (freizugebender Platz, Größe, Kopien, Name, Ordner) grenzen die Liste ein; die Kopien einer Gruppe bleiben in Survivor-Reihenfolge (die erste bleibt). *Aus aktivem Pane neu aufbauen…* hasht den Ordner im Hintergrund mit Anzahl, Bytes und *Abbrechen*: Unveränderte Dateien werden nicht neu gehasht, seit dem letzten Scan verschwundene Dateien verlassen den Index, und der Bericht nennt Dateien, die nicht lesbar waren, Ordner, die sich nicht auflisten ließen, und übersprungene FIFOs, Sockets oder Geräte (nie gelesen: das könnte hängen). Ein Backend ohne eigene Content-Prüfsumme (SMB, einfaches FTP, WebDAV nur mit ETags) lässt seine Dateien stattdessen lesen — nur die, deren Größe eine andere Datei teilt, und nur so weit, wie ihre ersten 64 KiB übereinstimmen; ein ETag zählt nie als Hash. *Alle Duplikate markieren (erste behalten)* behält die älteste Kopie; *Markieren und behalten…* (auch im Kontextmenü) behält die neueste Kopie, den kürzesten Pfad oder eine Kopie in einem Ordner, oder markiert die Kopien in einem Ordner; ein Hardlink einer behaltenen Kopie wird nie markiert, und Hardlinks zählen nicht als freizugebender Platz. *Auswahl in den Papierkorb verschieben…* (`Del`) verschiebt die markierten Kopien in den axross-Papierkorb, nachdem live geprüft ist, dass eine echte andere Kopie bleibt. `Enter` öffnet den enthaltenden Ordner, die Zeile unter der Liste zeigt die aktuelle Zeile vollständig (exakte Größe, Hash, Hardlinks), und `ax-cas://…`-URLs lassen sich kopieren. Tausende Gruppen erscheinen stückweise, während das Fenster bedienbar bleibt.

*Ansicht → Duplikat-Index & Verlauf…* zeigt den Index für sich: jeder
Neuaufbau wird als Scan festgehalten und mit Ordner, Backend, Beginn und
Ende, den indizierten Dateien, den noch im Index stehenden Dateien, den
Duplikatgruppen und seinem Status gelistet. *Duplikate zeigen* öffnet den
Duplicate Finder auf den Gruppen dieses Scans, *Neu scannen* durchläuft
denselben Ordner auf demselben Backend im Hintergrund noch einmal (mit
*Abbrechen*; ein neuer Scan wird festgehalten), *Aus dem Index
entfernen…* vergisst die Zeilen dieses Scans und *Ganzen Index leeren…*
alle Zeilen - die Dateien selbst bleiben, wo sie sind. Zeilen, die
indiziert wurden, bevor Scans festgehalten wurden, bilden einen Eintrag
*früher*: er lässt sich zeigen und entfernen, nicht neu scannen (sein
Ordner ist unbekannt).

### Disk Usage

*Ansicht → Disk Usage…* ist eine Tabelle mit der Kapazität jeder offenen
Verbindung (jede Verbindung einmal, egal wie viele Panes sie zeigen):
Backend, Protokoll, gesamt, belegt, frei und ein Balken des belegten
Anteils. Die Abfragen laufen außerhalb des GUI-Threads, jede mit eigenem
Timeout. Eine Verbindung, die keine Kapazität meldet (IMAP, LDAP, die
meisten Cloud-Object-Stores) oder nicht rechtzeitig antwortet, zeigt
*not supported* und keinen Balken - gemessen wurde nichts, und das ist
nicht 0 %; die Zeile darunter zählt sie. *Aktualisieren* misst neu.

### Geplante Jobs

*Ansicht → Geplante Jobs…* startet ein gespeichertes Skript (das
Scripts-Dock) in einem Intervall: dem Job einen Namen, den Namen des
Skripts und ein Intervall geben (5 Minuten, 15 Minuten, 1 Stunde, 6
Stunden, 1 Tag oder ein eigenes von mindestens 300 s) und *Hinzufügen*.
Die Tabelle zeigt zu jedem Job Skript, Intervall, letzten Lauf, Status,
nächsten Lauf und das Detail des letzten Laufs; *Ein- / ausschalten* und
*Entfernen* wirken auf den gewählten Job. Jobs laufen nur, solange axross
läuft (es prüft einmal pro Minute), jeder in einem Kindprozess wie ein
Lauf aus dem Scripts-Dock, nicht interaktiv (eine Rückfrage wird
abgelehnt, statt zu warten), höchstens 24 Stunden und 1 000 000 Zeichen
Ausgabe pro Lauf. Ein Job, der noch läuft, wird nicht noch einmal
gestartet; Termine, die verstrichen, während axross geschlossen war,
ergeben einen Lauf, keinen Rückstau; nach 10 Fehlschlägen in Folge
schaltet sich ein Job ab und nennt den Grund (*Ein- / ausschalten*
schaltet ihn wieder ein). Der Sicherheitsmodus paranoid lehnt die Läufe
ab. Skripte, die ein Job startet, tragen im Scripts-Dock `[scheduled]`.
Die Jobs liegen in `~/.local/state/axross/jobs.json`.

### Diagnose und Recovery-Scan

- **Tools → Diagnose für aktives Pane…** prüft die Verbindung des
  aktiven Panes: ihren Home-Ordner, ein Listing und ein Stat des
  gezeigten Ordners und - nach einer Rückfrage, nie im Sicherheitsmodus
  paranoid - eine Probe, die dort eine kleine Datei `.axross-diagnostic-*`
  schreibt, umbenennt und löscht. Der Bericht nennt jede Prüfung als
  `[OK]` oder `[FAIL]` mit ihrem Detail, Passwörter und Tokens
  ausgelassen; er entsteht außerhalb des GUI-Threads.
- **Tools → Recovery-Scan…** listet, was sich im Ordner des aktiven Panes
  wiederherstellen lässt: temporäre Dateien, die ein unterbrochenes
  atomares Schreiben zurückließ (`.tmp-*.tmp`, auch die älteren
  `.axross-atomic-*.tmp`), und die Einträge im axross-Papierkorb dieser
  Verbindung mit ursprünglichem Pfad und Größe. Er entfernt nichts:
  *Papierkorb anzeigen…* stellt wieder her, und Reste, die älter als eine
  Stunde sind, entfernt ein Pane, wenn es ihren Ordner öffnet.

## Mitgelieferte Extensions

axross bringt Extensions in `resources/extensions/` mit; jede ist zu
Beginn ausgeschaltet, und *Extensions → Extensions verwalten…* schaltet
sie ein und aus. Ein Werkzeugleisten-Knopf (Media Player, Ordner-Treemap,
Laufwerksübersicht) und die Einträge *Tools → Audio-Mixer*, *Tools →
Bluetooth* und *Tools → Systeminformationen…* bieten an, ihre Extension
einzuschalten, wenn sie aus ist. Media Player, Chat, Bluetooth und
Audio-Mixer beschreibt *Editoren und Viewer*, Agent Stats das *Agent-Dock*.
Die übrigen: Laufwerksübersicht und Markdown Preview sind Panels,
Checksum Manifest (*SHA256SUMS erstellen*), Forensic Tools (Disk-Images:
Hashes, qemu-img, The Sleuth Kit, TestDisk, PhotoRec) und VirtualBox
bringen Einträge im Kontextmenü. Wie Extensions vertraut, pausiert und
geschrieben werden - und welche `api` sie bekommen - steht in
[EXTENSIONS.md](EXTENSIONS.md) (englisch).

### Arcade

*Extensions → Arcade…* öffnet ein Fenster mit axross' eigenen vier
kleinen Spielen: **Byte Chase** (jedes Bit eines Labyrinths einsammeln,
während vier Daemons dich jagen; ein Root-Schlüssel dreht sie eine Weile
um), **Tilt Maze** (100 Level in 10 Welten auf einem isometrischen Brett,
die Leertaste springt über die Daemons und Gruben), **Rockfall** (40
Höhlen in 5 Welten: unter fallenden Felsen nach Kristallen graben, dann
rechtzeitig den Ausgang erreichen) und **Trail Runner** (Fahrer ziehen
Mauern hinter sich her; 1-3 Computerfahrer oder zwei Spieler an einer
Tastatur, die Leertaste gibt Schub). In der Auswahl wählen die Pfeile oder
W A S D, Enter oder ein Klick startet; ein Spiel bietet *Bei Level 1
beginnen*, *Bei Level n weitermachen* und einen *Weltcode*, der eine schon
erreichte Welt öffnet. Im Spiel: Pfeile oder W A S D lenken, `P` pausiert,
`M` schaltet stumm, `R` beginnt nach dem Spielende neu, Esc geht zurück zur
Auswahl und schließt von dort das Fenster. Jedes Level wird erzeugt, Musik
und Klänge werden synthetisiert und folgen der Ausgabe des Audio-Mixers;
Bestwerte und Fortschritt liegen in `~/.config/axross/arcade.json` und
`arcade-progress.json`.

### Ordner-Treemap

Ein Panel (der Werkzeugleisten-Knopf *Ordner-Treemap* oder *Extensions →
Ordner-Treemap*), das den Ordner des aktiven Panes als Kästen zeichnet,
deren Fläche die Größe ist: Dateien und Unterordner, die Unterordner im
Hintergrund über die Verbindung summiert - höchstens 20 000 Einträge und
12 Ebenen, Links auf Ordner werden nicht verfolgt. Eine Summe, die dort
aufhörte, markiert der Tooltip mit *(at least)*; er nennt den Kasten und
seine Größe. Ein Doppelklick auf einen Ordner-Kasten öffnet ihn im Pane;
wer einen Ordner verlässt, bevor sein Durchlauf fertig ist, beendet
diesen Durchlauf. Die Pause-Taste in der Titelleiste des Panels lässt es
dem Pane nicht mehr folgen.

### Entropy Heatmap

Eine Datei rechts anklicken → *Entropie-Heatmap…*: die Shannon-Entropie
jedes 4-KiB-Blocks ihrer ersten 16 MiB als Farbstreifen - blau für Text,
Tabellen und Padding, rot für komprimierte oder verschlüsselte Daten -
mit dem Durchschnitt und dem höchsten Wert in Bit pro Byte und einem
Urteil (*durchgehend komprimiert oder verschlüsselt*, der Anteil solcher
Blöcke, *niedrige Entropie* oder *gemischter Inhalt*). Die Datei wird im Hintergrund
über ihre Verbindung gelesen, entfernte Dateien gehen also auch.

### Backup Repositories

Rechtsklick auf einen Ordner (oder auf nichts, für den gezeigten Ordner)
→ *Backup-Repository-Info…* sagt, was ein **restic**-, **Borg**- oder
**duplicity**-Repository enthält, ohne Passwort und auf jedem Backend,
allein aus seinem Aufbau: bei restic die Zahl der Snapshots, Schlüssel,
Indizes und Pack-Ordner; bei Borg die Klartext-`config` (Version, ID,
Segment-Einstellungen, append-only, repokey oder keyfile) und die Zahl
der Segmente; bei duplicity jede Backup-Kette mit ihren vollen und
inkrementellen Backups, deren Zeiten, Volumes, Größe und
Verschlüsselung. *Unlock…* fragt nach dem Passwort (und einer
Borg-Schlüsseldatei, wenn das Repository eine hat) und listet die
Snapshots oder Archive über das Werkzeug selbst (`restic snapshots`,
`borg list`, `duplicity collection-status`) - nur lokale Repositories.
Das Passwort geht in die Umgebung des Werkzeugs oder an die Eingabe von
gpg, nie auf eine Kommandozeile, und wird nicht gespeichert; ins
Repository wird nichts geschrieben.

### Image Batch

Bilder wählen (`.png .jpg .jpeg .webp .bmp .gif .tif .tiff`), Rechtsklick
→ *Bilder skalieren / umwandeln…*: die längste Kante in Pixeln (0 behält die
Größe; nie vergrößert) und das Format (PNG, JPEG oder WebP). Die Kopien
landen in einem Unterordner `resized`, als `name (2).jpg`, wenn ein Name
vergeben ist - nichts wird überschrieben, die Originale bleiben
unberührt. Fotos werden zuerst nach ihrer EXIF-Ausrichtung aufgerichtet;
ein JPEG bekommt transparente Stellen auf Weiß. Bilder über 64 MiB und
Dateien, die kein Bild sind, werden übersprungen und gezählt. Geht auf
jedem Backend; das Pane lädt neu, wenn der Stapel fertig ist.

### Systeminformationen

**Systeminformationen** (mitgelieferte Extension, **Tools →
Systeminformationen…** bietet an, sie einzuschalten; danach auch *Extensions →
Systeminformationen…*) — ein Fenster mit allem über den Rechner, auf dem
axross läuft. *Übersicht*: Name, Hersteller, Modell und OS des Rechners
mit seinen Eckdaten (CPU-Threads, Speicher, Storage, Displays), und
Kacheln mit Ringen für CPU-Last, Speicher, Swap, das Root-Dateisystem
und den Akku (Ladung und Health), die heißesten Temperaturen auf einer
Farbskala (grün bis 60 °C, gelb, orange ab 80 °C oder der eigenen
High-Marke des Sensors, rot ab 90 °C oder Critical), Grafik mit den
angeschlossenen Displays und die Netzwerk-Interfaces mit ihrem
Live-Durchsatz; CPU und Speicher haben eine Sparkline der letzten zwei
Minuten. Ein Klick auf eine Kachel öffnet ihre Seite. Die Liste links
hat je eine Seite für *CPU* (Last je logischer CPU, P- und E-Cores,
Frequenzen, Caches, Befehlssatz-Features als Chips, die Sicht des
Kernels auf die CPU-Vulnerabilities), *Arbeitsspeicher* (belegt, Cache und frei
als ein Balken, Swap), *Speicher* (ein Balken je Disk mit ihren
Partitionen, Mount-Points und Belegung; Disks und Dateisysteme als
Tabellen), *Grafik & Bildschirme* (Adapter, Ausgänge mit Name,
Auflösung, Bildrate und Größe des Monitors aus seiner EDID, eine Skizze
der Bildschirme), *Netzwerk* (Interfaces mit Art, Zustand, Speed oder
WLAN-Signal, Treiber und Traffic; Bluetooth-Adapter; Funkschalter),
*Audio* (Soundkarten, Codecs, PCM-Devices), *USB & Peripherie* (der
USB-Baum und die Eingabegeräte), *PCI* (der PCI-Baum, Namen aus
`pci.ids`), *Akku & Strom*, *Sensoren* (Temperaturen, Lüfter,
Spannungen), *System & Betriebssystem* (Hersteller, Modell, Firmware, Secure Boot,
Kernel, Desktop, Versionen) und *Virtualisierung* (Bare Metal, eine
virtuelle Maschine oder ein Container, mit den Indizien). Alles wird
ohne root und ohne ein Programm zu starten aus `/proc` und `/sys`
gelesen (unter Windows und macOS weniger: was Python und das optionale
psutil sagen); jede Quelle hat eine Frist, und ein Abschnitt, der sich
nicht lesen lässt, sagt warum - die anderen warten nicht darauf. Das
Suchfeld (`/`) filtert alle Seiten zugleich, die Liste zählt die
Treffer je Seite. *Abschnitt kopieren*, *Alles kopieren* und *Bericht speichern…* (Text
oder JSON) exportieren das Gesammelte; *JSON-Export* speichert alles als
JSON-Datei oder kopiert alles bzw. die gezeigte Seite als JSON (jeder
Wert, jede Tabelle, jeder Rohwert). Seriennummern, MAC- und
IP-Adressen und UUIDs sind auf dem Bildschirm und in jeder Kopie
verborgen, bis *Kennungen zeigen* angehakt ist - solche Berichte landen
oft öffentlich. Live-Werte werden einmal pro Sekunde gelesen, solange
das Fenster zu sehen ist, nie im Hintergrund; *Aktualisieren* sammelt alles
neu. Das Fenster behält seine Größe.

## Übertragungen-, Terminal- und Log-Dock

- Der untere Streifen hat drei Tabs: **Übertragungen**, **Terminal**,
  **Log**. Jeder flasht bernsteinfarben, wenn off-screen etwas
  passiert (Transfer-Status, Shell-Output, Log-Zeile). Klick raist
  + cleart.
- Rechtsklick auf eine Übertragung für **Abbrechen** (diesen Job),
  **Wiederholen** (einen fehlgeschlagenen oder abgebrochenen Job) und
  **Zielordner öffnen**.
- Das Log-Dock filtert nach Level und nach Area: *Bereiche* neben dem Level
  ist eine Liste der Logging-Areas zum Anhaken (eine Area nimmt ihre
  Sub-Areas mit; *Sonstige* ist alles außerhalb, *Alle Bereiche* der Default).
  Beide Filter zeigen die bisher empfangenen Zeilen neu. Was überhaupt
  geloggt wird, steht in *Bearbeiten → Einstellungen… → Logging* (siehe
  [Logging](#logging)).
- Das Terminal (Dock und Terminal-Pane) ist ein VT100-/xterm-Screen:
  Carriage Return, Cursor-Bewegungen, Erase, Scroll-Regionen und der
  Alternate Screen funktionieren, also stehen zsh-Prompts,
  Zeilen-Editing, `less`, `top` und Editoren an der richtigen Stelle.
  Die Terminal-Größe der Shell ist die Größe der Terminal-Fläche und
  folgt jedem Resize (`stty size` zeigt sie). Farben werden nicht
  angezeigt.
- Tasten im Terminal gehen an die Shell: Strg+Buchstabe (auf macOS die
  Control-Taste), Funktionstasten, Pfeile und Editiertasten — Strg+W,
  Strg+Q oder F6 schließen dort also keine Pane, beenden axross nicht
  und verschieben keine Dateien. Einfügen mit Strg+Umschalt+V (macOS:
  Command+V), Mittelklick oder Kontextmenü; der Text geht an die Shell.
  Command-Shortcuts auf macOS und die Zoom-Tasten bleiben bei axross.
- Während eines Datei-Drags über einer Pane bekommt die Zeile, in die
  der Drop geht, einen Rahmen, und ein Hinweis am Cursor nennt den
  Ordner: *Nach … verschieben* oder mit Strg *Nach … kopieren*. Die Zeile `..` ist
  der Ordner darüber.

## Scripting & eingebettete REPL

axross liefert ein kuratiertes Python-Surface (``axross.*``) mit
122 öffentlichen Namen (111 Funktionen + 11 Klassen: die Result-Typen
der Network-, Grep- und Archiv-Helper, NonInteractiveError). Drei Wege zum
gleichen Surface:

- **Console-Dock** (View-Menü) — REPL mit Multi-Line-Input,
  History, Tab-Completion, Seitenpanel mit jeder Funktion + Docstring.
  Tab vervollständigt dort, deshalb bringt **Esc** den Fokus zurück ins
  Datei-Pane.
- **Headless** — ``axross --script myscript.py`` führt dein
  Python im selben Namensraum aus; ideal für Cron/CI/Batches.
  Wörter nach der Datei sind ``sys.argv[1:]`` des Skripts
  (``axross --script mirror.py /srv/data``); der Security-Mode
  paranoid, auch wenn in den *Einstellungen* gewählt, verweigert es.
- **MCP** — wenn ``--mcp-allow-scripts`` gesetzt ist, ist das
  Surface auch über MCP-Tool-Calls erreichbar.
- **Hilfe → Scripting-Leitfaden** — der Scripting-Leitfaden in axross
  (SCRIPTING_de.md, in der Sprache der Oberfläche, wo es eine Fassung
  gibt) und auf dem zweiten Tab die API-Referenz (der Text von
  `axross.docs()`), mit Inhaltsverzeichnis und Suchfeld (Return findet
  den nächsten Treffer).

Quick examples:

```python
b = axross.localfs()
items = b.list_dir("/var/log")[:10]
hits = axross.grep(b, "/var/log", r"kernel:.*panic")

src = axross.open("my-sftp")           # benannt per Connection Manager
axross.copy(src, "/etc/hosts", axross.localfs(), "/tmp/hosts.bak")

probe = axross.http_probe("https://example.com")
ips = axross.dns_resolve("example.com")
```

### Die API durchsuchen

- ``axross.help()`` — Cheat-Sheet nach Kategorie.
- ``axross.docs("backend")`` / ``axross.docs("scripts")`` /
  ``axross.docs("slash")`` — Markdown-Referenz pro Thema.
- Tab-Completion auf ``axross.<TAB>`` in der REPL.
- ``docs/SCRIPTING_REFERENCE.md`` — jedes Verb und jede Result-Klasse mit
  voller Signatur und Docstring.

### REPL-Slash-Commands

| Befehl | Wirkung |
|---|---|
| ``.help`` | Slash-Commands auflisten |
| ``.scripts`` | Gespeicherte Skripte in ``~/.config/axross/scripts/`` |
| ``.save <name>`` | Den in DIESER Sitzung abgeschickten Code speichern; ein vorhandenes Skript gleichen Namens wird nie ersetzt (erst ``.delete``) |
| ``.load <name>`` | Den Code eines gespeicherten Skripts ausgeben |
| ``.run <name>`` | Ein gespeichertes Skript im laufenden Namensraum ausführen |
| ``.delete <name>`` | Ein gespeichertes Skript entfernen |
| ``.open`` | Den Pfad des Skript-Ordners ausgeben |

### Proxy in Skripten

``axross.open(profile_name)`` und ``axross.open_url(url, **kw)`` reichen
die Proxy-Einstellungen durch dieselbe ConnectionManager-Logik wie die GUI.
``open()`` liest sie aus dem gespeicherten Profil; ``open_url()`` nimmt sie
als Keyword-Argumente:

```python
b = axross.open_url(
    "sftp://alice@gateway.example.com/",
    password="hunter2",
    proxy_type="socks5",          # "socks5" / "socks4" / "http" / "https" (+ "+ntlm" ...)
    proxy_host="proxy.example.com",
    proxy_port=1080,
    proxy_username="puser",       # optional
    proxy_password="ppass",       # optional
)
```

Ist `proxy_type` nicht `"none"`, sind `proxy_host` und ein `proxy_port`
ungleich 0 Pflicht. Ein halb konfigurierter Proxy schlägt fehl, statt
direkt zu verbinden. Ohne `proxy_*`-Keyword nimmt `open_url` den
Standard-Proxy aus *Tools → Netzwerk & Proxy…* (seine Bypass-Liste und das
PAC-Skript gelten); ein PAC-Skript, das sich nicht auswerten lässt, wirft
`ProxyResolutionError`, statt direkt zu verbinden. Welche Backends den Proxy
unterstützen und welche nicht (UDP, Kernel-/USB-Transporte, lokale
Backends) steht in **[USAGE.md](USAGE.md)** (EN) und
**[PROXY_SUPPORT.md](PROXY_SUPPORT.md)**.

### Kategorien (jeder öffentliche Name: `axross.api_schema()`)

| Gruppe | Verben |
|---|---|
| Verbinden / Backend | ``open``, ``open_url``, ``localfs``, ``ramfs``, ``list_backends``, ``available_backends`` |
| Profile | ``list_profiles``, ``get_profile``, ``save_profile``, ``delete_profile`` |
| Datei-I/O | ``copy``, ``move``, ``checksum``, ``read_bytes`` / ``write_bytes`` / ``read_text`` / ``write_text``, ``hash_bytes`` / ``hash_file`` |
| Krypto / Archive | ``encrypt``, ``decrypt``, ``extract_archive``, ``is_archive``, ``archive_inspect`` |
| Bookmarks | ``list_bookmarks``, ``add_bookmark``, ``remove_bookmark`` |
| Skripte | ``script_dir``, ``list_scripts``, ``save_script``, ``load_script``, ``delete_script``, ``run_script`` |
| Pro Protokoll | ``find_tftp_files``, ``slp_discover``, ``nntp_post``, ``git_push``, ``exec``, ``interactive_shell``, ``query``, ``tables``, ``imap_search`` / ``imap_move`` / ``imap_set_flags``, ``share``, ``ldap_search`` |
| DNS / Netz | ``dns_resolve`` / ``dns_records`` / ``dns_reverse``, ``port_open``, ``port_scan``, ``subnet_hosts`` |
| Netzwerk-Helfer | ``ping`` / ``PingResult``, ``mac_lookup`` / ``OuiInfo``, ``whois`` / ``WhoisInfo``, ``time_skew`` / ``TimeSkew``, ``tcp_banner``, ``tls_cert`` / ``TlsCert``, ``ssh_hostkey`` / ``SshHostKey``, ``http_probe`` / ``HttpProbe`` |
| SNMP | ``snmp_get``, ``snmp_walk``, ``snmp_set``, ``SnmpVar`` |
| Suche über Backends | ``find_files``, ``grep`` / ``GrepHit``, ``diff_files`` |
| Datei-Metadaten | ``metadata``, ``remove_metadata``, ``export_metadata`` |
| UI-Helfer | ``message``, ``confirm``, ``toast`` (modal + Toast mit SVG-Status-Icons; ohne GUI stdout/stdin), ``is_interactive``, ``NonInteractiveError`` |

### UI-Helfer — message / confirm / toast

Skripte + REPL können modale Dialoge und Toasts zeigen, die
**ohne Qt-Event-Loop sauber auf stdout/stdin zurückfallen** (das
gleiche Skript läuft also in Cron/CI weiter):

```python
axross.message("Backup fertig (123 Dateien kopiert)",
               level="success")

if axross.confirm("47 Dateien löschen? Nicht rückgängig.",
                  default_yes=False):
    for p in doomed:
        backend.remove(p)

axross.toast("Verbindung weg — re-try", level="error")
axross.toast("1,2 MB gespeichert", level="success", timeout=2)
```

Levels: ``"info"`` (blau), ``"success"`` (grün), ``"warning"``
(gelb), ``"error"`` (rot) — jeweils mit eingebettetem SVG-Status-
Icon und axross-Glyph als Fenster-Icon.

Der headless-Prompt von ``confirm()`` fragt nur, wenn stdin ein
Terminal ist. Ohne Mensch — Cron, Pipe, der Kindprozess des
Scripts-Docks, ein MCP-``script_run`` oder ``AXROSS_NONINTERACTIVE=1`` —
wirft er ``axross.NonInteractiveError``, statt den Default zu nehmen;
``assume_yes=True`` antwortet dort ohne Rückfrage mit Ja.

## SSH-/SCP-Terminal-Multiplexing

Wenn du via SSH oder SCP verbunden bist, öffnet axross **eine**
TCP-Verbindung + paramiko-Transport. Folge-Operationen multiplexen
darauf:

- **SFTP/Datei-Ops** laufen auf einem dedizierten Channel.
- **Terminal hier öffnen** (Terminal-Dock) allokiert einen weiteren
  Channel mit PTY — voll-interaktive Shell, kein zweites Login,
  kein zweiter Key-Challenge. Funktioniert gleich für SSH und SCP.

Damit bekommt ein SCP-Pane denselben Rechtsklick „Remote-Shell hier
öffnen“ wie ein SSH-Pane, auf derselben Verbindung.

## Keyring automatisch erkennen und neu erkennen

Gespeicherte Passwörter landen im Keyring des Betriebssystems
(Secret Service / KWallet / Windows Credential Locker / macOS Keychain /
das Secret-Service-Plug-in von KeePassXC). axross sucht beim ersten
Speichern ein funktionierendes Backend. Jedes andere keyring-Backend
funktioniert ebenso, solange es keine Eingabe im Terminal braucht (etwa
keyring-pass oder keyrings.cryptfile über ``keyringrc.cfg``); sind
mehrere installiert, nimmt axross das, das keyring selbst zuerst
nimmt. Klartextdateien (``PlaintextKeyring``) und das
``EncryptedKeyring`` von keyrings.alt, das sein Master-Passwort im
Terminal abfragt, werden nicht genutzt. Ohne brauchbares Backend ist
„Im Keyring speichern“ ausgegraut, mit einem Hinweis, was zu
installieren ist:

- **Arch:** ``sudo pacman -S gnome-keyring`` (oder kwallet,
  oder keepassxc)
- **Debian:** ``sudo apt install gnome-keyring``
- **Fedora:** ``sudo dnf install gnome-keyring``

Startest du den Daemon erst **nach** axross, hilft
**Datei → System-Keyring neu erkennen** (oder einfach noch einmal
speichern – der nächste ``store_password`` prüft automatisch neu).

## MCP-Server

axross läuft wahlweise als Model-Context-Protocol-Server, sodass ein
LLM-Client (Claude Desktop, Cline, ein eigener Agent) jedes
konfigurierte Backend über JSON-RPC-Tools steuern kann.

```bash
axross --mcp-server                                  # read-only, stdio
axross --mcp-server --mcp-write --mcp-root ~/data    # Schreib-Tools (auf diesen Root beschränkt)
axross --mcp-server --mcp-http 127.0.0.1:7331        # HTTP-Loopback
```

Die Read-only-Datei-Tools (`list_dir`, `stat`, `read_file`,
`checksum`, `search`, `walk`, `grep`, …), die Schreib-Tools bei
`--mcp-write`, die Capability-Gruppen von `--mcp-tools`
(`axross --mcp-list-tools` gibt jedes Tool aus, das ein Satz Flags
anbietet), `resources/*`-Endpoints,
`notifications/message`-Log-Forwarding, Per-Tool-Timeouts,
Per-Session-Token-Bucket-Rate-Limits, HTTP-Sessions mit SSE-Progress,
optional Multi-Backend-Routing.

Volle Referenz: **[docs/MCP_de.md](MCP_de.md)** (DE) · [MCP.md](MCP.md) (EN) · [MCP_es.md](MCP_es.md) (ES).
Für LLM-Clients: [LLM_GUIDE.md](LLM_GUIDE.md) (englisch).

## Agent-Dock — ein lokales LLM arbeitet mit axross

Ansicht → Panels → Agent (Den Agenten fragen: Strg+Umschalt+K;
Strg+Umschalt+A kehrt in einer Dateiliste die Auswahl um) öffnet einen Chat mit einem
LLM-Profil (die Profile des Analysis-Docks (sift): LM Studio, Ollama, vLLM,
llama.cpp oder ein anderer OpenAI-kompatibler Server; LLM… verwaltet
sie). Das Modell arbeitet mit denselben Tools wie der MCP-Server, im
oben angezeigten Ordner (dem des aktiven Panes, wenn es lokale Dateien
zeigt).

**Ollama** betreibt ein Modell ohne weitere Angabe mit einem Context von
4096 Tokens, und schon die Anweisungen und Tools des Agents brauchen
2.000 bis 5.000 Tokens (5.259 mit *Änderungen an Dateien erlauben*). Den Server
mit `OLLAMA_CONTEXT_LENGTH=16384` starten oder `PARAMETER num_ctx 16384`
in einem Modelfile setzen: Ollama kürzt einen Request, der nicht passt,
ohne Meldung, und seine OpenAI-kompatible API nimmt keine Context-Größe
an. Hat eine Antwort den Context gefüllt, sagt der Tab das.

**Tabs.** Jeder Tab ist ein eigener Verlauf mit eigenem Modell,
Protection-Mode, Sandbox, Ordner und Tools: „+“ oder Strg+T öffnet
einen, ein Doppelklick benennt ihn um. Mit *Tabs und ihre Unterhaltungen behalten*
(Tools → Agent-Einstellungen…) ist jeder Tab eine JSON-Datei in
`~/.config/axross/agent/sessions/` (`0o600`) und kommt beim nächsten
Start wieder. Strg+Enter sendet, Esc oder Stop beendet die Aufgabe
sofort - auch während das Modell noch an der Antwort schreibt (der
Request wird abgebrochen, der Server hört auf zu generieren) - und
Pfeil hoch/runter holt frühere Aufgaben zurück. Schreibt ein
Reasoning-Modell seine ganze Antwort nur ins Reasoning (Qwen3 in LM
Studio tut das manchmal), wird sie so gekennzeichnet angezeigt; endet
ein Modell ganz ohne Antwort, steht das da.

**Verläufe als eigene Panels.** Rechtsklick auf einen Tab → **Als Panel
lösen** - oder den Tab weit aus der Tab-Leiste ziehen - macht den
Verlauf zu einem eigenen Panel; **Tools → Neues Agent-Fenster** (oder ⧉
neben „+“) öffnet einen neuen Verlauf gleich als Panel. **An Workspace senden** im selben Tab-Menü erledigt es in einem Schritt: der Verlauf
wird abgelöst und auf den gewählten Workspace gelegt, mit **Neuer Workspace** allein auf einen neuen, wo er die Hauptansicht ist - per
Rechtsklick auf dessen Tab → **In eigenes Fenster lösen** bekommt er ein eigenes
Fenster. Es wandert
derselbe Verlauf: eine laufende Aufgabe läuft weiter, ihre Rückfragen
kommen weiterhin, nichts startet neu. Ein solches Panel liegt wie ein
Extension-Panel: auf **Alle Workspaces** (im Dock-Bereich des Fensters)
oder - über den ⇄-Button bzw. Rechtsklick auf seine Titelleiste (*An Workspace senden*) oder **Workspace → Extension-Panel hinzufügen** - auf einem
Workspace, wo es ein Pane ist: an der Titelleiste ziehen, in der Größe
ändern, beim Detach des Workspace geht es mit. ⇲ (oder *An das Agent-Dock anheften* im Rechtsklick-Menü) setzt es als Tab zurück. Sein [x] schließt
den Verlauf wie das Schließen seines Tabs: gibt es einen Verlauf, fragt
es vorher, dann ist er gelöscht. Wird sein Workspace geschlossen, bleibt
es auf *Alle Workspaces*; *Alle Panels in diesem Bereich schließen* setzt es zurück
ins Agent-Dock. Jedes Panel hat seine eigene Lampe; die Stimme arbeitet
für den Verlauf, in dem sie gestartet wurde, sonst für den, in dem
zuletzt getippt wurde; Einstellungen, Profile und Extensions erreichen jeden
Verlauf. Mit *Tabs und ihre Unterhaltungen behalten* kommen abgelöste Verläufe nach einem Neustart
auf ihrem Workspace bzw. auf *Alle Workspaces* wieder; einer, dessen
Workspace nicht wiederkommt (das Layout wird nicht wiederhergestellt),
ist wieder ein Tab.

**Denkt nach.** Was ein Reasoning-Modell denkt, bevor es antwortet oder
ein Tool aufruft (`reasoning_content` bzw. `reasoning` neben der
Antwort, oder `<think>…</think>` an ihrem Anfang), steht getrennt von
der Antwort: eine graue, kursive Zeile **▸ Denkt nach** mit dem ersten
Satz. Ein Klick auf *Denkt nach* klappt den ganzen Text auf, ein zweiter
wieder zu. Vorgelesen wird nur die Antwort. Gespeicherte Tabs behalten
diesen Text, zugeklappt.

**Die Lampe** in der Title-Bar des Docks zeigt, ob das LLM des Tabs
antwortet: **grün** - der letzte Request an seinen Endpoint (eine
Modell-Liste oder ein Request einer Aufgabe) hat geklappt; **orange** -
einer läuft; **rot** - er ist gescheitert, es gibt kein Profil, oder der
Endpoint ist remote und hat noch keinen Consent (gefragt wird erst bei
der ersten Aufgabe). Der Tooltip nennt Endpoint, Modell und Grund; ein
Klick prüft erneut. Die Prüfung holt im Hintergrund die Modell-Liste des
Servers, nur solange das Dock sichtbar ist.

**Protection-Modes** (je Tab):

- **Ask** — jede Änderung und jeder Remote-Befehl wartet auf Ja in
  einem Dialog, der Tool und Argumente zeigt (Passphrasen maskiert).
- **Plan** — der Agent liest nur und schreibt einen Plan; *Diesen Plan ausführen* führt ihn dann im Ask-Mode aus.
- **Automatisch** — Änderungen laufen ohne Frage; Remote-Befehle und Tools
  eines MCP-Servers auf „always“ fragen weiter.
- **Bypass** — nichts fragt. Nur wählbar, wenn in den Agent-Einstellungen
  eingeschaltet, nie im Security-Mode paranoid, und rot markiert.

**Dateien übergeben.** Das „+“-Menü hängt Auswahl oder Ordner des
aktiven Panes an, Dateien aus einem Dialog oder einen Pfad aus der
Zwischenablage; Dateien lassen sich aus einem Pane auf den Tab ziehen,
oder *An den Agenten senden* im Rechtsklick-Menü des Panes. Eine lokale Datei
außerhalb des Tab-Ordners macht ihren Ordner für diesen Tab lesbar
(read-only).

**Tools** (Tools ▸ im Tab): die Datei-Tools, die angehakten Gruppen
(metadata, filetype, archive, …), *Änderungen an Dateien erlauben*, *Remote-Befehle erlauben*, eine Zeile `mcp:<name>` je MCP-Server und `ext:<id>`
je Extension mit Agent-Tools. Immer dabei: `ask_user` (der Agent fragt
dich etwas) und `update_plan` (eine Checkliste über dem Eingabefeld).

**Nie vom Agenten geändert**, egal welche Wurzel und welcher Zugriff:
axross' eigene Einstellungen und Daten (`~/.config/axross`,
`~/.local/share/axross`, `~/.local/state/axross` - seine Rechte, seine
MCP-Server), Shell-Startdateien (`~/.bashrc`, `~/.profile`, `~/.zshrc`,
…), `~/.config/autostart`, `~/.config/systemd`, `~/.ssh` und `~/.gnupg`,
Befehle im PATH (`~/.local/bin`) und Python-Start-Hooks (`~/.local/lib`),
Einstellungen von Git, pip und npm, Startdateien von Editoren und
Window-Managern sowie Einstellungen und MCP-Server anderer LLM-Clients
(`~/.claude`, Claude Desktop, Cursor, VS Code), am Standardort und am
XDG-Ort: geändert, würde jede davon Code ausführen oder die Rechte des
Agenten ohne Rückfrage erweitern. Ein Ordner, der eine davon enthält,
wird auch nicht gelöscht oder verschoben, und ein Symlink führt nicht an
ihnen vorbei. In der Sandbox werden die vorhandenen und die fehlenden
Ordner darunter nur lesend eingehängt. Der Agent liest außerdem keine
Tokens von axross und keine privaten SSH- und GnuPG-Keys
(`--mcp-allow-secret-reads` hebt das für den MCP-Server auf).

**Versteckte Dateien sind für Agent und MCP schreibgeschützt.** Über die
Liste hinaus schreibt, löscht oder verschiebt kein Werkzeug des Agenten
oder des MCP-Servers einen versteckten Eintrag des Home-Ordners
(`~/.pdbrc`, `~/.wezterm.lua`, `~/.aliases`, `~/.jupyter`, …) oder irgendetwas
in `~/.config`, `~/.local/share` und `~/.local/state` (auch dort, wohin XDG
sie verlegt, `~/Library` unter macOS, `%APPDATA%` unter Windows): zu viele
Programme führen Code von dort aus. Soll der Agent einen dieser Ordner
ändern, gib genau diesen Ordner frei - als Wurzel des Agenten (oder
des MCP-Servers) oder als zusätzlichen Ordner (`~/.config/myapp`); die
Orte der Liste oben bleiben darin geschützt, und das ganze Home
freizugeben hebt nichts auf. zsh-Dateien in `$ZDOTDIR` (aus `~/.zshenv`
gelesen) zählen als Startdateien, und die Git-Dateien, die Code ausführen -
`.git/config`, `.git/hooks`, `.git/info`, `.gitmodules` eines Repositorys,
ein `.git`-Eintrag selbst -, werden überall abgelehnt. In der Sandbox werden
die versteckten Einträge eines beschreibbaren Home nur lesend eingehängt,
und kein neuer kann angelegt werden; Git-Konfiguration und Hooks des
Agenten-Ordners sind ebenfalls nur lesbar. MCP-`chmod` setzt kein
setuid-, setgid- oder Sticky-Bit und macht nichts für Gruppe oder alle
schreibbar.

**Geheimnisse, die der Agent nicht liest**, neben denen von axross: die
Zugangsdaten gängiger Werkzeuge (`~/.aws`, `~/.kube`,
`~/.docker/config.json`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`,
`~/.pypirc`, `~/.npmrc`, cargo, rclone, Vault, Terraform, die Zugangsdaten
von Claude Code, `pass`), Browser- und Mail-Profile (Firefox, Chrome,
Chromium, Brave, Edge, Thunderbird; die macOS-Schlüsselbunde) und unter
einem versteckten Ordner des Home jede Datei, deren Name credential,
token, secret, key (`*.pem`, `*.key`, `id_*`, `*key*.json`), eine
Passwort-Datenbank (`*.kdbx`), cookies oder history nennt (Shell- und
REPL-Verläufe enthalten getippte Tokens). Ihre Namen bleiben sichtbar;
die Sandbox zeigt sie leer. Der Papierkorb von axross (`~/.axross-trash`)
ist für alle Werkzeuge ebenfalls geheim und schreibgeschützt: ein
gelöschter Schlüssel bleibt ein Schlüssel, und was aus dem Papierkorb
zurückkommt, legt axross mit seinen Rechten zurück. Der Papierkorb
signiert jeden Eintrag: ein Eintrag, dessen Daten oder Angaben geändert
wurden, wird nicht wiederhergestellt, und einer, der an einen geschützten
Ort zurückgeht (eine Startdatei, einen Autostart-Eintrag), nur im
Papierkorb-Fenster und erst nach deiner Bestätigung.

**Dateien schreibgeschützt** (in der oberen Zeile des Tabs, und für jeden Tab in
Agent-Einstellungen → Zugriff): der Agent liest Dateien, ändert aber keine —
kein Schreiben, Löschen oder Verschieben, keine Remote Commands (ein
Command kann Dateien ändern), Extra-Ordner read-only, keine schreibenden
Tools von MCP-Servern oder Extensions, und eine Sandbox mountet nichts
schreibbar. Das gilt dort, wo die Tools des Agents gebaut werden, und
noch einmal bei jedem Aufruf, nicht nur im Dialog. Eine genaue
Ausnahme: ein MCP-Server, der deine Dateien nicht ändern kann, behält
seine Tools — ein Container-Server auf axross' eigener podman-Zeile (aus
einem Catalog installiert) mit `--network=none` und nur read-only
Ordnern (`:ro`). Seine Einstellung *Fragt* gilt weiter: mit „Jeder Aufruf fragt (auch in Auto)“ wartet
jeder Aufruf auf dein Yes. Jeder andere Server (Netzwerk, ein
schreibbarer Ordner, ein Programm auf diesem Rechner, ein HTTP-Server,
eine von Hand geschriebene podman-Zeile) bietet nur die Tools an, die er
als read-only markiert, und gar keins, wenn er vor jedem Aufruf fragt.

**Themen ▸** füllt das Eingabefeld mit einer vorbereiteten Aufgabe —
System inventory, Install or update software (im Plan-Mode), Service
status, Collect logs, Disk usage, Summarise a folder, Read data out,
Review a config folder, Free disk space (mit den Tools des Duplicate
Finders) — zum Ergänzen und Absenden. Extensions können eigene
hinzufügen.

**Eigene Topics** („Work prompts“): Topics ▸ *+ Neues Thema…* öffnet ein
leeres Formular, *Diese Aufgabe als Thema speichern…* übernimmt das Eingabefeld,
*Meine Themen bearbeiten oder löschen…* ändert oder löscht sie. Ein Topic speichert
Titel, Slash-Command,
den Prompt (`{folder}` und `{backend}` werden eingesetzt), den
vorgeschlagenen Mode, was er braucht und welche Tool-Gruppen er
anhakt, in `~/.config/axross/agent/work_prompts.json`. Jedes Topic hat
einen Command: `/` im Eingabefeld zeigt sie (`/free-space`,
`/review-config`, eigene); Text nach dem Command bleibt unter dem Prompt
stehen. Ein Command füllt das Feld — du liest und sendest.

**Prompts** (*Bearbeiten → Einstellungen… → Agent → Prompts*): System-Prompt (die
Regeln, die das Modell zuerst bekommt) und User-Prompt (ein Template für
jede Aufgabe: `{task}` wird zum getippten Text, Text ohne `{task}` kommt
davor, leer schickt die Aufgabe wie getippt) als benannte Profile.
*Default (eingebaut)* ist axross' eigener Prompt und lässt sich weder ändern noch
löschen — *Duplizieren* legt eine änderbare Kopie an. *Prompt-Profil neuer Anfragen* wählt das Profil für die nächste Anfrage jedes Tabs; der
Tab ergänzt weiter Ordner, Plan-Mode und Vorlese-Regeln. Gespeichert in
`~/.config/axross/agent/settings.json`.

**axross-Funktionen** sind die Tools, die axross selbst für den Agenten
ausführt — außerhalb seiner Sandbox, mit den Rechten von axross:
*Entfernte Dateien* (die in den Panes offenen Verbindungen, Backend
`pane:<name>`), *Saved connections* (gespeicherte Profile, die der
Agent selbst öffnet), *Befehle auf entfernten Hosts* (SSH-/WinRM-/…-Hosts),
*MCP-Server* und *Extension-Tools*. Sie sind ein Weg aus der Sandbox
heraus; deshalb sichert sie ein Hauptschalter, und der ist
**standardmäßig aus**. Ein als *Produktion* markiertes Profil verweigert jede Änderung.

**Was ein Tab erreichen darf** — zwei Ebenen, beide müssen es erlauben:

- *Agent-Einstellungen → Zugriff* ist die Obergrenze jedes Tabs: der
  Hauptschalter *Agents dürfen axross-Funktionen nutzen* und jede Funktion.
  Dort aus heißt in jedem Tab aus.
- *Zugriff…* im Tab (oder *Agent-Einstellungen → Sessions* für alle Tabs auf
  einmal) ist die eigene Wahl des Tabs innerhalb davon: sein
  Hauptschalter und seine Funktionen, sein **Netzwerk** und seine
  **Ordner**. Ein neuer Tab startet mit dem Hauptschalter, wie die
  Agent-Einstellungen ihn haben.

| Netzwerk eines Tabs | Bedeutung |
|---|---|
| As the sandbox profile says | Level und Allowed Hosts des Profils (ohne Sandbox: keine Grenze) |
| None | gar kein Host |
| Only these hosts | die eigene `host:port`-Liste des Tabs |
| All hosts | nur bei einer lax-Sandbox oder ohne Sandbox |

Der Sandbox-Level bleibt die Obergrenze: ein Tab engt nur ein, was sein
Level kann (paranoid bietet nur *Keine*, normal und high kein *Alle Hosts*).
Das Netzwerk gilt für die eigenen Verbindungen der Sandbox, für
Remote-Arbeit in axross und für http-MCP-Server gleichermaßen und wird
bei jeder Verbindung geprüft. Die **Ordner** eines Tabs sind read-only
oder read-write; read-write nur, wo der Level Extra-Ordner zulässt (lax,
normal), und mit *Änderungen an Dateien erlauben*. Der Tooltip von *Zugriff…*
fasst alles zusammen.

**Agent-Profile** richten einen Tab in einem Schritt ein: LLM-Profil,
Prompt-Profil, Protection Mode, Sandbox, Tool-Gruppen, axross-Funktionen
(Hauptschalter, Funktionen, Netzwerk), *Dateien schreibgeschützt*, *Änderungen an Dateien erlauben* / *Remote-Befehle erlauben* und die MCP-Server, die er anbietet —
gewählt **nach Kategorie** (die Catalog-Kategorie, aus der ein Server
installiert wurde, z. B. *Security: Reverse Engineering*; *Kategorie* in
Agent-Einstellungen → MCP-Server setzt eine von Hand) und/oder **nach Name**
(oder nach dem Catalog-Eintrag, aus dem er stammt — ein umbenannter
Server passt weiter). Der Pfeil neben „+“ im Agent-Dock bietet **Neuer Tab aus Profil**, **Profil anwenden…** (auch im Rechtsklick-Menü eines Tabs)
und **Agent-Profile bearbeiten…**; Tools → Neuer Agent-Tab aus Profil öffnet
einen Tab für den Ordner des aktiven Panes. *Profil anwenden…* zeigt
vorher, was der Tab bekäme; es ändert die Settings des Tabs, Ordner und
Konversation bleiben, und ein Tab mit laufendem Task lehnt ab (erst
stoppen — der laufende Task behält die Settings, mit denen er startete).
Der Tab nennt sein Profil (*Profil: …*) und listet, was die Obergrenze
gekappt hat oder fehlt, mit **Aus dem Katalog installieren…** (der Catalog öffnet
auf dieser Kategorie oder sucht den Server-Namen).

Ein Profil **erweitert Agent-Einstellungen → Zugriff nie**: sind axross-Funktionen
dort aus, werden die MCP-Server des Profils nicht angeboten, und der Tab
sagt es; Bypass nur, wo er wählbar ist; ein Sandbox-Profil, das es nicht
gibt, bleibt stehen und wird verweigert, nie still *Keine Sandbox*. Unter
*Dateien schreibgeschützt* bietet ein Server mit *Fragt* „Jeder Aufruf fragt (auch in Auto)“ gar kein
Tool an, außer er ist ein Container ohne Netzwerk mit read-only Ordnern
(siehe *Dateien schreibgeschützt* oben) — der Tab nennt jeden solchen Server und
warum.

Eingebaute **Presets** (read-only, markiert *(Preset)*; *Kopieren* macht ein
änderbares Profil daraus):

| Preset | Was es einrichtet |
|---|---|
| Dateiassistent | die Datei-Tools von axross, die offenen Remote-Verbindungen; Änderungen fragen; keine MCP-Server |
| Reverse Engineering | Kategorien *Security: Reverse Engineering* und *Security: Firmware & Forensics*; Sandbox *High* |
| Forensik (nur lesen) | Kategorie *Security: Firmware & Forensics*; *Dateien schreibgeschützt* |
| Netzwerk- & Web-Recon | Kategorien *Security: Network Recon*, *Security: Web*, *Security: OSINT*; Mode Ask |
| Code & Secrets | Server *git* und *filesystem*, Kategorie *Security: Code & Secrets* |
| Remote-Betrieb | Remote Files, Saved Connections, Remote Commands (jedes fragt); Mode Ask |
| Recherche | Server *fetch*, *memory*, *sequentialthinking*; nicht *Dateien schreibgeschützt* (fetch braucht Netzwerk), *Änderungen an Dateien erlauben* aus |

Ein Preset, dessen Server nicht installiert sind, richtet den Rest des
Tabs trotzdem ein. Agent-Einstellungen → **Profile** bearbeitet die eigenen
Profile (New, Copy, Delete), zeigt in einer Preview, was ein Tab innerhalb
der Access-Seite bekommt, und wählt das **Profil neuer Tabs**. Gespeichert
in `~/.config/axross/agent/settings.json` (`agent_profiles`,
`agent_profile`); ein von Hand geänderter Eintrag wird geprüft wie der
Rest der Datei (unbekannte Keys fallen weg, falsche Typen nehmen ihren
Default, ein vergebener Name — auch der eines Presets — verwirft den
Eintrag).

**Sandboxes** (Agent-Einstellungen → Sandboxes): ein Tab kann seinen Agenten
in bubblewrap, podman oder docker laufen lassen. Ein Sandbox-Profil hat
einen Level:

| Level | Netzwerk | Ordner | Extra-Ordner |
|---|---|---|---|
| lax | das des Hosts | wie eingestellt | wie eingestellt |
| normal | nur Allowed Hosts | wie eingestellt | wie eingestellt |
| high | nur Allowed Hosts | wie eingestellt | read-only |
| paranoid | nur das LLM | read-only | read-only |

*lax* mit bubblewrap erreicht das Internet über einen eigenen
Netzwerk-Namespace, wenn `pasta` (passt) installiert ist; ohne es teilt
die Sandbox das Netzwerk des Hosts - auch seine abstrakten Sockets
(X-Server, D-Bus) - und das Log sagt es. Ein MCP-Server aus der
`.mcp.json` eines Projekts (oder den Einstellungen eines anderen
Clients), der ein Programm startet, fragt vor dem Einschalten und nennt
den ganzen Befehl und die Datei, aus der er stammt.

Die Anfragen ans Modell, der API-Key und die Zustimmung bleiben
draußen: die Sandbox hat kein eigenes Netzwerk, axross sendet für sie.
Allowed Hosts (`host:port`) erreicht sie über axross, geprüft bei jeder
Verbindung — eine Änderung gilt sofort. Remote-Verbindungen,
gespeicherte Profile, MCP-Server und Extension-Tools laufen ebenfalls
in axross, außerhalb der Sandbox, ihre Zugangsdaten kommen also nie
hinein; Level und Allowed Hosts der Sandbox entscheiden, ob der Agent
sie nutzen darf (paranoid: keine). Die Limits des Levels für Speicher,
Tasks und CPU gelten bei podman und docker; bubblewrap bekommt sie über
einen systemd-User-Scope (ohne einen nur den Speicher, per `prlimit`).
podman und docker brauchen das Image: `scripts/axross-podman.sh
agent-image` ([PACKAGING.md](PACKAGING.md)).

**MCP-Server** (Agent-Einstellungen → MCP-Server): weitere MCP-Server — ein
Programm (stdio) oder ein HTTP-Endpunkt —, deren Tools ein Tab als
`<server>__<tool>` anbieten kann. *Testen* listet ihre Tools. Ein Server
auf „always“ fragt bei jedem Aufruf; „writes“ lässt Tools, die der
Server als read-only markiert, ohne Frage laufen. Ein Programm kann in
einem Sandbox-Profil laufen; eines ohne sagt *läuft auf diesem Rechner, nicht
in einem Container*. Der Token eines HTTP-Servers liegt im Keyring. Ein
getippter Befehl, der Code herunterlädt (`npx …`, `uvx …`, `docker run
…`), wird nie als Programm auf diesem Rechner gespeichert: *In einem Container installieren* baut ihn in rootless podman (ohne Netz), oder der Grund, warum
das nicht geht, wird gezeigt. Eine von Hand bearbeitete Einstellungsdatei mit
so einem Befehl startet ihn ebenso wenig (der Server wird ausgelassen, mit
Log-Zeile), und eine Container-Zeile mit erweiternden Flags
(`--privileged`, `--cap-add`, Host-Namespaces, andere Mounts) wird
abgelehnt.

*Tools → MCP-Server…* öffnet diese Seite (Bearbeiten → Einstellungen… → Agent →
MCP-Server). **Aus Katalog hinzufügen…** durchsucht die *MCP-Quellen* und
installiert einen Server in **rootless podman**; nichts davon läuft auf
dem Host:

- **Quellen** (Agent-Einstellungen → MCP-Quellen, jede abschaltbar): der
  mitgelieferte Katalog (geht offline: die MCP-Referenz-Server fetch,
  filesystem, git, memory, sequentialthinking, time und everything; die
  eigenen Server der Hersteller für GitHub - nur lesend, Repositories,
  Issues und Pull Requests -, Playwright, MarkItDown und Brave Search;
  DuckDuckGo-Suche; drei Security-Server, vuln-nist, shodan und rea.
  Images sind per Digest gepinnt und kommen nur aus Dockers kuratiertem
  `mcp/*`-Namespace und von GitHubs eigenem
  `ghcr.io/github/github-mcp-server`; npm- und PyPI-Pakete sind auf eine
  exakte Version gepinnt), Docker Hubs `mcp`-Namespace, die offizielle
  MCP Registry (`registry.modelcontextprotocol.io`) und eigene
  Katalogdateien oder `https://`-URLs. *Prüfen* liest eine und nennt, was
  sie enthält oder warum sie abgelehnt wird (falsches Schema, größer als
  1 MiB, kein JSON, ein Eintrag ohne gepinnten Digest …). Was eine Quelle
  sagt, wird als reiner Text gezeigt.
- **c0decave MCP Hub** (standardmäßig an): ein Katalog desselben Schemas
  unter `https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json`.
  Nur Images unter `ghcr.io/c0decave/`, gepinnt per echtem
  `sha256`-Digest, werden übernommen; jeder andere Eintrag (andere
  Registry, npm, pypi, Remote, kein Digest) wird mit Grund abgelehnt.
  Solange der Hub nicht antwortet, sagt die Statuszeile *not reachable or
  not published yet*, und die anderen Quellen arbeiten wie gewohnt.
- **Discover** (standardmäßig an): kuratierte Awesome-Listen zum Stöbern -
  [R00T-Kim/awesome-offensive-mcp](https://github.com/R00T-Kim/awesome-offensive-mcp)
  (CC0; ein Snapshot liegt axross bei, Discover geht also offline) und
  [wong2/awesome-mcp-servers](https://github.com/wong2/awesome-mcp-servers)
  (MIT; nur live gelesen). Ihr README wird als nicht vertrauenswürdiger
  Text gelesen: Kategorie, Name, Beschreibung und der GitHub-Repository-Link,
  sonst nichts - kein Markup, kein anderer Link. Ein Eintrag ist nur dann
  **installable via MCP Registry** oder **installable via Docker Hub**,
  wenn diese Quelle dasselbe Repository nennt (im Hintergrund geprüft,
  höchstens 300 Requests je Lauf, 24 h im Cache); sonst ist er **nur Link**: *Repository öffnen*, keine Installation - axross baut nie aus einem
  bloßen GitHub-Repository. *Aktualisieren* liest die Listen und prüft neu.
- **Installieren**: ein Image wird per Digest gepullt (bei Docker Hub wird der
  Digest des Tags vorher erfragt; andere werden auf den Digest gepinnt,
  den podman meldet). Ein npm- oder pypi-Paket wird in einem Container
  eines gepinnten `node:24-slim`- / `python:3.13-slim`-Images installiert
  (`npm --ignore-scripts`, `pip --only-binary=:all:`), dessen einziges
  Netz die Paket-Registry ist, und als `localhost/axross-mcp:<name>-<version>`
  committet - nie npx, uvx, npm oder pip auf dem Host. Ein Remote-Server
  (Streamable HTTP, https) wird ein HTTP-Server. Der Fortschritt wird
  gezeigt, *Installation abbrechen* bricht ab; danach wird der Server getestet
  (initialize, tools/list) und eingeschaltet, wenn der Test bestand.
  **Speichern** behält ihn.
- **Wie er läuft**: `podman run --rm -i --init --pull=never` ohne
  Capabilities, ohne neue Privilegien, mit read-only Root, kleinem
  noexec-`/tmp`, Prozess- und Speicherlimits. Netz standardmäßig
  **Keins**; **Allowlist** erreicht nur die angegebenen `host:port` über
  einen Proxy in axross (für Programme, die `HTTPS_PROXY` beachten; die
  anderen haben gar keine Route - Nodes eigenes `fetch` nur mit
  `NODE_USE_ENV_PROXY=1`, das der Eintrag Brave Search setzt); **Voll**
  jeden Host. Ordner nur wie gewählt, read-only, solange *Beschreibbar*
  nicht angehakt ist. Umgebungswerte und Secrets (im Keyring) erreichen
  den Container über eine Pipe, nie auf der Kommandozeile oder in einer
  Datei.
- **Deinstallieren** entfernt den Server und beim Speichern sein Image per ID
  (`podman rmi`, nie erzwungen: ein Image in Benutzung, anders getaggt
  oder schon vor der Installation vorhanden bleibt). **Nach Update suchen**
  zeigt einen neueren Digest oder eine neuere Version; aktualisiert wird
  nichts von selbst.

**Auf diesem Rechner erkannt** (Agent-Einstellungen → MCP-Server und die
Tools-Liste jedes Agent-Tabs): MCP-Server, die hier schon eingerichtet
sind, werden mit einer Checkbox angeboten, ohne einen Befehl zu tippen -
die Server von Claude Desktop (`claude_desktop_config.json`), Claude Code
(`~/.claude.json`, auch je Projekt, und `.mcp.json` im Ordner des Tabs),
VS Code (`settings.json` → `mcp.servers`,
`mcp.json`, `.vscode/mcp.json`) und Cursor (`~/.cursor/mcp.json`,
`.cursor/mcp.json`), dazu podman-Images, die axross installiert hat (auch
wenn die Einstellungen den Server verloren haben). Ein Haken in den Agent-Einstellungen
fügt den Server eingeschaltet hinzu (*Speichern* behält ihn), Haken weg entfernt
ihn; ein Haken an einer `detected:<name>`-Zeile eines Tabs fügt ihn hinzu,
speichert die Einstellungen und hakt `mcp:<name>` in diesem Tab an - das Modell
bekommt seine Tools sofort. Danach ist er ein Server wie jeder andere
(dieselben Confirm-Modes, standardmäßig „always“). **Was heruntergeladen
wird, läuft im Container, nie auf diesem Rechner:** ein Befehl, der beim
Start Code holt (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`,
`uv tool run`, `pipx run`, `docker`/`podman run` …), wird beim Haken
gekapselt installiert - das npm- oder pypi-Paket im gepinnten
`node`/`python`-Container gebaut (die neueste exakte Version, wenn der
Befehl keine nennt), ein Image gepullt und mit axross' gehärteter
podman-Zeile gestartet, ohne Netz; die Flags einer `docker run`-Zeile
(`--privileged`, `--network=host`, Volumes, `--cap-add`, `--device`,
Host-Namespaces, `--security-opt` …) werden nicht übernommen, und die
Details nennen, was wegfiel. Was sich nicht umsetzen lässt (eine Git-URL,
`--package`, `uv run`, eine unbekannte Option …), wird gezeigt, ist aber
nicht anhakbar, mit Grund. Ein Programm, das schon auf der Platte liegt,
läuft wie es ist, im Sandbox-Profil neuer Tabs (Agent-Einstellungen) bzw. des
Tabs, in dem es angehakt wurde, und sagt das: *läuft auf diesem Rechner, nicht
in einem Container*; eines, das es hier nicht gibt, ist nicht anhakbar. Die
Dateien werden nur gelesen, als nicht vertrauenswürdige Daten (reguläre Dateien bis 8 MiB,
JSON oder TOML, nichts wird ausgeführt). Umgebungswerte, die nach Secrets
aussehen (am Namen - TOKEN, PASSWORD, API_KEY … - oder an der Form), und
Bearer-Tokens landen nie in einem Log oder in `agent.json`: das
Einschalten fragt vorher und legt sie im Keyring ab. Programme im PATH
werden nicht erkannt: dort identifiziert nichts einen MCP-Server, ohne
ihn auszuführen oder am Namen zu raten.

Eine eigene Katalogdatei hat das Schema `axross-mcp-catalog`, Version 1
(Beispiel in [USAGE.md](USAGE.md)); `kind` ist `oci` (gepinnt per
`digest`), `npm` oder `pypi` (`package` und eine exakte `version`) oder
`remote` (`url`, `bearer`).

**Extensions** können den Agenten starten (`api.run_agent`,
`api.open_agent_tab`), ihm Tools geben (`api.add_agent_tool`), Topics
hinzufügen (`api.add_agent_topic`) und seinen Events folgen
(`api.on_agent_event`). Die mitgelieferte Extension *Agenten-Statistik* zeigt
ein kleines Fenster über dem Hauptfenster (ein normales Fenster:
verschieben, Größe ändern, schließen; auch unter Tiling-Window-Managern
schwebend) mit Aufgaben,
Antworten, Tool-Aufrufen, Fehlern, Tokens und Zeit.

Ein Profil, dessen Server nicht auf diesem Rechner oder in seinem Netz
liegt, fragt vorher, weil das Gelesene dorthin geht.

Im Container: `scripts/axross-podman.sh gui --llm-model DATEI.gguf`
startet axross auf deinem Display, llama.cpp daneben und das Profil
gleich mit ([PACKAGING.md](PACKAGING.md)). Mit `--agent-sandbox` läuft
dort auch die bubblewrap-Sandbox: podman maskiert `/proc`, das
bubblewrap selbst mounten muss; ohne die Option sagt der Tab das. Im
Container bubblewrap wählen - podman kann dort keine eigenen Container
starten.

Ein MCP-Client kann dem gleichen lokalen Modell mit `--mcp-tools agent`
(`agent_run`) eine Aufgabe übergeben; dieses Modell kann nur lesen
([MCP_de.md](MCP_de.md) §9.9).

### Mit dem Agenten sprechen

Der Button **🎤** im Tab spricht mit dem Agenten, **🔊** liest seine
Antworten vor. Sprache erkennt das LLM-Profil des Tabs (LLM Profiles,
*Advanced*): lokal mit Whisper — nichts verlässt den Rechner — oder ein
OpenAI-kompatibler Server (`/audio/transcriptions`; ein entfernter fragt,
bevor er eine Aufnahme hört). Antworten spricht eine lokale Piper-Stimme.

- **Mikrofon-Modi** (Einstellungen → Stimme): *Push-to-talk* (Button halten,
  oder die Hold-Taste, Default **F9**, solange das Agent-Dock den Fokus
  hat), *Toggle* (Klick startet, erneuter Klick oder eine Pause beendet)
  und *Conversation* (nach jeder gesprochenen Antwort hört es wieder zu;
  Klick auf den Button beendet).
- **Erkannter Text** landet im Aufgabenfeld zum Lesen und Senden, oder
  wird sofort gesendet (eine Conversation sendet immer).
- **Was gesprochen wird:** nur die Antwort - keine Tool-Aufrufe, kein Code
  (ein kurzer Satz sagt, dass Code angezeigt wird), keine URLs oder langen
  Pfade. Stop, Esc, Tippen oder eine neue Aufgabe beenden es. Lehnt axross
  einen Tool-Aufruf ab (Files read-only, nicht erlaubt, keine Permission),
  sagt die Stimme das kurz; die erste Sprachnutzung einer Session grüßt.
- **Sprache:** Deutsch oder Englisch, oder *der Antwort folgen*. In
  deutscher Sprache werden englische IT-Begriffe (Server, Backup, Pull
  Request, …) englisch gesprochen; ein Begriff, den die Antwort in
  `{Klammern}` schreibt, ebenso (die Klammern werden nicht angezeigt).
- **Stimmen** (ein Tab je Sprache): die Stimme, die die Sprache spricht
  (Deutsch: Thorsten oder Kerstin, Englisch: Ryan oder Lessac), ob sie
  heruntergeladen ist, **Download** (ein zweiter Klick bricht ab) und
  **Anhören** - spricht zwei Beispielsätze mit den Werten des Tabs,
  gespeichert oder nicht, über den Output aus *Einstellungen → Audio*; ein
  zweiter Klick stoppt. Jede Stimme behält eigene Werte, wie sie spricht:
  *Tempo* (0,5-2×), *Tonhöhe* (±6 Halbtöne; Piper kennt keine Tonhöhe, also
  wird die Sprache um den Faktor langsamer erzeugt und dann um ihn höher
  resampelt - die Länge bleibt), *Ausdruck* und *Rhythmusvariation*
  (wie stark Tonfall und Lautlängen variieren, 0-200 %), *Lautstärke* (Anteil
  am Output-Volume, 10-100 %) und *Pause zwischen Sätzen* (0-2 s);
  *Zurücksetzen* setzt einen Wert zurück, *Alle zurücksetzen* alle Werte der Stimme.
  Jede gesprochene Antwort nutzt sie.
- **Einrichtung:** `pip install axross[voice]` (piper-tts, faster-whisper;
  in axross-full enthalten), dann **Download** neben einer Stimme auf der
  Seite Stimme, oder *Hilfe → Funktionen…*, Gruppe **Stimme**, für Stimmen und
  ein Whisper-Modell (gepinnte Checksummen, nach
  `~/.local/share/axross/voice/`).
- **Sicherheit:** Bestätigungen werden immer geklickt, nie gesprochen; im
  paranoiden Security Mode ist das Mikrofon aus; Audio und Transkripte
  bleiben im Speicher.

## Mail-Docks und Mail-Projekte

**Tools → Mail-Docks…** richtet Agenten ein, die je ein Postfach beobachten (ein
gespeichertes IMAP-, POP3- oder Exchange-Profil und ein Ordner). Jedes Dock hat ein
eigenes Panel: was es beobachtet, wann es wieder läuft, sein Log (mit jedem
Tool-Aufruf seines Agenten), *Jetzt ausführen*, *Stopp* (beendet den laufenden
Durchgang; eine Mail, die auf deine Antwort wartet, wird nicht gesendet), *Pause* (bleibt
beim nächsten Start erhalten, wie *Nach seinem Timer ausführen* in den Einstellungen abzuwählen),
*Einstellungen…* und *Drafts-Ordner öffnen* (die POP3-Entwürfe, in einem Pane). Ein
geschlossenes Dock kommt über **Ansicht → Panels** zurück; das Fenster Mail-Docks legt
Docks an, bearbeitet, zeigt und entfernt sie. Ein Dock braucht ein Postfach. Einstellungen: Intervall, die **Anweisungen** für jeden Lauf,
LLM-Profil, **Sandbox**-Profil (Modell und Agent laufen darin, die Zugangsdaten des
Postfachs nie), die **Sende-Regel** und der SMTP-Server.

- *Nie senden - nur Entwürfe*: Antworten landen im Entwürfe-Ordner (IMAP APPEND mit
  \Draft; POP3: im Entwurfsordner des Docks).
- *Vor jeder Mail fragen*: eine Mail wartet im Panel auf *Senden* / *Nicht senden*
  (nach 30 Minuten ohne Antwort nicht gesendet).
- *Dem Absender ohne Nachfrage antworten*: Antworten an den Absender der beantworteten
  Mail (und an die *erlaubten Empfänger*, Adressen oder `@domain`) gehen sofort raus;
  alle anderen warten auf dein Ja.

Der Agent eines Docks hat nur die Mail-Werkzeuge (`mail_list_new`, `mail_list`,
`mail_read`, `mail_analyse`, `mail_draft`, `mail_send`, `dock_report`) und schreibt keine
Dateien. Mail-Inhalt ist in jedem Ergebnis als nicht vertrauenswürdig markiert; eine
Mail kann weder Empfänger hinzufügen noch die Regel ändern. `dock_report` hinterlässt
einem anderen Dock eine Notiz, die es beim nächsten Lauf liest - die Notiz allein
startet ihn. Ein Lauf ohne neue Mail und ohne Notiz fragt das Modell nichts. Eine Mail
gilt als erledigt, sobald der Agent sie gelesen, analysiert oder beantwortet hat - eine,
die er nur in `mail_list_new` sah, oder eine aus einem fehlgeschlagenen oder gestoppten
Lauf ist beim nächsten Lauf wieder neu. SMTP:
STARTTLS oder TLS mit geprüftem Zertifikat, unverschlüsselt nur zu diesem Rechner; das
Passwort liegt im Schlüsselbund.

**Tools → Mail-Projekt…** importiert `.eml`- und Outlook-`.msg`-Dateien, Outlook-Datendateien
(`.pst`, `.ost`, auch die von Outlook 2013; jede Nachricht als `.eml` mit ihren originalen
Transport-Headern), mbox, Maildir,
ganze Ordner oder den Ordner eines Postfach-Profils in einen Projektordner und analysiert
jede Nachricht offline: Received-Kette mit Verzögerungen, SPF/DKIM/DMARC wie
aufgezeichnet, ein From-Name mit fremder Adresse, abweichende Reply-To- und
DKIM-Domains, Links, deren Text woanders hinzeigt als der Link, und Anhänge (Programme,
Makros, doppelte Endungen, Rechts-nach-links-Zeichen, Inhalt passt nicht zum Namen). Die
Liste ist nach Verdacht sortiert; der Tab *Nachricht* zeigt die Mail selbst mit entschärftem
HTML (keine Skripte, Styles, Frames, Formulare, nichts wird geladen, jeder Link mit seinem
echten Ziel daneben, geöffnet erst nach Nachfrage). *SPF / DKIM / DMARC im DNS prüfen*
(aus, solange nicht gewählt - die Abfragen verraten, welche Domains du ansiehst) prüft
live: SPF für die Adresse des einliefernden Servers, jede DKIM-Signatur gegen den
veröffentlichten Schlüssel, die DMARC-Regel und ihre Ausrichtung; ein Mail-Dock hat
denselben Schalter. *Agent fragen…* öffnet einen Agent-Tab auf dem
Projektordner, nur lesend, mit einem Analyse-Prompt. Im Ordner: jede Nachricht wie
importiert (`messages/<sha256>`), ihr Bericht (`reports/<sha256>.json`), `index.sqlite`,
`index.csv` und `PROJECT.md`.

## Einstellungen

**Bearbeiten → Einstellungen…** (**Strg+,**; unter macOS im Programm-Menü) bündelt
alle Einstellungen von axross in einem Fenster: links die Kategorien,
rechts die Seite der gewählten, darüber ein Feld, das eine Einstellung
über ihren Namen findet (*sudo*, *proxy* oder *zoom* tippen).

| Kategorie | Einstellungen |
|---|---|
| Allgemein | Sprache (gilt ab dem nächsten Start), Layout der letzten Session beim Start wiederherstellen, wann ein Pane aktiv wird (per Klick oder nach 0,5–3 s Maus im Pane), die Tour „Erste Schritte“ beim nächsten Start anbieten (siehe [Handbuch und Touren](#handbuch-und-touren)) |
| Darstellung | Theme, kompakter Modus, einfarbige Symbole, Symbolfarben (*Wie das Theme*; *Eigene Farben in jedem Theme* – auch in Hacker und Amber, die jedes Symbol in einer Farbe zeichnen; *Eine Farbe* nach Wahl), Schriftgröße (Zoom), versteckte Dateien hervorheben und ihre Farbe (eine Farbe, die auf dem Theme schwer lesbar ist, erst nach Rückfrage) |
| Werkzeugleiste | Die Knöpfe nach Kategorie gruppieren, die Farbe jeder Kategorie hinter ihren Knöpfen zeigen, die Farbe jeder Kategorie (Verbindungen, Fenster & Panes, Dateien & Suche, Medien, LLM & Agent, Tools & System, Extensions), *Auf Standard zurücksetzen* |
| Dateien & Panes | Versteckte Dateien anzeigen, Größenlimit beim Öffnen, parallele Übertragungen, RAM-Workspaces (an / aus, Größenlimit, frei gehaltener Speicher) und temporäre Dateien im RAM (gilt ab dem nächsten Start) |
| Netzwerk & Proxy | Der Standard-Proxy, die Ausnahmen (*Kein Proxy für*), ein PAC-Skript, ein Test |
| LLM-Profile | Die LLM-Server des Agent-Docks und des Docks *Analyse (sift)*; *Modelle abrufen* öffnet eine Liste mit Größe, Parametern, Quantisierung und dem geladenen Modell, soweit der Server sie meldet |
| Analyse (sift) | Automatische Analyse der gewählten Datei (aus: eine Auswahl nennt die Datei nur, *Analysieren* erklärt sie), das LLM-Profil von *Mit LLM analysieren* (das aktive oder ein eigenes – der Agent behält seine Wahl), höchstens gelesene Bytes pro Datei (begrenzt auch die Kopie einer Remote-Datei), Zeitbudget pro Datei, Vision, Kontext-Tokens (0 = was der Server meldet), Tags pro Datei, Kategorien (eine pro Zeile), Ergebnisse von sift im Cache behalten, *Cache leeren*; die Version von sift, oder ein Link auf *Hilfe → Funktionen…*, wenn dieser Build kein sift hat |
| Agent | Allgemein, Prompts, Zugriff, Sandboxes, MCP-Server, MCP-Quellen, Sessions |
| Stimme | Antworten vorlesen, gesprochene Sprache, die Stimme jeder Sprache (Download, Anhören) und wie sie spricht (Tempo, Tonhöhe, Ausdruck, Rhythmusvariation, Lautstärke, Pause zwischen Sätzen), Mikrofon-Modus, Haltetaste, erkannten Text einfügen oder senden, die Pause, die das Sprechen beendet |
| Audio | Audio-Backend (Automatisch, PipeWire, PulseAudio; das Backend dieses Laufs wird gezeigt, eine Änderung gilt ab dem nächsten Start), Output-Device und Volume (skaliert alles, was axross abspielt) mit *Testton abspielen*, Input-Device und Volume (Gain) mit *Mikrofon testen* (eine Pegelanzeige) und *3 s aufnehmen und abspielen*, das Ergebnis der Audio-Prüfung und *Audio erneut prüfen* |
| Metadaten | Wie *Metadaten entfernen* schreibt, vorher fragen |
| Suche | Gleichzeitig durchsuchte Hosts von *Auf Netzwerk-Hosts suchen*; wo der Offline-Index und der Index des Duplicate Finders liegen |
| Sicherheit | Paranoider Sicherheitsmodus (bleibt für den nächsten Start; `AXROSS_SECURITY_MODE` in der Umgebung hat Vorrang), das sudo-Passwort merken |
| Extensions | Welche Extensions eingeschaltet sind |
| Updates | Beim Start nach Updates suchen, Updates automatisch herunterladen, *Jetzt prüfen*, die letzte Prüfung (siehe [Updates](#updates)) |
| Logging | Die Gesamtstufe (DEBUG, INFO, WARNING, ERROR), eine Stufe je Bereich (*Erben*, eine Stufe oder *Aus*; Bibliotheken von Dritten WARNING), Größe und Rotation der Log-Datei, *Ins Terminal loggen (stderr)*, wiederholte Meldungen zusammenfassen, *Auf Standard zurücksetzen* (siehe [Logging](#logging)) |

Die Seite **Analyse (sift)** schreibt `~/.config/axross/analysis.json`;
das offene Dock *Analyse (sift)* übernimmt eine gespeicherte Änderung
sofort und erklärt die gezeigte Datei neu. Die Grenzen sind die von sift
– ein Wert, den sift ablehnen würde (ein Kontext von 100 Tokens, eine
doppelte Kategorie), wird über der Seite genannt, und nichts wird
gespeichert. Die Ergebnisse von sift liegen im Cache `~/.cache/axross/sift`
(`$XDG_CACHE_HOME/axross/sift`, nur für dich lesbar); *Cache leeren*
entfernt dort die Einträge von sift und sonst nichts. Eine beschädigte
`analysis.json` wird wie die Standardwerte gelesen und bleibt als
`analysis.json.unreadable-…` daneben liegen, bevor das nächste Speichern
sie ersetzt.

Die Seite **Audio** greift erst auf Qt Multimedia zu, wenn die
Audio-Prüfung (ein eigener Prozess) geantwortet hat; scheitert sie,
nennt die Seite den Grund, die Tests bleiben aus, und das Backend lässt
sich trotzdem wählen und speichern. Ein gespeichertes Gerät, das nicht
eingesteckt ist, bleibt als *(nicht verbunden)* in seiner Liste – bis
es wieder da ist, spielt das Standardgerät des Systems. Ein Gerät, das
bei offener Seite eingesteckt wird, erscheint sofort.

**OK, Übernehmen, Abbrechen** gelten auf jeder Seite gleich: geschrieben
werden nur Seiten, deren Werte geändert wurden; *OK* und *Übernehmen*
prüfen zuerst jede geänderte Seite und speichern gar nichts, solange
eine ein Problem hat (diese Seite wird gezeigt, das Problem steht
darüber); dann wird jede geänderte Seite gespeichert und wirkt sofort.
*Abbrechen*, Esc und das [x] verwerfen, was nicht übernommen wurde.

### Logging

Die Seite **Logging** bestimmt, was ins Log kommt – ohne es
vollzuschreiben. Jeder Teil von axross gehört zu genau einem Bereich:
Anwendung, Protokolle (ein Eintrag je Familie: SFTP / SSH / SCP / rsync,
SMB / DFS, FTP / TFTP, WebDAV, Cloud-Speicher, NFS / iSCSI, Mail / News,
WinRM / WMI, Datenbanken, Git / SVN, Geräte, Altprotokolle,
Verbindungen & Proxy), Lokale Dateien, Übertragungen, Indexierung /
Suche, Analyse, Agent / LLM, MCP (Client und Server), Skripte, Medien /
Audio / Stimme, Update, Sicherheit, Terminal, Extensions, Oberfläche und
Bibliotheken von Dritten (paramiko, smbprotocol, urllib3 und requests,
die Cloud-SDKs, Pillow, asyncio, …). Ein Bereich steht auf *Erben* (die
Stufe des Bereichs darüber, ganz oben die Gesamtstufe), DEBUG, INFO,
WARNING, ERROR oder *Aus*. Die Gesamtstufe ist INFO; Bibliotheken von
Dritten stehen auf WARNING, DEBUG für SMB zeigt also die SMB-Schritte von
axross, nicht jedes Paket der Bibliothek. Ein Bereich auf DEBUG verfolgt
ein Problem dort, während der Rest auf INFO bleibt – seine Debug-Zeilen
entstehen gar nicht erst, solange der Bereich leiser steht.

Die Log-Datei ist `~/.local/state/axross/logs/axross.log` (nur für dich
lesbar); sie rotiert bei 5 MiB und behält 3 rotierte Dateien – beides
wird auf der Seite eingestellt (1–100 MiB, 1–20 Dateien). *Ins Terminal
loggen (stderr)* schreibt dieselben Zeilen ins Terminal, aus dem axross
gestartet wurde. *Wiederholte Meldungen zusammenfassen* (an, 10 s): eine
Meldung, die einer vor weniger als dieser Zeitspanne geschriebenen
gleicht (gleicher Bereich, gleiche Stufe, gleicher Text und Fehler),
wird gezählt statt geschrieben, die Zahl folgt als eine Zeile,
`Last message repeated 999 more times in 10.0 s: ...` – ein Timer, der
alle 10 ms scheitert, ergibt zwei Zeilen je Zeitspanne, nicht hundert
pro Sekunde. *Auf Standard zurücksetzen* zeigt die Standardwerte; *OK*
oder *Übernehmen* speichert sie. Jede Änderung wirkt sofort und steht in
`~/.config/axross/logging.json`.

`--debug` auf der Kommandozeile setzt für diesen Lauf jeden Bereich von
axross auf DEBUG und schreibt ins Terminal; `--verbose` hebt jeden
Bereich auf mindestens INFO, ebenfalls mit Ausgabe im Terminal.
Bibliotheken von Dritten behalten dabei ihre Stufe, und die Seite sagt,
solange ein solches Flag gilt.

*Tools → Netzwerk & Proxy…, LLM-Profile…, Agent-Einstellungen…, MCP-Server…,
Metadaten-Einstellungen…* und *Extensions → Extensions verwalten…* öffnen das
Fenster *Einstellungen* auf ihrer Seite. *Ansicht → Versteckte Dateien
anzeigen* (**Strg+H**), *Ansicht → Theme* und *Ansicht → Vergrößern /
Verkleinern / Normale Größe* bleiben schnelle Schalter; sie werden
sofort gespeichert, wie die Seite.

## Updates

**axross-base und Packs.** `axross-base` enthält nur den Kern; jedes pip-Extra, jede
mitgelieferte Erweiterung und die Feature-Gruppen sind *Units*, die es aus seinem eigenen
Release nachlädt: *Hilfe → Funktionen… → Packs…* listet sie mit Downloadgröße; *Hinzufügen* holt
die Wheels der Unit (aus dem Release, sonst dieselbe Datei von PyPI) und prüft Signatur,
Pack-Manifest und die SHA-256 jedes Wheels, bevor etwas entpackt wird; *Entfernen* löscht,
was keine andere Unit braucht. Eine Unit aus reinen Python-Wheels ist sofort nutzbar;
eine mit nativem Wheel und das Entfernen wirken beim nächsten Start. Ein Update des
Binaries bringt die installierten Units des neuen Releases mit, bevor das Binary geholt
wird; wurde das Pack-Manifest des Releases neu ausgestellt (dieselbe Version, ein Pack
repariert), bietet *Hilfe → Funktionen…* *Packs aktualisieren* an, genauso geprüft.

Die One-File-Binaries (`axross-full`, `axross-slim`, das macOS- und das
Windows-`axross-slim`) aktualisieren sich aus den GitHub-Releases von
`c0decave/axross`:

- **Check beim Start.** Einmal pro Start, etwa zwei Sekunden nachdem das
  Fenster erscheint, fragt axross die GitHub-API nach dem neuesten
  Release: ein https-Request, im Hintergrund; der Start wartet nie darauf. Eine
  neuere Version erscheint als **Update auf X.Y.Z installieren…** rechts in der
  Statusleiste und im *Hilfe*-Menü. Ein gescheiterter Check (kein Netz,
  GitHubs Rate Limit) ist eine Zeile im Log und der Status auf *Einstellungen →
  Updates*, nie ein Dialog. Releases mit Draft- oder Prerelease-Markierung
  werden ignoriert.
- **Hilfe → Nach Updates suchen…** prüft sofort und zeigt die Antwort, auch
  wenn axross aktuell ist.
- **Das Update-Fenster** zeigt diese und die neue Version, die Release
  Notes (als Markdown dargestellt; Bilder und andere Ressourcen darin
  werden nie geladen, HTML darin erscheint als Text, und nur http- und
  https-Links öffnen sich, im Browser) und einen Link zur Release-Seite
  und bietet **Herunterladen und installieren**, **Diese Version überspringen** (für diese Version kein Hinweis mehr;
  von Hand gefragt, wird sie trotzdem angeboten) und **Später erinnern**
  (kein Hinweis bis zum nächsten Start).
- **Herunterladen und installieren** lädt das Binary dieses Builds (axross-full
  bekommt axross-full, ein Slim-Build sein Slim-Binary), prüft dessen
  SHA-256 gegen die `SHA256SUMS` desselben Release (und gegen GitHubs
  eigenen Digest der Datei) und lehnt alles ab, was nicht passt - dann
  wird nichts ersetzt, und die Teildatei wird gelöscht. Vorher muss die
  `SHA256SUMS` selbst gültig signiert sein: `SHA256SUMS.sig` ist eine
  Ed25519-Signatur mit dem axross-Release-Key, dessen Public Key in axross
  eingebaut ist. Ein Release ohne sie, oder mit einer, die nicht
  verifiziert, wird abgelehnt („The update is refused: release X.Y.Z is
  not signed with the axross release key“) – wer das Release ändern kann,
  kann dessen Checksummen ändern, aber nicht diese Signatur erzeugen. Eine geprüfte
  Datei ersetzt das laufende Binary mit einem atomaren Rename, mit den
  Permissions der alten Datei; die alte bleibt daneben als
  `<name>.previous`. Sie wirkt ab dem nächsten Start; **Jetzt neu starten**
  schließt axross (es fragt nach ungespeicherter Arbeit wie bei jedem
  Schließen) und startet die neue Version.
- **Ein Ordner ohne Schreibrecht** (ein von root installiertes Binary)
  wird nicht angefasst: die geprüfte Datei landet in
  `~/.cache/axross/update/`, und **Speichern unter…** legt eine Kopie ab, wo du
  willst.
- **Windows** kann ein laufendes Programm nicht ersetzen: die neue Version
  wird neben der alten als `axross-slim-windows-x64-X.Y.Z.exe` gespeichert;
  axross schließen und die alte Datei durch sie ersetzen (oder die neue
  starten).
- **Eine Python-Installation** (pip oder ein Source-Checkout) wird nie
  ersetzt; das Fenster nennt `pip install -U axross`.

*Einstellungen → Updates*: **Beim Start nach Updates suchen** (an), **Updates automatisch herunterladen** (aus: der Hinweis bietet den Download an; an:
eine beim Start gefundene Version wird im Hintergrund geladen, geprüft und
installiert und wartet auf den nächsten Start), **Jetzt prüfen** und Zeit und
Ergebnis des letzten Checks. Kontaktiert werden nur `github.com`,
`api.github.com` und `release-assets.githubusercontent.com`, über https;
jeder Redirect wird gegen diese Liste geprüft. Der Default-Proxy
(*Netzwerk & Proxy*) wird benutzt; ohne ihn `https_proxy` aus dem
Environment. Der Check beim Start läuft nicht mit
`AXROSS_NO_UPDATE_CHECK=1` im Environment oder im Paranoid Security Mode;
*Jetzt prüfen* funktioniert trotzdem.

## Konfigurationsdateien

- `~/.config/axross/profiles.json` — Verbindungsprofile (`0o600`).
- `~/.config/axross/bookmarks.json` — Bookmark-Bar.
- `~/.config/axross/session.json` — Pane-Layout, Window-Geometry und
  Dock-Layout beim letzten Beenden; beim Start wiederhergestellt,
  außer *Beim Start das Layout der letzten Session wiederherstellen*
  (Einstellungen → Allgemein) ist aus. Das `window`-Objekt hält auch das Aussehen (Theme,
  kompakter Modus, einfarbige Symbole, Schriftgröße, versteckte Dateien hervorheben) und die Sprache.
- `~/.config/axross/settings.json` — kleine Einstellungen: Größenlimit
  beim Öffnen, Pane-Aktivierung, wie Metadaten entfernt werden und ob vorher gefragt wird, das sudo-
  Passwort merken, gleichzeitig durchsuchte Hosts, der Sicherheitsmodus, die
  Update-Einstellungen (`update_check_at_start`, `update_auto_download`,
  eine übersprungene Version, die letzte Prüfung), ob der nächste Start die
  Tour „Erste Schritte“ anbietet (`offer_tour_at_start`).
- `~/.config/axross/proxy.json`, `llm.json`, `extensions.json` — Standard-
  Proxy, LLM-Profile, eingeschaltete Extensions (Secrets im Keyring).
- `~/.config/axross/agent/voice.json` — die Einstellungen der Stimme (`0o600`).
- `~/.config/axross/audio.json` — die Audio-Einstellungen: Backend,
  Ausgabe- und Eingabegerät, Lautstärken (`0o600`).
- `~/.config/axross/column_prefs.json` — Spaltenbreiten und
  ausgeblendete Spalten, eine Datei für alle Panes.
- `~/.config/axross/agent/settings.json` — Agent-Einstellungen (Modi, Zugriff,
  Sandbox-Profile, MCP-Server; `0o600`).
- `~/.config/axross/agent/sessions/` — eine JSON-Datei je behaltenem Agent-Tab (`0o600`).
- `~/.config/axross/<provider>_token.json` — OAuth-Refresh-Tokens (`0o600`).
- `~/.config/axross/ramfs.json` — RAM-Workspace-Einstellungen. `"tmpfs_enabled": true`
  legt jede Temp-Datei des Prozesses (Download-/Upload-Buffer ab 8 MiB,
  Archiv-Entpacken, FUSE-Write-Buffer) auf eine RAM-Disk (`/run/user/$UID`,
  sonst `/dev/shm`) statt auf die Platte: nichts landet auf der Platte, aber
  es kostet RAM, daher standardmäßig aus. Ein im Environment gesetztes
  `TMPDIR` gewinnt immer.
- Eine Konfigurationsdatei, die kein gültiges JSON ist (eine misslungene
  Handänderung), wird nie überschrieben: axross behält sie als
  `NAME.unreadable-<Zeit>-<id>` daneben und beginnt die Datei neu; eine,
  die es gar nicht lesen kann (Rechte), wird nicht geschrieben.
- `~/.config/axross/logging.json` — die Logging-Einstellungen: Gesamtstufe, Stufe je Bereich,
  Größe und Rotation der Log-Datei, Terminal, Zusammenfassen wiederholter Meldungen
  (`0o600`).
- `~/.local/state/axross/logs/axross.log` — rotierendes Logfile (5 MiB, 3 rotierte
  Dateien, sofern *Bearbeiten → Einstellungen… → Logging* nichts anderes sagt; `0o600`).

## Wo es weitergeht

- **Nur verbinden?** [OAUTH_SETUP.md](../OAUTH_SETUP.md) führt durch
  die Cloud-Storage-App-Registrierungen.
- **Auf feindlichen Netzen?** [OPSEC.md](OPSEC.md) listet jeden
  Client-zu-Server-Fingerprint, den axross sendet, plus Mitigations.
- **axross von einem LLM aus steuern?** [MCP_de.md](MCP_de.md) ist
  die kanonische Protokoll-Referenz.
- **Extensions schreiben oder einschalten?** [EXTENSIONS.md](EXTENSIONS.md)
  erklärt Vertrauen, Pausieren und die `api` der Extensions (englisch).
- **Bauen oder beitragen?** [DEVELOPMENT.md](DEVELOPMENT.md) hat
  Test-Suite, Lab-Compose und Coverage-Matrix.
