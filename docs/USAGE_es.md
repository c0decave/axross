# Uso de Axross

Esta guía cubre lo que puedes hacer con Axross una vez que está
corriendo. Para la instalación, ver [INSTALL.md](../INSTALL.md); para
el manual completo en alemán, ver [HANDBUCH.md](HANDBUCH.md).

Idiomas: [English](USAGE.md) · [Deutsch](USAGE_de.md) · **Español**

## De un vistazo

Axross es un gestor de ficheros estilo Total Commander para 22
protocolos, construido en torno a tres ideas:

- **Layout multi-panel.** Divide horizontal o verticalmente en
  cuantos panels quieras; cada panel se conecta a su propio backend
  (local, SFTP, S3, IMAP, lo que sea).
- **Primitivas agnósticas al backend.** Papelera, escrituras
  atómicas, overlays cifrados, línea temporal de versiones,
  almacenamiento direccionable por contenido — todo funciona en
  cada protocolo, incluso aquellos cuya API nativa no lo soporta.
- **Modo servidor MCP.** Axross puede correr headless y exponer
  cualquier backend configurado como herramientas MCP, de modo que
  un cliente LLM puede manejarlo. Solo lectura por defecto;
  `--mcp-write` opt-in para mutaciones.

## Conexiones

El Connection Manager (Ctrl+N) es el sitio para crear perfiles. Cada
perfil selecciona un protocolo y guarda host / usuario / autenticación
/ proxy / opciones por protocolo. Los campos sensibles (passwords,
secretos OAuth, cadenas de conexión Azure) van al keyring del SO; el
JSON de perfil mismo nunca lleva credenciales en plano.

- **Verificación de host-key.** El primer contacto SSH muestra un
  diálogo con el fingerprint SHA-256 antes de conectar; las claves
  confiadas persisten en `~/.ssh/known_hosts`.
- **Flujos OAuth.** OneDrive / SharePoint / Google Drive / Dropbox
  abren un navegador para el paso de consent. Los tokens se cachean
  en `~/.config/axross/<provider>_token.json` con `0o600` desde el
  origen. Los proxies de perfil cubren el tráfico API/token que
  controla Axross; la página externa de consent del navegador puede
  usar la configuración proxy del navegador o del sistema. Receta de
  registro de app por proveedor:
  [OAUTH_SETUP.md](../OAUTH_SETUP.md).
- **Soporte de proxy.** Por perfil SOCKS5 / SOCKS4 / HTTP-CONNECT
  para backends con un hook de transporte real. SOCKS5 resuelve
  nombres de host en el lado del servidor (sin fuga DNS). SOCKS4
  depende del transporte: los backends raw-socket pueden usar SOCKS4a
  para resolución remota, mientras que stacks HTTP SDK pueden resolver
  localmente. Usa SOCKS5 si importa evitar fugas DNS. Los backends sin
  soporte SOCKS/HTTP limpio avisan en vez de ignorar campos de proxy
  en silencio. S3 solo usa HTTP-CONNECT; Rsync puede pasar
  `proxy_username` mediante OpenBSD `nc`, pero no `proxy_password`.
  Las sesiones SDK basadas en requests que controla Axross ignoran
  `HTTP_PROXY` / `HTTPS_PROXY` del entorno del proceso; el perfil es
  la fuente de la ruta.
- **Overrides OpSec.** Los campos de perfil controlan keepalive
  SSH, nombre de workstation SMB, NAWS de Telnet, stripping de
  metadata rsync. Ver [OPSEC.md](OPSEC.md) para el modelo de
  amenazas.

## Layout multi-panel

- Añade panels con **Ctrl+T**, divide con **Ctrl+Shift+H** /
  **Ctrl+Shift+V**, cierra con **Ctrl+W**.
- El panel activo lleva borde azul; el panel **destino** (donde
  aterrizan las copias) lleva borde verde. El último panel
  enfocado se vuelve destino.
- Un panel se vuelve activo cuando el ratón descansa en él 1 s.
  **View → Activate Pane** fija 1, 2 o 3 s, u **On Click**. El foco del
  teclado solo sigue desde la lista de archivos de otro panel, nunca
  desde un campo de texto.
- **Alt+Izq / Alt+Der** recorren la historia de panels;
  **Ctrl+Tab** cicla.
- Drag-and-drop entre panels inicia una transferencia (funciona
  para local↔remoto, remoto↔remoto, cross-protocolo).

### El layout vuelve al arrancar

Al cerrar, axross guarda el layout en `session.json`; el siguiente
arranque lo reconstruye automáticamente:

- el árbol de splitters con sus tamaños, la geometry de la ventana, el
  layout de los docks (cuáles están abiertos y dónde) y el theme;
- los panels locales en sus carpetas — una carpeta borrada desde
  entonces abre la carpeta home, sin diálogo;
- los panels de terminal locales como una shell nueva en el mismo
  sitio, en la carpeta donde estaba la shell anterior (home si ya no
  existe).

**Un arranque nunca conecta.** Un panel o terminal de un profile de
conexión guardado vuelve como placeholder, *Not connected —
&lt;profile&gt;*, con un botón **Reconnect**. En un panel de archivos,
Reconnect conecta igual que abrir el profile desde Quick Connect
(prompt de password, comprobación de host key) y pone el panel donde
estaba el placeholder, en su carpeta guardada. En un terminal abre el
terminal del profile como lo hace un layout preset (password guardado,
sin prompt). El restore no ejecuta scripts ni extensions, y el
Paranoid Security Mode no cambia.

**File > Restore Layout on Start** (activado por defecto) lo desactiva;
la elección se guarda en `session.json` al momento y un arranque
muestra entonces el layout por defecto con un solo panel. Un
`session.json` ausente, ilegible o inválido también arranca con el
layout por defecto; el motivo queda en el log. **File > Restore Last
Session** (**Ctrl+Shift+R**) sigue reconstruyendo el layout guardado
a petición, y ahí los panels remotos sí conectan.

## Transferencias

Cada copia o movimiento entre panels entra a la cola de transferencias.
El dock inferior muestra progreso, throughput y ETA. Las
transferencias corren en threads worker y sobreviven a un diálogo
rechazado o un panel cerrado.

- **Semántica atómica.** Cada escritura va a un fichero temporal
  hermano (`.tmp-<hex>.tmp`) y se renombra en su sitio al final. En
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync el
  upload subyacente ya es atómico; en el resto el rename es el
  punto de commit.
- **Resume.** Las transferencias fallidas pueden reanudarse; los
  bytes parciales en el destino se retoman donde quedaron.
- **Retry.** "Retry Failed" reintenta cada transferencia en estado
  de error.
- **Verify.** El flag `verify_checksum` por job re-hashea el
  destino tras el upload y rechaza en caso de mismatch.

## Capa de funcionalidades del filesystem

Estas primitivas funcionan en **cualquier** backend, incluso aquellos
cuyo protocolo nativo no las soporta.

| Módulo | Qué proporciona |
|---|---|
| `core.atomic_io` | `atomic_write(backend, path, data)` — atómico-nativo en S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync; tmp-then-rename en el resto. |
| `core.atomic_recovery` | Sweep de crash-recovery para `.tmp-*.tmp` huérfanos. Hook por panel al navegar borra restos de más de 1 h. El prefijo legacy `.axross-atomic-*.tmp` se sigue reconociendo. |
| `core.server_ops` | `server_side_copy` / `server_side_move` con fallback automático a `open_read` + `open_write` cuando el backend no tiene copy nativo. |
| `core.watch` | API de file-watching. inotify nativo en LocalFS (con watchdog); polling en el resto. Toggle en la path bar. |
| `core.trash` | Papelera universal: `trash` / `list_trash` / `restore` / `empty_trash`. Sidecar metadata por entrada, sin manifest central. |
| `core.xlink` | Symlinks entre protocolos vía ficheros JSON pointer `.axlink`. |
| `core.encrypted_overlay` | Cifrado at-rest AES-256-GCM con PBKDF2-HMAC-SHA256 (200 k iteraciones). |
| `core.cas` | Capa direccionable por contenido: índice SQLite `(backend, path) → checksum`, detección de duplicados, URLs `ax-cas://<algo>:<hex>`. |
| `core.snapshot_browser` | Vista de timeline uniforme sobre S3, Dropbox, GDrive, OneDrive, Azure Blob. |
| `core.metadata_index` | Búsqueda offline SQLite por nombre / ext / tamaño / mtime. |
| `core.previews` | Thumbnailer local de imágenes con allow-list MIME, caps de tamaño y gate del límite de allocation Qt. F3 / doble-click. |
| `core.archive` | Extracción segura de zip / tar / 7z (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .7z`). Guards contra zip-slip / bomba / metadata mentirosa; `.7z` requiere el extra `[archive]`. |
| `core.elevated_io` | Lectura local con privilegios vía `pkexec` — Axross nunca mantiene el privilegio. Entrada "Open as root…" en el menú contextual. |
| `core.fuse_mount` | Montaje FUSE de cualquier FileBackend. Solo lectura por defecto; `writeable=True` habilita create / write / unlink / mkdir / rename. Extra opcional `[fuse]`. |
| `core.mcp_server` | Servidor MCP JSON-RPC con framing stdio que expone el backend configurado como herramientas. `--mcp-write` añade herramientas mutadoras, capadas a un root a prueba de path-traversal. |

## Acciones del menú contextual

| Acción | Trigger | Qué hace |
|---|---|---|
| Nueva carpeta | Click derecho | `backend.mkdir(path)` en cada backend con escritura. |
| Nuevo fichero… | Click derecho | Fichero de cero bytes vía `backend.open_write(path).write(b"")`. |
| Nuevo symlink… | Click derecho | Dos prompts. Visible solo en backends con `supports_symlinks=True`. |
| Nuevo hardlink… | Click derecho | Misma forma; cross-device → `OSError(EXDEV)`. |
| Find in Index | `Ctrl+Shift+F` | Búsqueda en el índice offline de metadata. |
| Duplicate Finder | Menú View | Agrupar por hash de contenido, copiar URLs `ax-cas://…`; mover las copias seleccionadas a la papelera de axross tras comprobar en vivo que queda otra copia real. |
| View Media… / View Selected Media… | Click derecho, menú View | Imágenes, PDFs y vídeos de la carpeta (opcionalmente recursivo) o de la selección como grid overview, visor para ir pasando o slideshow — ver *Editores y visores*. |
| Show / Remove / Export Metadata… | Click derecho | EXIF / GPS / XMP / IPTC, propiedades de Office, info de PDF, tags de audio / vídeo de la selección — o de toda la carpeta si no hay nada seleccionado (subcarpetas opcionales) — ver *Metadata de ficheros*. |
| Move to Trash | Click derecho | Papelera universal. |
| Show Trash… | Click derecho | Diálogo restaurar / borrar permanentemente. |
| Show Versions… | Click derecho | Snapshot browser — Save Version As, Restore as Current. |
| Show Checksum… | Click derecho | Checksum nativo (S3 ETag, Drive md5, ssh sha256sum…) con fallback a stream-hash. |
| Extract to folder… | Click derecho sobre archivo soportado | Carpeta hermana del mismo nombre, cancelable, con los guards de `core.archive`. Solo backends locales. |
| Encrypt / Decrypt con passphrase | Click derecho | AES-256-GCM. |
| Open as root… | Click derecho | Solo local; routea a `pkexec`. Oculto si polkit/pkexec faltan. |
| Create XLink… | Click derecho | Fichero pointer cross-protocolo. |
| Mount as FUSE (read-only / read-write)… | Click derecho | Dos entradas para que el modo de mount sea visible al frente. Cambia a "Unmount FUSE" mientras está montado. |
| Batch Rename… | Click derecho (multi-selección) | Find/Replace o regex con preview en vivo + rename atómico. |
| Permissions… | Click derecho | Diálogo chmod con grid de checkboxes + input octal. |

## Path bar

- **Auto-refresh ◉** suscribe el panel a `core.watch`; refresh
  debounced en cambios del backend.
- **Filtro en vivo** escribe en la path bar para filtrar el listado
  en tiempo real.
- **Marcadores** como dock izquierdo; F8 marca el path actual, F12
  alterna el dock. Las carpetas arrastradas desde un pane al dock
  (espacio libre, un grupo o entre dos entradas) se convierten allí en
  marcadores, las remotas con su connection profile. Los ficheros y
  carpetas soltados *sobre* un marcador se mueven a su carpeta (Ctrl
  copia), con la misma comprobación de nombres existentes que F5 / F6;
  una carpeta que falta o un remoto que no responde se notifica y no se
  encola nada, y un marcador remoto sin conexión abierta conecta
  primero y luego transfiere.

## Editores y visores

- **Editor de texto** (incorporado) — para ficheros < 1 MB, con
  detección de conflictos al guardar.
- **Editor hex** — solo lectura; útil para triage en ficheros
  remotos.
- **Visor de imágenes** — F3 / doble-click, allow-list MIME,
  caps de tamaño.
- **Media viewer** — *View → View Media…* o click derecho → *View
  Media…* sobre la carpeta (*View Selected Media…* para una
  selección de ficheros y carpetas). Se eligen los tipos (imágenes
  incl. SVG, PDFs, vídeos vía QtMultimedia), si se incluyen
  subcarpetas (profundidad 1–32; como máximo 5000 ficheros, las
  carpetas symlink no se siguen, las ilegibles se saltan y se
  cuentan) y cómo empezar: **Overview first** (grid de thumbnails
  con filtro, orden por nombre / fecha / carpeta y slider de
  tamaño; Enter o doble-click abre), **Start slideshow** o **Click
  through**. En el visor: Izquierda / Derecha / PageUp / PageDown /
  Space avanzan (se paran en el primer y último elemento; dentro de
  un PDF pasan páginas y tras la última van al siguiente elemento),
  Home / End, F11 fullscreen, Ctrl+M maximize / restore (la ventana
  recuerda tamaño, posición y estado maximize para la próxima
  apertura), rueda o `+` / `-` zoom, `F` fit, `1`
  100 %, `R` rotar, `S` slideshow (intervalo en segundos; la
  slideshow da la vuelta, un vídeo se reproduce hasta el final), Esc
  vuelve a la overview, otro Esc cierra. Funciona en cualquier
  backend: los ficheros remotos se copian a un directorio temporal
  privado hasta el *Open Size Limit* y se borran después; un
  elemento demasiado grande, cifrado o roto muestra el motivo. El SVG
  solo se renderiza sin DOCTYPE/entidades, scripts ni referencias
  fuera del fichero. El modo `paranoid` bloquea el visor.
  `I` (o el botón *Info*) muestra la metadata del elemento actual en
  un panel lateral, con *Remove metadata* — también en el visor de
  imágenes.
- **Terminal SSH** — dock con pestañas junto a la cola de
  transferencias. PTY local (`pty.fork()`) y SSH-remoto via
  paramiko están ambos disponibles; la variante SSH reusa la
  conexión existente en lugar de abrir una nueva.

## Metadata de ficheros

Click derecho → **Show Metadata…**, **Remove Metadata…** o **Export
Metadata…** actúa sobre los ficheros y carpetas seleccionados o, sin
selección, sobre la propia carpeta. La ventana de metadata muestra una
fila por fichero con sus campos uno tras otro como `key: value`; doble
clic o clic derecho → *Properties…* abre todos los campos de ese fichero,
agrupados y uno por línea, y clic derecho → *Remove Metadata* limpia solo
los ficheros seleccionados. Tiene filtro, *Copy* (los campos de los
ficheros seleccionados como texto), *Export…* (JSON o CSV) y *Remove
Metadata* para todos los ficheros listados. Las carpetas se
leen sin bajar; *Include subfolders* entra en las subcarpetas (como
máximo 5000 ficheros, profundidad 8, las carpetas symlink no se siguen).
Leer y eliminar corren en segundo plano con progreso y *Cancel*. En los
visores de imágenes y de media, `I` abre la misma información como panel
lateral.

| Tipo | Lectura | Se elimina | Se conserva |
|---|---|---|---|
| JPEG, PNG, WebP, GIF | incluido | EXIF (GPS, cámara, números de serie, fechas, autor, software), thumbnails embebidos, XMP, IPTC, comentarios, chunks de texto PNG, datos tras la imagen | orientación EXIF, perfil de color ICC; los píxeles nunca se recodifican y se comprueba que son idénticos |
| TIFF | incluido | lo mismo, con un guardado sin pérdida | orientación, perfil ICC; un TIFF con compresión JPEG se rechaza |
| docx / xlsx / pptx, odt / ods / odp | incluido | `docProps/core.xml`, `app.xml`, `custom.xml`, `meta.xml` de ODF, el comentario del zip | todas las demás partes, que descomprimen a los mismos bytes |
| PDF | pypdf, si no QtPdf | diccionario Info, streams XMP, PieceInfo, revisiones anteriores (reescritura completa) | — necesita el extra `[metadata]` (`pip install 'axross[metadata]'`) |
| Audio / vídeo | `ffprobe` | todos los tags y capítulos, data streams (pistas GPS de cámaras), la carátula de los ficheros de audio (`ffmpeg -c copy`, sin recodificar) | los streams |

**Cómo se escribe** — *Tools → Metadata Settings…*:

- **In place** (por defecto): el fichero se reemplaza de forma atómica
  y el original queda en el trash de axross. Una ejecución — un fichero
  o una carpeta entera — es una entrada para *Edit → Undo Last
  Operation* (`Ctrl+Z`), que devuelve cada original byte a byte, pero
  solo mientras el fichero contenga exactamente lo que escribió la
  eliminación.
- **Cleaned copy**: `nombre.clean.ext` junto al original
  (`nombre.clean (1).ext` si ya existe); nunca se sobrescribe nada.

Solo se pide confirmación si allí está marcado *Ask before removing
metadata*. Los ficheros remotos pasan por una copia temporal privada
limitada por el *Open Size Limit* y vuelven por la escritura atómica del
backend; una conexión cuyo trash no se puede escribir recibe una copia
limpia en su lugar, y el resultado lo indica. Un fichero que cambia
mientras se limpia no se toca. En modo `paranoid` leer y eliminar
funcionan, salvo audio / vídeo: supondría ejecutar ffprobe / ffmpeg
sobre el contenido del fichero. Scripts: `axross.metadata`,
`axross.remove_metadata`, `axross.export_metadata` (ver
[SCRIPTING_es.md](SCRIPTING_es.md)).

## Dock de Transferencias / Terminal / Log

- La franja inferior tiene tres pestañas: **Transfers**, **Terminal**,
  **Log**. Cada una parpadea ámbar cuando algo pasa fuera de pantalla
  (cambio de estado de transferencia, salida de shell, línea de log).
  Click la levanta y limpia el indicador.
- Click derecho en una transferencia para **Cancel**, **Retry**,
  **Open destination folder**.

## Scripting y REPL embebida

Axross trae una superficie Python curada (``axross.*``) con 89
nombres públicos (verbos + 9 clases de resultado para los
network-helpers). Tres puertas al mismo surface:

- **Dock Console** (menú View) — REPL con entrada multilínea,
  historial, tab-completion, panel lateral con cada función y su
  docstring.
- **Headless** — ``axross --script myscript.py`` corre tu Python
  en el mismo namespace; ideal para cron/CI/lotes.
- **MCP** — si ``--mcp-allow-scripts`` está activo, el surface
  también es alcanzable vía herramientas MCP.

Ejemplos:

```python
b = axross.localfs()
items = b.list_dir("/var/log")[:10]
hits = axross.grep(b, "/var/log", r"kernel:.*panic")

src = axross.open("my-sftp")           # perfil nombrado en Connection Manager
axross.copy(src, "/etc/hosts", axross.localfs(), "/tmp/hosts.bak")

probe = axross.http_probe("https://example.com")
ips = axross.dns_resolve("example.com")
```

Explorar la API:
- ``axross.help()`` — chuleta agrupada por categoría
- ``axross.docs("backend")`` / ``"scripts"`` / ``"slash"`` —
  referencia Markdown por tema
- ``docs/SCRIPTING_REFERENCE.md`` — referencia completa por verbo y clase

Slash-commands de la REPL: ``.help``, ``.scripts``, ``.save
<name>``, ``.load <name>``, ``.run <name>``, ``.delete <name>``,
``.open``.

Listas detalladas de verbos en **[USAGE.md](USAGE.md)** (EN) o
``docs/SCRIPTING_REFERENCE.md``.

### UI helpers — message / confirm / toast

Los scripts + REPL pueden mostrar diálogos modales y toasts que
**caen limpiamente a stdout/stdin sin Qt event loop** (el mismo
script funciona en cron/CI):

```python
axross.message("Backup terminado (123 ficheros copiados)",
               level="success")

if axross.confirm("¿Borrar 47 ficheros? Irreversible.",
                  default_yes=False):
    for p in doomed:
        backend.remove(p)

axross.toast("Conexión perdida — reintentando", level="error")
axross.toast("1,2 MB guardados", level="success", timeout=2)
```

Niveles: ``"info"`` (azul), ``"success"`` (verde), ``"warning"``
(amarillo), ``"error"`` (rojo) — cada uno con icono SVG de estado
incrustado y el glifo de axross como icono de ventana.

El prompt headless de ``confirm()`` solo pregunta cuando stdin es un
terminal. Sin nadie que responda — cron, una pipe, el proceso hijo del
Scripts dock, un ``script_run`` de MCP o ``AXROSS_NONINTERACTIVE=1`` —
lanza ``axross.NonInteractiveError`` en vez de usar el valor por
defecto; ``assume_yes=True`` responde que sí sin preguntar.

## Multiplexado de terminal SSH/SCP

Cuando te conectas vía SSH o SCP, axross abre **una** conexión TCP
+ Transport paramiko. Las operaciones siguientes se multiplexan
sobre ese transport:

- **SFTP/operaciones de archivo** corren en un canal dedicado.
- **Open Terminal** (dock terminal) reserva un canal adicional con
  PTY — shell interactiva completa, sin segundo login, sin
  segundo desafío de clave. Igual para SSH y SCP.

Una pane SCP obtiene el mismo click derecho "abrir terminal remota
aquí" que una pane SSH, sobre la misma conexión.

## Auto-detección y re-detección del keyring

Las contraseñas guardadas van al keyring del sistema (Secret-
Service / KWallet / Windows Credential Locker / macOS Keychain /
plug-in Secret-Service de KeePassXC). Axross sondea un backend
funcional al primer uso. Cualquier otro backend de keyring sirve
también, siempre que no pida nada en la terminal (por ejemplo
keyring-pass o keyrings.cryptfile configurados en ``keyringrc.cfg``);
con varios instalados se usa el que keyring mismo pone primero. Los
ficheros en claro (``PlaintextKeyring``) y el ``EncryptedKeyring`` de
keyrings.alt, que pide su contraseña maestra en la terminal, no se
usan. Sin un backend utilizable, "Save in keyring" queda deshabilitado
con una pista accionable:

- **Arch:** ``sudo pacman -S gnome-keyring`` (o kwallet, o keepassxc)
- **Debian:** ``sudo apt install gnome-keyring``
- **Fedora:** ``sudo dnf install gnome-keyring``

Si arrancas el demonio **después** de axross, usa **File →
Re-detect System Keyring** (o intenta guardar otra vez — el
siguiente ``store_password`` rehace la detección automáticamente).

## Servidor MCP

Axross puede correr como servidor Model Context Protocol de modo que
un cliente LLM (Claude Desktop, Cline, un agente propio) pueda manejar
cualquier backend configurado a través de una superficie de
herramientas JSON-RPC.

```bash
axross --mcp-server                                  # solo lectura, stdio
axross --mcp-server --mcp-write                      # añade tools de escritura (capada a un root)
axross --mcp-server --mcp-http 127.0.0.1:7331        # HTTP, loopback
```

17 herramientas (`list_dir`, `stat`, `read_file`, `checksum`,
`search`, `walk`, `grep`, `list_versions`, `open_version_read`,
`preview` + 7 herramientas de escritura cuando `--mcp-write`),
endpoints `resources/*`, log forwarding por
`notifications/message`, timeouts por herramienta, rate limits
token-bucket por sesión, sesiones HTTP con streaming SSE de
progreso, multi-backend routing opcional.

Referencia completa: **[docs/MCP_es.md](MCP_es.md)** (ES) · [MCP.md](MCP.md) (EN) · [MCP_de.md](MCP_de.md) (DE).

## Ficheros de configuración

- `~/.config/axross/profiles.json` — perfiles de conexión (`0o600`).
- `~/.config/axross/bookmarks.json` — barra de marcadores.
- `~/.config/axross/session.json` — layout de panels, geometry de la
  ventana y layout de docks al cierre; se restaura al arrancar salvo
  que File > Restore Layout on Start esté desactivado.
- `~/.config/axross/column_prefs.json` — anchos de columna por panel.
- `~/.config/axross/<provider>_token.json` — refresh tokens OAuth (`0o600`).
- `~/.local/state/axross/logs/axross.log` — log rotativo (5 MB, 3 backups).

## A dónde ir después

- **¿Solo conectar?** [OAUTH_SETUP.md](../OAUTH_SETUP.md) recorre los
  registros de app de almacenamiento en la nube.
- **¿Operando en redes hostiles?** [OPSEC.md](OPSEC.md) lista cada
  fingerprint cliente-a-servidor que Axross emite y cómo suprimirlo.
- **¿Manejar Axross desde un LLM?** [MCP_es.md](MCP_es.md) es la
  referencia canónica del protocolo.
- **¿Construir o contribuir?** [DEVELOPMENT.md](DEVELOPMENT.md) tiene
  la suite de tests, el compose del lab, y la matriz de cobertura.
- **¿Manual completo en alemán?** [HANDBUCH.md](HANDBUCH.md).
