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
  origen. Receta de registro de app por proveedor:
  [OAUTH_SETUP.md](../OAUTH_SETUP.md).
- **Soporte de proxy.** Por perfil SOCKS5 / SOCKS4 / HTTP-CONNECT.
  SOCKS5 resuelve nombres de host en el lado del servidor (sin
  fuga DNS); SOCKS4 cae a DNS local por diseño del protocolo.
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
- **Alt+Izq / Alt+Der** recorren la historia de panels;
  **Ctrl+Tab** cicla.
- Drag-and-drop entre panels inicia una transferencia (funciona
  para local↔remoto, remoto↔remoto, cross-protocolo).

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
| CAS Duplicate Finder | Menú View | Agrupar por hash de contenido, copiar URLs `ax-cas://…`. |
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
  alterna el dock.

## Editores y visores

- **Editor de texto** (incorporado) — para ficheros < 1 MB, con
  detección de conflictos al guardar.
- **Editor hex** — solo lectura; útil para triage en ficheros
  remotos.
- **Visor de imágenes** — F3 / doble-click, allow-list MIME,
  caps de tamaño.
- **Terminal SSH** — dock con pestañas junto a la cola de
  transferencias. PTY local (`pty.fork()`) y SSH-remoto via
  paramiko están ambos disponibles; la variante SSH reusa la
  conexión existente en lugar de abrir una nueva.

## Dock de Transferencias / Terminal / Log

- La franja inferior tiene tres pestañas: **Transfers**, **Terminal**,
  **Log**. Cada una parpadea ámbar cuando algo pasa fuera de pantalla
  (cambio de estado de transferencia, salida de shell, línea de log).
  Click la levanta y limpia el indicador.
- Click derecho en una transferencia para **Cancel**, **Retry**,
  **Open destination folder**.

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
- `~/.config/axross/session.json` — layout de panels al cierre.
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
