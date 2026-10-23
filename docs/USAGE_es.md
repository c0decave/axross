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

El Connection Manager (Ctrl+Shift+N) es el sitio para crear perfiles;
Quick Connect (Ctrl+N) abre uno guardado. Cada
perfil selecciona un protocolo y guarda host / usuario / autenticación
/ proxy / opciones por protocolo. Los campos sensibles (passwords,
secretos OAuth, cadenas de conexión Azure) van al keyring del SO; el
JSON de perfil mismo nunca lleva credenciales en plano.

- **Features que faltan.** *Help > Features…* lista cada feature
  opcional - conexiones, análisis de ficheros y archivos, herramientas
  externas como ripgrep, rsync o qemu-img, Sleuth Kit, TestDisk /
  PhotoRec y VBoxManage de las extensiones forense y VirtualBox - como
  instalada o ausente, con cómo
  conseguirla. *Install Selected* ejecuta `python -m pip install …` en
  el Python que ejecuta axross tras una pregunta con el comando (la
  salida en el log, casi siempre sin reiniciar); un build congelado
  enlaza la descarga de axross-full de la misma release; una
  herramienta muestra el comando de paquetes de este sistema para
  copiarlo. Elegir un backend con dependencias ausentes, o analizar sin
  sift, ofrece la misma ventana.
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

- Añade panels dividiendo con **Ctrl+Shift+H** /
  **Ctrl+Shift+V**, cierra con **Ctrl+W**.
- El panel activo lleva borde azul; el panel **destino** (donde
  aterrizan las copias) lleva borde verde. El último panel
  enfocado se vuelve destino.
- Un panel se vuelve activo cuando el ratón descansa en él 0,5 s.
  **Edit → Settings… → General → Activate a pane** fija 0,5, 1, 2 o 3 s, u
  **On Click**. El foco del
  teclado solo sigue desde la lista de archivos de otro panel, nunca
  desde un campo de texto.
- **Alt+Izq / Alt+Der** recorren la historia de panels;
  **Tab** / **Shift+Tab** en una lista de archivos ciclan los panels.
- Drag-and-drop entre panels inicia una transferencia (funciona
  para local↔remoto, remoto↔remoto, cross-protocolo).

### Workspaces — varios layouts, en varias pantallas

Un workspace es un layout de paneles propio y con nombre. **Workspace →
New Workspace → With File List** (**Ctrl+Alt+N**) abre uno con un panel
local, **With Terminal** (**Ctrl+Alt+Shift+N**) uno con una shell local; a
partir del segundo, los workspaces aparecen como tabs sobre los paneles.
**Ctrl+Alt+PgDown / PgUp** los cambian, y cada uno conserva su propio
panel de origen y de destino.

- **Varias shells:** **Workspace → Add Terminal Pane** (también en el
  menú del clic derecho del tab) pone otra shell local en el workspace,
  junto a los paneles que ya están.
- **Renombrar:** doble clic en el tab, su menú del clic derecho, o
  **Workspace → Rename Workspace…**.
- **Detach to Window** (menú Workspace o clic derecho en el tab) pone el
  workspace en una ventana propia — por ejemplo en otra pantalla. Al
  cerrar esa ventana, el workspace vuelve como tab.
- **Mover un panel:** **Workspace → Move Pane to Workspace** envía el
  panel activo a otro workspace (o a uno nuevo); o arrastra la cabecera
  del panel sobre un panel de otro workspace o ventana. Los paneles de
  archivos y los de terminal se arrastran igual (un panel de terminal
  también con su botón ⇄); si mantienes un panel arrastrado medio
  segundo sobre un tab de workspace, ese tab se abre, así un panel
  llega también a un workspace en segundo plano.
- **Close Workspace** lo cierra con sus paneles (pregunta antes); al
  cerrarse el último panel de un workspace, se cierra el workspace.
  Siempre queda uno.
- Un layout preset (**View → Layout Preset**) sustituye solo los
  paneles del workspace actual.
- Todos los workspaces — nombres, orden, el actual, layouts con sus
  terminales y carpetas, cuáles están separados y dónde están sus
  ventanas — vuelven en el siguiente arranque (ver abajo).

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

*Restore the layout of the last session on start* (**Edit → Settings… →
General**, activado por defecto) lo desactiva;
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
  hermano oculto (`.<nombre>.part-<job>-<fingerprint>`) y se renombra
  en su sitio al final. En
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync el
  upload subyacente ya es atómico; en el resto el rename es el
  punto de commit.
- **Resume.** Las transferencias fallidas pueden reanudarse; los
  bytes parciales en el destino se retoman donde quedaron. Una
  transferencia que falla porque el destino está lleno borra su
  fichero parcial.
- **Retry.** "Retry Failed" reintenta cada transferencia en estado
  de error, cada una una sola vez.
- **Cancel All** detiene también una copia o un move cuyo recorrido
  de carpetas sigue en marcha: ninguno de sus ficheros entra en cola.
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
| `core.metadata_index` | Búsqueda offline SQLite por nombre / ext / tamaño / mtime. Un fichero: `$AXROSS_METADATA_DB`, si no `$XDG_DATA_HOME/axross/metadata.sqlite`, si no `~/.local/share/axross/metadata.sqlite` (un índice que ya está allí sigue en uso). Solo lo llena *Index Active Folder…*, nunca la navegación; guarda por entrada la conexión, el path, nombre, tamaño, extensión y fechas, sin contenido. La búsqueda por extensión, tamaño y fecha usa índices de SQLite; la de un trozo del nombre lee todas las filas. sift no construye ningún índice ni busca: es un analizador de ficheros. |
| `core.previews` | Thumbnailer local de imágenes con allow-list MIME, caps de tamaño y gate del límite de allocation Qt. F3 / doble-click. |
| `core.archive` | Extracción segura de zip / tar / 7z (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .7z`). Guards contra zip-slip / bomba / metadata mentirosa; `.7z` requiere el extra `[archive]`. |
| `core.elevated_io` | Lectura local con privilegios vía `pkexec` — Axross nunca mantiene el privilegio. Entrada "Open as root…" en el menú contextual. |
| `core.fuse_mount` | Montaje FUSE de cualquier FileBackend. Solo lectura por defecto; `writeable=True` habilita create / write / unlink / mkdir / rename. Extra opcional `[fuse]`. |
| `core.mcp_server` | Servidor MCP JSON-RPC con framing stdio que expone el backend configurado como herramientas. `--mcp-write` añade herramientas mutadoras, capadas a un root a prueba de path-traversal. |

## Acciones del menú contextual

| Acción | Trigger | Qué hace |
|---|---|---|
| Disk Image… | Clic derecho (un fichero `.img .raw .dd .iso .qcow2 .vdi .vmdk .vhd(x) .e01 …`) | El contenedor (qcow2, VDI, VMDK, VHD/VHDX, E01), la tabla de particiones (MBR con particiones lógicas, GPT) y el filesystem y la etiqueta de cada volumen, leídos en Python puro a través de cualquier backend. Una imagen local monta un volumen mediante un loop device sobre exactamente sus bytes: primero `udisksctl` sin preguntar (donde polkit lo permite), luego `sudo`, luego `pkexec` y por último `udisksctl` dejando preguntar a polkit. La contraseña de sudo se pide una vez y se guarda en memoria mientras axross está abierto (nunca en disco, nunca en una línea de comandos); *Remember the sudo password* (*Edit → Settings… → Security*) lo desactiva y vuelve al orden `udisksctl` (polkit pregunta), `pkexec`, `sudo` preguntando cada vez. El Paranoid Security Mode nunca la recuerda. sudo, pkexec y udisksctl se ejecutan solo desde carpetas del sistema propiedad de root, nunca desde `$PATH`. **Read-only** salvo que *Allow writing* esté marcado y confirmado. La carpeta montada se abre en un panel nuevo; *Unmount* libera el loop device. Los montajes hechos por axross se recuerdan entre reinicios (`~/.config/axross/mounts.json`; solo vuelven los que siguen montados). *Identify File Type…* reconoce imágenes de disco también por su contenido (GPT, MBR, discos virtuales) y ofrece *Disk Image…* para esa fila, se llame como se llame. qcow2 / VDI dinámico / VMDK hay que convertirlos antes (`qemu-img convert -O raw`); un VDI fijo se monta directamente. |
| Tags ▸ | Clic derecho sobre una selección | Marca un tag de color (Important y Review later existen; New Tag… añade uno) en cada fichero seleccionado de cualquier backend; puntos en la columna Name, los tags en su tooltip; `tag:<nombre>` en el campo de filtro muestra solo esos ficheros; *View > Tagged Files…* lista los ficheros de cada tag y va allí. Guardado en `~/.config/axross/tags.json`. |
| Nueva carpeta | Click derecho | `backend.mkdir(path)` en cada backend con escritura. |
| Nuevo fichero… | Click derecho | Fichero de cero bytes vía `backend.open_write(path).write(b"")`. |
| Nuevo symlink… | Click derecho | Dos prompts. Visible solo en backends con `supports_symlinks=True`. |
| Nuevo hardlink… | Click derecho | Misma forma; cross-device → `OSError(EXDEV)`. |
| Find in Index | `Ctrl+Shift+F` | Búsqueda en el índice offline de metadata. |
| Calculate Size (N dirs) | Clic derecho sobre carpetas | Tamaño total, número de ficheros y carpetas de cada carpeta elegida, recorridos en segundo plano a través de la conexión (*Cancel* en la línea de estado); la tabla de resultados ordena y los tamaños aparecen en la columna Size del panel hasta que la carpeta se recarga. **Los ficheros ocultos cuentan**: dotfiles, carpetas ocultas y entradas que el backend marca como ocultas se suman como cualquier otra — igual que `du` —, las muestre el panel o no. Un enlace cuenta con su propio tamaño y nunca se sigue; una carpeta que no se puede leer se nombra en el resultado y se salta. |
| Identify Files in This Folder… | Clic derecho (también en espacio libre); el botón de la ventana *Identify File Type* | Cada fichero directamente en la carpeta (una carpeta elegida, si no la mostrada; las subcarpetas se cuentan, no se recorren; ficheros ocultos incluidos) identificado por su contenido como en *Identify File Type…*, en segundo plano y a través de la conexión, así que también en paneles remotos. Acotado: como mucho 2000 ficheros, 64 KiB por fichero, 15 s de timeout por lectura, *Cancel*; no se pregunta a `file(1)`. Las columnas ordenan: nombre, tipo detectado, MIME type, el veredicto *mismatch*, tamaño, una nota — en una imagen de disco su contenedor, tabla de particiones y número de particiones (`Raw disk image, MBR, 2 partitions, 4.0 MiB`; como mucho 4 MiB leídos para ello) — y, para ficheros locales con el extra `sift` instalado, el tipo según sift. Una fila abre *Disk Image…* (imágenes de disco) o *Properties…*; un doble clic elige lo que corresponda. |
| Duplicate Finder | Menú View | Agrupar por hash de contenido, copiar URLs `ax-cas://…`; mover las copias seleccionadas a la papelera de axross tras comprobar en vivo que queda otra copia real. |
| View Media… / View Selected Media… | Click derecho, menú View | Imágenes, PDFs y vídeos de la carpeta (opcionalmente recursivo) o de la selección como grid overview, visor para ir pasando o slideshow — ver *Editores y visores*. |
| Show / Remove / Export Metadata… | Click derecho | EXIF / GPS / XMP / IPTC, propiedades de Office, info de PDF, tags de audio / vídeo de la selección — o de toda la carpeta si no hay nada seleccionado (subcarpetas opcionales) — ver *Metadata de ficheros*. |
| Move to Trash | Click derecho | Papelera universal. Funciona como Delete Permanently: en segundo plano, con la misma segunda pregunta para las entradas ocultas. |
| Delete Permanently | Click derecho, `Del` | Primero cuenta fuera del hilo de la GUI lo que se borrará (carpetas, archivos, bytes, entradas ocultas) y luego pregunta. Una carpeta seleccionada con entradas ocultas (dotfiles o el flag hidden del backend) - o una que la comprobación no pudo leer entera - necesita un segundo OK cuyo default es No. El borrado corre en segundo plano: la línea de estado muestra el progreso, Cancel para en la entrada siguiente - también dentro de una carpeta que se borra en local, por SMB, SFTP o FTP, y la línea de estado dice cuánto de esa carpeta ya se borró (lo borrado queda borrado; un servidor que borra una carpeta entera con un request, como WebDAV o S3, termina esa carpeta) - los fallos se listan por entrada y la carpeta se recarga al final. Una ruta que ya se está borrando se rechaza, también desde el otro pane. |
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
- **Marcadores de terminal** abren una shell en vez de una carpeta: una
  shell local, una en un profile SSH (SFTP/SCP) o una en un host sin
  profile — *SSH Host (no profile)*: host o dirección IP, puerto (22),
  usuario, un fichero de clave opcional —, opcionalmente entrando en una
  carpeta de trabajo. Se crean con el botón ☆ de un panel de terminal
  (*Bookmark this Terminal*) o con *New Terminal Bookmark…* en el menú
  contextual de la barra lateral; un clic abre un panel de terminal junto
  al panel activo. Un marcador nunca guarda credenciales: el de profile
  nombra el profile; el de host conecta como Quick Connect — en segundo
  plano, pregunta si confiar en una host key desconocida (known_hosts,
  nunca en silencio), usa el fichero de clave o un ssh-agent en marcha,
  pide la contraseña cuando eso no basta y la passphrase de una clave
  cifrada; nada de lo tecleado se guarda y se aplica el proxy de
  *Settings → Network & Proxy*. Un profile que falta o sin shell, o un
  host que no es un nombre de host, se notifica y no se abre nada. La
  shell de un marcador de host no forma parte del layout guardado.

## Editores y visores

Cada visor, editor y diálogo tiene dos botones arriba a la derecha:
[x] lo cierra, el de su izquierda lo maximiza a toda la pantalla y
restaura el tamaño que tenía antes. `Ctrl+M` hace lo mismo, igual que
el botón Maximize de la barra de título. En un diálogo, arrastrar con el
botón izquierdo el resto de esa fila superior mueve el diálogo, y
arrastrar la barra de título de un panel flotante mueve el panel -
también donde el window manager no dibuja barra de título (spectrwm,
otros tiling) o mantiene la ventana maximizada (layout `fullscreen` de
spectrwm), y en Wayland: axross pide entonces al window manager que la
mueva. Un doble clic en la barra de título de un panel flotante lo
vuelve a acoplar.

- **Editor de texto** (incorporado) — cada fichero abierto para editar
  es una pestaña de una ventana de editor (*Edit* / F4 en un panel,
  local o remoto): resaltado de sintaxis (Pygments; el lenguaje por
  nombre o línea `#!`, cambiable en la barra de estado), números de
  línea, buscar y reemplazar con regex, mayúsculas y palabra completa
  (Ctrl+F / Ctrl+H, F3), ir a línea (Ctrl+G), ajuste de línea, zoom,
  finales de línea (LF / CRLF / CR) y codificación (UTF-8, UTF-8 BOM,
  Latin-1, UTF-16) en *Format*, Save / Save All. *File → New* (Ctrl+N)
  abre una pestaña sin fichero, *Open…* (Ctrl+O) ficheros locales (los
  remotos se abren desde su panel), *Save As…* (Ctrl+Shift+S) escribe
  una pestaña local en un fichero local y una remota en una ruta de su
  propio backend, y pregunta antes de reemplazar un fichero; Save All es
  Ctrl+L. Enter mantiene la sangría de la línea, un nivel más tras `:`
  (Python, YAML) o `{` (lenguajes con llaves). *Tools → Text Editor*
  abre la ventana sin fichero. Guardar conserva el
  final de cada línea no tocada, un BOM y los espacios duros, escribe de
  forma atómica y pregunta si el fichero cambió desde que se abrió; el
  panel con la carpeta se refresca. Cerrar con cambios sin guardar
  pregunta Save / Discard / Cancel; cerrar la última pestaña cierra la
  ventana, y la barra de menús lleva los botones maximize y [x]. Se abren ficheros hasta el límite de
  apertura (32 MB por defecto, *Edit → Settings… → Files & Panes*).
- **Editor hex** — útil para triage en ficheros remotos.
- **Visor de imágenes** — F3 / doble-click, allow-list MIME,
  caps de tamaño.
- **PDF** — F3 / doble-click abre el PDF solo en el media viewer
  (necesita QtPdf; sin QtPdf o en el security mode `paranoid` se abre
  el editor hex y el log dice por qué).
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
  Space van al fichero anterior / siguiente (se paran en el primer y
  último elemento; también dentro de un PDF, y la slideshow solo pasa
  páginas de un PDF abierto solo). Un PDF de más de una página muestra un control de páginas
  `← n / m →` en la barra de botones; Arriba / Abajo pasan sus páginas.
  Home / End, F11 fullscreen, Ctrl+M maximize / restore (la ventana
  recuerda tamaño, posición y estado maximize para la próxima
  apertura), rueda o `+` / `-` zoom, `F` fit, `1`
  100 %, `R` rotar, `S` slideshow (intervalo en segundos; la
  slideshow da la vuelta, un vídeo se reproduce hasta el final), Esc
  vuelve a la overview, otro Esc cierra. **Supr** (Delete) borra el
  fichero mostrado (o el tile seleccionado) tras una pregunta;
  arrastrar la imagen o un tile a un pane lo mueve allí, con Ctrl se
  copia - igual que un arrastre desde el pane del que salió el visor
  (una imagen ampliada se desplaza en su lugar). El visor de imágenes
  hace ambas cosas también. Funciona en cualquier
  backend: los ficheros remotos se copian a un directorio temporal
  privado hasta el *Open Size Limit* y se borran después; un
  elemento demasiado grande, cifrado o roto muestra el motivo. El SVG
  solo se renderiza sin DOCTYPE/entidades, scripts ni referencias
  fuera del fichero. El modo `paranoid` bloquea el visor.
  `I` (o el botón *Info*) muestra la metadata del elemento actual en
  un panel lateral, con *Remove metadata* — también en el visor de
  imágenes.
- **Media Player** (extensión incluida, *Extensions → Manage
  Extensions…*) — un dock que reproduce MP3, WAV, Ogg Vorbis, FLAC,
  Opus, AAC y más. Las pistas se añaden con click derecho → *Play in
  Media Player*, *Add…* o arrastrando archivos y carpetas desde un
  panel de archivos o el escritorio a la playlist (las carpetas
  aportan sus archivos de audio ordenados, como máximo 2000 y 6
  niveles; lo que no es audio se omite con un aviso; los archivos
  remotos se copian a una carpeta temporal fuera del hilo de la GUI,
  como máximo 512 MB cada uno y 2 GB por drop). Las filas se
  reordenan arrastrándolas; la pista en curso (en negrita, con icono
  de play y en el título del dock) sigue sonando. Se avanza con el
  slider de posición (click o arrastre, `1:23 / 4:56`). ⏮ reinicia la
  pista tras 3 s, si no vuelve a la anterior; shuffle reproduce cada
  pista una vez por ronda, repeat es off / all / one. Una pista que
  no se puede reproducir se marca y se salta. *Load…* / *Save…* leen
  y escriben playlists M3U / M3U8 (UTF-8, rutas relativas para pistas
  bajo la carpeta de la playlist, títulos y duraciones `#EXTINF`; URLs
  y entradas ausentes o que no son audio se omiten, archivos de más
  de 1 MiB o con bytes NUL se rechazan; las copias temporales de
  pistas remotas no se guardan). La lista, la pista actual con su
  posición, el volumen, mute, shuffle y repeat vuelven en el
  siguiente arranque (`~/.config/axross/media_player.json`, modo
  0600). El volumen sigue una curva perceptual (cúbica); botón de
  mute. Teclas mientras el reproductor tiene el foco: Space
  play/pausa, Enter reproduce la fila seleccionada, Delete quita las
  filas seleccionadas, Izquierda / Derecha avanzan 5 s (con Shift
  30 s), Ctrl+Izquierda / Ctrl+Derecha pista anterior / siguiente, M
  mute, + / - volumen. Con numpy: ecualizador de 10 bandas con presets
  (la flecha a la izquierda de *Equalizer* pliega los sliders de las
  bandas y deja el sitio a la playlist) y una visualización animada:
  espectro, espectro reflejado, espectro radial, osciloscopio o VU
  meter estéreo - un clic en ella pasa a la siguiente. La visualización
  elegida y el ecualizador plegado vuelven en el siguiente inicio.
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

**Cómo se escribe** — *Edit → Settings… → Metadata* (*Tools → Metadata
Settings…* la abre):

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
- El terminal (dock y pane de terminal) es una pantalla VT100 / xterm:
  retorno de carro, movimientos del cursor, borrado, regiones de
  scroll y la pantalla alternativa funcionan, así que los prompts de
  zsh, la edición de línea, `less`, `top` y los editores dibujan donde
  deben. El tamaño de terminal de la shell es el del área del terminal
  y sigue cada cambio de tamaño (`stty size` lo muestra). Los colores
  no se muestran.
- Las teclas pulsadas en el terminal van a la shell: Ctrl+letra (en
  macOS la tecla Control), teclas de función, flechas y teclas de
  edición; así Ctrl+W, Ctrl+Q o F6 no cierran un pane, no salen de
  axross ni mueven ficheros. Pegar con Ctrl+Shift+V (macOS: Command+V),
  clic central o el menú contextual; el texto va a la shell. Los atajos
  con Command en macOS y las teclas de zoom siguen siendo de axross.
- Mientras se arrastra un fichero sobre un pane, la fila donde caerá
  queda enmarcada y una nota junto al cursor nombra la carpeta:
  *Move to …* o, con Ctrl, *Copy to …*. La fila `..` es la carpeta de
  arriba.

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

Las herramientas de ficheros de solo lectura (`list_dir`, `stat`,
`read_file`, `checksum`, `search`, `walk`, `grep`, …), las de escritura
con `--mcp-write`, los grupos de capacidades de `--mcp-tools`
(`axross --mcp-list-tools` imprime cada herramienta que sirve un
conjunto de flags), endpoints `resources/*`, log forwarding por
`notifications/message`, timeouts por herramienta, rate limits
token-bucket por sesión, sesiones HTTP con streaming SSE de
progreso, multi-backend routing opcional.

Referencia completa: **[docs/MCP_es.md](MCP_es.md)** (ES) · [MCP.md](MCP.md) (EN) · [MCP_de.md](MCP_de.md) (DE).
Para clientes LLM: [LLM_GUIDE.md](LLM_GUIDE.md) (en inglés).

## Dock Agent — un LLM local trabaja con axross

View > Panels > Agent (Ctrl+Shift+A) abre un chat con un perfil LLM
(los perfiles del dock Analysis: LM Studio, Ollama, vLLM, llama.cpp o
cualquier servidor compatible con OpenAI; LLM… los gestiona). El modelo
trabaja con las mismas herramientas que el servidor MCP, en la carpeta
mostrada arriba (la del panel activo, si muestra ficheros locales).

**Ollama** ejecuta un modelo con un context de 4096 tokens si no se le
indica otra cosa, y solo las instrucciones y los tools del agente ocupan
de 2.000 a 5.000 tokens (5.259 con *Allow changes to files*). Arranca el
servidor con `OLLAMA_CONTEXT_LENGTH=16384` o pon `PARAMETER num_ctx
16384` en un Modelfile: Ollama recorta sin avisar una request que no
cabe, y su API compatible con OpenAI no acepta un tamaño de context.
Si una respuesta llenó el context, el tab lo dice.

**Tabs.** Cada tab es una conversación propia con su modelo, protection
mode, sandbox, carpeta y herramientas: "+" o Ctrl+T abre uno, un doble
clic lo renombra. Con *Keep tabs* activado (Tools > Agent Settings…)
cada tab es un fichero JSON en `~/.config/axross/agent/sessions/`
(`0o600`) y vuelve al siguiente arranque. Ctrl+Enter envía, Esc o Stop
terminan la tarea al momento - también mientras el modelo aún escribe
su respuesta (la request se corta, el servidor deja de generar) - y
flecha arriba/abajo recupera tareas anteriores. Si un modelo de
reasoning escribe toda su respuesta solo en el reasoning (Qwen3 en LM
Studio lo hace a veces), se muestra marcada como tal; si un modelo
termina sin respuesta, se dice.

**Thinking.** Lo que un modelo de reasoning piensa antes de responder o
de llamar a una herramienta (`reasoning_content` o `reasoning` junto a
la respuesta, o `<think>…</think>` al principio de ella) se muestra
aparte de la respuesta: una línea gris en cursiva **▸ Thinking** con su
primera frase. Un clic en *Thinking* abre el texto entero, otro lo
cierra. Solo se lee en voz alta la respuesta. Los tabs guardados
conservan el thinking, cerrado.

**La lámpara** en la barra de título del dock dice si el LLM del tab
responde: **verde** - la última request a su endpoint (una lista de
modelos o una request de una tarea) salió bien; **naranja** - hay una en
curso; **rojo** - falló, no hay perfil, o el endpoint es remoto y aún no
tiene consentimiento (no se pregunta antes de la primera tarea). El
tooltip nombra el endpoint, el modelo y el motivo; un clic vuelve a
comprobar. La comprobación pide la lista de modelos del servidor en
segundo plano, solo mientras el dock está visible.

**Protection modes** (por tab):

- **Ask** — cada cambio y cada comando remoto espera un Sí en un
  diálogo que muestra la herramienta y sus argumentos (passphrases
  enmascaradas).
- **Plan** — el agente solo lee y escribe un plan; *Run this plan* lo
  ejecuta luego en modo Ask.
- **Auto** — los cambios se ejecutan sin preguntar; los comandos
  remotos y las herramientas de un servidor MCP en "always" siguen
  preguntando.
- **Bypass** — nada pregunta. Solo disponible si se activa en Agent
  Settings, nunca en el security mode paranoid, y marcado en rojo.

**Darle ficheros.** El menú "+" adjunta la selección o la carpeta del
panel activo, ficheros desde un diálogo o una ruta del portapapeles;
también se pueden arrastrar ficheros de un panel al tab, o usar *Send
to Agent* en el menú contextual del panel. Un fichero local fuera de la
carpeta del tab hace legible su carpeta (read-only) para ese tab.

**Herramientas** (Tools ▸ en el tab): las de ficheros, los grupos
marcados (metadata, filetype, archive, …), *Allow changes to files*,
*Allow remote commands*, una línea `mcp:<nombre>` por servidor MCP y
`ext:<id>` por extensión con herramientas para el agente. Siempre
presentes: `ask_user` (el agente te pregunta algo) y `update_plan` (una
checklist encima del campo de tarea).

**Topics ▸** rellena el campo de tarea con una tarea preparada — System
inventory, Install or update software (en modo Plan), Service status,
Collect logs, Disk usage, Summarise a folder, Read data out, Review a
config folder, Free disk space (con las herramientas del Duplicate
Finder) — para completarla y enviarla. Las extensiones pueden añadir las
suyas.

Los **topics propios** («work prompts»): Topics ▸ *+ New Topic…* abre
un formulario vacío, *Save This Task as Topic…* parte del campo de
tarea y *Edit or Delete My Topics…* los cambia o borra. Un topic guarda
título, comando slash, el prompt (`{folder}` y `{backend}` se rellenan), el modo que
sugiere, lo que necesita y los grupos de herramientas que marca, en
`~/.config/axross/agent/work_prompts.json`. Cada topic tiene un comando:
escribe `/` en el campo de tarea para elegir uno (`/free-space`,
`/review-config`, los tuyos); el texto tras el comando queda debajo del
prompt. Un comando rellena el campo — tú lo lees y lo envías.

**Prompts** (*Edit → Settings… → Agent → Prompts*): el system prompt
(las reglas que el modelo recibe primero) y el user prompt (un template
para cada tarea: `{task}` se convierte en lo que escribiste, un texto
sin `{task}` va delante, vacío envía la tarea tal cual) como perfiles con
nombre. *Default* es el prompt propio de axross y no se puede cambiar ni
borrar — *Duplicate* crea una copia editable. *Prompt profile of new
requests* elige el perfil de la próxima petición de cada pestaña; la
pestaña sigue añadiendo su carpeta, el modo Plan y las reglas de lectura
en voz alta. Se guarda en `~/.config/axross/agent/settings.json`.

Las **funciones de axross** son las herramientas que axross ejecuta él
mismo para el agente — fuera de su sandbox, con los derechos de axross:
*Remote files* (las conexiones abiertas en los paneles, backend
`pane:<nombre>`), *Saved connections* (perfiles guardados que el agente
abre él mismo), *Remote commands* (hosts SSH/WinRM/…), *servidores MCP*
y *herramientas de extensiones*. Son una salida del sandbox; por eso las
protege un interruptor principal, que está **desactivado por defecto**.
Un perfil production rechaza todo cambio.

**Lo que un tab puede alcanzar** — dos niveles, ambos deben permitirlo:

- *Agent Settings > Access* es el techo de todo tab: el interruptor
  principal *Let agents use axross functions* y cada función. Desactivado
  ahí significa desactivado en todo tab.
- *Access…* en el tab (o *Agent Settings > Sessions* para todos los tabs
  a la vez) es la elección propia del tab dentro de ese techo: su
  interruptor principal y sus funciones, su **red** y sus **carpetas**.
  Un tab nuevo empieza con el interruptor principal como lo tiene Agent
  Settings.

| Red de un tab | Significado |
|---|---|
| As the sandbox profile says | nivel y allowed hosts del perfil (sin sandbox: sin límite) |
| None | ningún host |
| Only these hosts | la lista `host:port` propia del tab |
| All hosts | solo con un sandbox lax o sin sandbox |

El nivel del sandbox sigue siendo el techo: un tab solo restringe lo que
su nivel puede (paranoid solo ofrece *None*, normal y high no ofrecen
*All*). La red vale para las conexiones propias del sandbox, el trabajo
remoto en axross y los servidores MCP http por igual, y se comprueba en
cada conexión. Las **carpetas** de un tab son read-only o read-write;
read-write solo donde el nivel permite carpetas extra (lax, normal) y
con *Allow changes to files*. El tooltip de *Access…* lo resume todo.

**Sandboxes** (Agent Settings > Sandboxes): un tab puede ejecutar su
agente en bubblewrap, podman o docker. Un perfil de sandbox tiene un
nivel:

| Nivel | Red | Carpeta | Carpetas extra |
|---|---|---|---|
| lax | la del host | según ajuste | según ajuste |
| normal | solo allowed hosts | según ajuste | según ajuste |
| high | solo allowed hosts | según ajuste | read-only |
| paranoid | solo el LLM | read-only | read-only |

Las peticiones al modelo, la API key y el consentimiento quedan fuera:
el sandbox no tiene red propia, axross envía por él. Los allowed hosts
(`host:port`) se alcanzan a través de axross, comprobados en cada
conexión — un cambio vale al instante. Las conexiones remotas, los
perfiles guardados, los servidores MCP y las herramientas de
extensiones también se ejecutan en axross, fuera del sandbox, así que
sus credenciales nunca entran; el nivel y los allowed hosts del sandbox
deciden si el agente puede usarlos (paranoid: ninguno). Los límites del
nivel de memoria, tareas y CPU valen con podman y docker; bubblewrap los
recibe de un scope de usuario de systemd (sin él solo la memoria, con
`prlimit`). podman y docker necesitan la imagen:
`scripts/axross-podman.sh agent-image` ([PACKAGING.md](PACKAGING.md)).

**Servidores MCP** (Agent Settings > MCP Servers): más servidores MCP —
un programa (stdio) o un endpoint http — cuyas herramientas un tab
puede ofrecer como `<servidor>__<herramienta>`. *Test* lista sus
herramientas. Un servidor en "always" pregunta en cada llamada;
"writes" deja ejecutar sin preguntar las herramientas que el servidor
marca como read-only. Un programa puede ejecutarse en un perfil de
sandbox; el token de un servidor http se guarda en el keyring.

**Extensiones** pueden arrancar el agente (`api.run_agent`,
`api.open_agent_tab`), darle herramientas (`api.add_agent_tool`),
añadir topics (`api.add_agent_topic`) y seguir sus eventos
(`api.on_agent_event`). La extensión incluida *Agent Stats* muestra una
ventana pequeña sobre la ventana principal (una ventana normal: mover,
cambiar tamaño, cerrar; también flotante en window managers de mosaico)
con tareas, respuestas,
llamadas a herramientas, errores, tokens y tiempo.

Un perfil cuyo servidor no está en esta máquina ni en su red pregunta
antes, porque lo que leen las herramientas se envía allí.

En un contenedor: `scripts/axross-podman.sh gui --llm-model FICHERO.gguf`
arranca axross en tu pantalla con llama.cpp al lado y el perfil ya
configurado ([PACKAGING.md](PACKAGING.md)). Con `--agent-sandbox`
funciona ahí también el sandbox bubblewrap: podman enmascara `/proc`,
que bubblewrap necesita montar él mismo; sin la opción el tab lo dice.
Dentro de un contenedor elige bubblewrap: podman no puede arrancar
contenedores propios ahí.

Un cliente MCP puede pasar una tarea al mismo modelo local con
`--mcp-tools agent` (`agent_run`); ese modelo solo puede leer
([MCP_es.md](MCP_es.md) §9.9).

### Hablar con el agente

El botón **🎤** de la pestaña habla con el agente, **🔊** lee sus
respuestas en voz alta. La voz la reconoce el perfil LLM de la pestaña
(LLM Profiles, *Advanced*): en local con Whisper — nada sale del equipo —
o un servidor compatible con OpenAI (`/audio/transcriptions`; uno remoto
pregunta antes de oír una grabación). Las respuestas las dice una voz
Piper local.

- **Modos del micrófono** (Settings > Voice): *push-to-talk* (mantener el
  botón, o la tecla de mantener, por defecto **F9**, mientras el dock Agent
  tiene el foco), *toggle* (un clic empieza, otro clic o una pausa termina)
  y *conversation* (tras cada respuesta hablada vuelve a escuchar; un clic
  en el botón la termina).
- **El texto reconocido** va al campo de la tarea para leerlo y enviarlo,
  o se envía en seguida (una conversation siempre envía).
- **Qué se dice:** solo la respuesta - ni llamadas a tools, ni código (una
  frase corta dice que el código se muestra), ni URLs o rutas largas. Stop,
  Esc, escribir o una tarea nueva lo cortan. Si axross rechaza una llamada
  (Files read-only, no permitida, sin permission) la voz lo dice
  brevemente; el primer uso de la voz en una sesión saluda.
- **Voz e idioma:** masculina o femenina, alemán o inglés, o *seguir la
  respuesta*. En alemán, los términos IT ingleses (Server, Backup, Pull
  Request, …) se dicen en inglés; también un término que la respuesta
  escribe entre `{llaves}` (las llaves no se muestran).
- **Instalación:** `pip install axross[voice]` (piper-tts, faster-whisper;
  incluido en axross-full), luego *Help > Features…*, grupo **Voice**:
  descargar las voces y un modelo Whisper (checksums fijados, en
  `~/.local/share/axross/voice/`).
- **Seguridad:** las confirmaciones siempre se hacen con clic, nunca con la
  voz; en el security mode paranoico el micrófono está apagado; el audio y
  las transcripciones se quedan en memoria.

## Settings

**Edit → Settings…** (**Ctrl+,**; en macOS en el menú de la aplicación)
reúne todos los ajustes de axross en una ventana: a la izquierda las
categorías, a la derecha la página de la elegida y encima un campo que
encuentra un ajuste por su nombre (escribe *sudo*, *proxy* o *zoom*).

| Categoría | Ajustes |
|---|---|
| General | Idioma (al siguiente arranque), restaurar el layout de la última sesión al arrancar, cuándo un panel se vuelve activo (con clic o tras 0,5–3 s con el ratón dentro) |
| Appearance | Theme, compact mode, monochrome icons, tamaño de letra (zoom), resaltar hidden files y su color (un color difícil de leer en el theme solo tras preguntar) |
| Files & Panes | Mostrar hidden files, open size limit, workspaces en RAM (sí / no, límite de tamaño, memoria que queda libre) y ficheros temporales en RAM (al siguiente arranque) |
| Network & Proxy | El proxy por defecto, lista de bypass, script PAC, una prueba |
| LLM Profiles | Los servidores LLM de los docks Agent y Analysis; *Fetch models* abre una lista con tamaño, parámetros, cuantización y el modelo cargado de cada uno, en la medida en que el servidor los indica |
| Agent | General, Prompts, Access, Sandboxes, MCP Servers, Sessions |
| Voice | Leer las respuestas en voz alta, idioma hablado, voz, modo del micrófono, tecla de mantener, texto reconocido insertado o enviado, la pausa que termina de hablar |
| Metadata | Cómo escribe Remove Metadata, preguntar antes |
| Search | Hosts buscados a la vez por *Find on Network Hosts*; dónde están el índice offline y el de duplicados |
| Security | Paranoid security mode (se mantiene al siguiente arranque; `AXROSS_SECURITY_MODE` en el entorno tiene prioridad), recordar la contraseña de sudo |
| Extensions | Qué extensions están activadas |

**OK, Apply, Cancel** funcionan igual en todas las páginas: solo se
escriben las páginas cuyos valores cambiaron; OK y Apply comprueban antes
cada página cambiada y no guardan nada mientras una tenga un problema (se
muestra esa página y el problema encima); después cada página cambiada se
guarda y surte efecto al momento. Cancel, Esc y la [x] descartan lo no
aplicado.

*Tools → Network & Proxy…, LLM Profiles…, Agent Settings…, Metadata
Settings…* y *Extensions → Manage Extensions…* abren la ventana Settings en
su página. *View → Show Hidden Files* (**Ctrl+H**), *View → Theme* y *View
→ Zoom* siguen siendo interruptores rápidos; se guardan al momento, como la
página.

## Ficheros de configuración

- `~/.config/axross/profiles.json` — perfiles de conexión (`0o600`).
- `~/.config/axross/bookmarks.json` — barra de marcadores.
- `~/.config/axross/session.json` — layout de panels, geometry de la
  ventana y layout de docks al cierre; se restaura al arrancar salvo
  que *Restore the layout of the last session on start* (Settings >
  General) esté desactivado. Su objeto `window` guarda también el aspecto
  (theme, compact, monochrome icons, tamaño de letra, hidden files) y el
  idioma.
- `~/.config/axross/settings.json` — ajustes pequeños: open size limit,
  activación de panels, modo de escritura y confirmación de metadata,
  recordar la contraseña de sudo, hosts buscados a la vez, el security mode.
- `~/.config/axross/proxy.json`, `llm.json`, `extensions.json` — el proxy
  por defecto, los perfiles LLM, las extensions activadas (secretos en el
  keyring).
- `~/.config/axross/agent/voice.json` — los ajustes de Voice (`0o600`).
- `~/.config/axross/column_prefs.json` — anchos y columnas ocultas,
  un solo archivo para todos los panels.
- `~/.config/axross/agent/settings.json` — Agent Settings (modos, accesos,
  perfiles de sandbox, servidores MCP; `0o600`).
- `~/.config/axross/agent/sessions/` — un fichero JSON por tab de Agent guardado (`0o600`).
- `~/.config/axross/<provider>_token.json` — refresh tokens OAuth (`0o600`).
- `~/.config/axross/ramfs.json` — ajustes de los workspaces en RAM. `"tmpfs_enabled": true`
  envía cada fichero temporal del proceso (buffers de descarga/subida a
  partir de 8 MiB, extracción de archivos, buffers de escritura FUSE) a un
  disco RAM (`/run/user/$UID`, si no `/dev/shm`) en vez del disco: nada
  toca el disco, pero consume RAM, por eso está desactivado por defecto. Un
  `TMPDIR` definido en el entorno siempre tiene prioridad.
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
