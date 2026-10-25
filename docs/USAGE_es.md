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
  abren un navegador para el paso de consent (Dropbox pide después en una
  ventana el código que muestra). El diálogo de conexión indica, por servicio,
  qué crear y dónde; el archivo de cliente de Google rellena ambos campos
  (Import Client JSON…). Los tokens se cachean
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
  para local↔remoto, remoto↔remoto, cross-protocolo). **Ctrl+X** /
  **Ctrl+V** hacen cut y paste entre dos carpetas cualesquiera (ver
  Transferencias).

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
- **Paneles de extensiones** (Media Player, Drives Overview, Markdown
  Preview, …) están en todos los workspaces hasta que pones uno en un
  workspace: el botón ⇄ de su barra de título (o un clic derecho en
  ella) ofrece cada workspace, **New Workspace** y **All Workspaces**, y
  **Workspace → Add Extension Panel** (también en el menú del clic
  derecho del tab) lleva un panel a un workspace. Allí es un panel más:
  solo aparece con su workspace, se va con él cuando se separa en una
  ventana, se arrastra por su barra de título sobre otro panel y acepta
  paneles arrastrados, cambia de tamaño con el splitter y **Equalize
  Pane Sizes** lo iguala. Su [x] lo saca del workspace; mostrado de nuevo
  desde el menú **Extensions**, vuelve a su sitio. Al cerrar el
  workspace, sus paneles se aparcan en All Workspaces (ocultos, con su
  estado); al apagar la extensión sus paneles salen y al encenderla
  vuelven.
- **Close Workspace** lo cierra con sus paneles (pregunta antes); al
  cerrarse el último panel de un workspace, se cierra el workspace.
  Siempre queda uno.
- **Equalize Pane Sizes** (**Ctrl+Shift+E**) iguala el workspace en
  pantalla — también uno que solo tiene terminales o paneles de
  extensiones.
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

**Cut y Paste.** *Cut* (Ctrl+X, o clic derecho > Cut) solo recuerda
las entradas seleccionadas - no se elimina nada; mientras el cut espera
se muestran atenuadas. *Paste* (Ctrl+V, o clic derecho > Paste, también
en el espacio vacío) en cualquier panel - otra carpeta, otra conexión -
las mueve a la carpeta de ese panel como un move de la cola de
transferencias: la misma comprobación de nombres existentes que F5 / F6,
y cada origen se elimina solo cuando su propia copia terminó y fue
comprobada; una transferencia fallida, cancelada o parcial lo deja
donde estaba. Un cut que nunca se pega no elimina nada: un cut nuevo lo
reemplaza, Esc en su panel lo descarta, cerrar el panel o cambiar su
conexión también. Pegar en la carpeta de la que vienen las entradas no
hace nada; una carpeta pegada en sí misma se rechaza. El cut termina
cuando su move entra en la cola.

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
| Analyse with sift / Analyse Folder with sift | Clic derecho (la entrada de carpeta también en espacio libre), el menú Actions, *Tools → Analyse with sift* | Abre el dock *Analysis (sift)* (el icono del tamiz de sift, `Ctrl+Shift+I`) y explica el fichero allí sin modelo. Varios ficheros seleccionados, o una carpeta (la seleccionada, si no la mostrada), se ofrecen como un batch para el perfil LLM activo; *Tools → Analyse with sift* toma la selección, o la carpeta mostrada si no hay selección. El resumen de directorio propio de sift (`sift --dir-summary`, desde sift 0.1.96) no forma parte del dock: una carpeta se analiza fichero por fichero. Sin sift (axross-slim, o una instalación desde el código sin el extra `sift`) cada entrada dice que sift viene con axross-full o con el extra `axross[sift]` y enlaza *Help → Features…*. |
| Duplicate Finder | Menú View | Agrupar por hash de contenido, copiar URLs `ax-cas://…`; mover las copias seleccionadas a la papelera de axross tras comprobar en vivo que queda otra copia real. |
| View Media… / View Selected Media… | Click derecho, menú View | Imágenes, PDFs y vídeos de la carpeta (opcionalmente recursivo) o de la selección como grid overview, visor para ir pasando o slideshow — ver *Editores y visores*. |
| Show / Remove / Export Metadata… | Click derecho | EXIF / GPS / XMP / IPTC, propiedades de Office, info de PDF, tags de audio / vídeo de la selección — o de toda la carpeta si no hay nada seleccionado (subcarpetas opcionales) — ver *Metadata de ficheros*. |
| Cut / Paste | Click derecho (Paste también en el espacio vacío), `Ctrl+X` / `Ctrl+V` | Cut recuerda la selección y no elimina nada (las entradas se atenúan); Paste en cualquier panel las mueve a su carpeta por la cola de transferencias - ver *Transferencias*. Un cut que nunca se pega lo deja todo en su sitio. |
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
  en tiempo real. **Ctrl+F** salta al campo del filtro; **Esc** allí
  borra el filtro y vuelve a la lista. Esc en la lista detiene primero
  un load en curso, luego borra un filtro activo, luego la selección y
  luego un cut pendiente de ese panel.
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
  niveles, los enlaces a carpetas se siguen una vez; también cuentan
  .m4b, .wv, .webm y otros formatos que reproduce el motor; lo que no da
  pista - no es audio, ilegible, demasiado profundo - se cuenta en el
  aviso, los archivos junto a pistas encontradas como portadas no; los archivos
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
  mute. El dispositivo de salida y el volumen de salida de *Edit →
  Settings… → Audio* se aplican encima (un cambio allí llega al
  momento a una pista que suena). Si el audio no arranca, el panel dice
  por qué: *Try Again* comprueba otra vez y arranca el reproductor en
  cuanto el audio responde, *Audio Settings…* abre la página Audio
  (otro backend u otro dispositivo). Teclas mientras el reproductor tiene el foco: Space
  play/pausa, Enter reproduce la fila seleccionada, Delete quita las
  filas seleccionadas, Izquierda / Derecha avanzan 5 s (con Shift
  30 s), Ctrl+Izquierda / Ctrl+Derecha pista anterior / siguiente, M
  mute, + / - volumen. Con numpy: ecualizador de 10 bandas con presets
  (la flecha a la izquierda de *Equalizer* pliega los sliders de las
  bandas y deja el sitio a la playlist) y una visualización animada:
  espectro, espectro reflejado, espectro radial, osciloscopio, VU meter
  estéreo, espectro en línea (eje de frecuencia logarítmico), waterfall
  (espectrograma), espectro polar, stereo scope (goniómetro: L contra
  R) o un starfield que acelera con el bajo - un clic en ella pasa a la
  siguiente. Su menú del click derecho lista cada visualización y cada
  esquema de colores (Classic, Fire, Ice, Neon, Mono, *Follow the
  theme*, *Custom*), el número de barras y el límite de frame rate;
  *Visualizer Settings…* (también *Extensions → Media Player
  Visualizer…*) añade los colores propios (fondo, barras suaves y
  fuertes, picos - un color de pico sin contraste 3:1 con el fondo se
  ajusta), la velocidad de caída de los picos y el smoothing.
  *Fullscreen* (menú, doble clic o F11 sobre la visualización) la
  muestra sola en la pantalla como un screensaver - Esc, F11 o un doble
  clic salen, el puntero del ratón se oculta tras 2,5 s sin moverse
  (desactivable); *Detach into a Window* la pone en una ventana propia
  de cualquier tamaño que sigue sonando, *Attach to the Panel* o cerrar
  esa ventana la devuelve. La flecha a la izquierda de *Playlist* (o
  *Show Playlist* en el menú) pliega la playlist: el panel queda en los
  controles y la visualización, las teclas siguen funcionando y los
  archivos soltados sobre el panel siguen llegando a la playlist. La
  visualización, sus colores y opciones, y el ecualizador y la playlist
  plegados vuelven en el siguiente inicio.
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
(los perfiles del dock Analysis (sift): LM Studio, Ollama, vLLM, llama.cpp o
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

**Conversaciones en panels propios.** Clic derecho en un tab → **Detach
as Panel** - o arrastrar el tab lejos de la barra de tabs - convierte la
conversación en un panel propio; **Tools → New Agent Window** (o ⧉ junto
a "+") abre una conversación nueva directamente como panel. Se mueve la
misma conversación: una tarea en curso sigue, sus preguntas siguen
llegando, nada se reinicia. Un panel así se coloca como un panel de
extensión: en **All Workspaces** (el área de docks de la ventana) o -
con el botón ⇄ o un clic derecho en su barra de título (*Move to
Workspace*) o **Workspace → Add Extension Panel** - en un workspace,
donde es un pane: se arrastra por su barra de título, cambia de tamaño y
va con el workspace cuando este se separa. ⇲ (o *Attach to Agent Dock*
en el menú del clic derecho) lo devuelve como tab. Su [x] cierra la
conversación como cerrar su tab: si hay conversación pregunta antes, y
luego se borra. Al cerrar su workspace queda en All Workspaces; *close
all panels in this area* lo devuelve al dock Agent. Cada panel tiene su
propia lámpara; la voz trabaja para la conversación en la que se inició,
si no para aquella en la que se escribió por última vez; settings,
perfiles y extensiones llegan a todas las conversaciones. Con *Keep
tabs* activado, las conversaciones separadas vuelven tras reiniciar en
su workspace o en All Workspaces; una cuyo workspace no vuelve (el
layout no se restaura) vuelve a ser un tab.

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

**Files read-only** (en la fila superior de la pestaña, y para todas las
pestañas en Agent Settings > Access): el agente lee archivos pero no
cambia ninguno — no escribe, borra ni mueve, no ejecuta comandos remotos
(un comando puede cambiar archivos), las carpetas extra son de solo
lectura, ninguna herramienta de escritura de servidores MCP o
extensiones, y un sandbox no monta nada escribible. Se aplica donde se
construyen las herramientas del agente y otra vez en cada llamada, no
solo en el diálogo. Una excepción exacta: un servidor MCP que no puede
cambiar tus archivos conserva sus herramientas — un servidor en
contenedor con la línea de podman propia de axross (instalado desde un
catálogo), `--network=none` y solo carpetas de solo lectura (`:ro`). Su
*Asks* sigue valiendo: con "Every call asks" cada llamada espera tu Yes.
Cualquier otro servidor (red, una carpeta escribible, un programa en
esta máquina, un servidor HTTP, una línea de podman escrita a mano) solo
ofrece las herramientas que marca de solo lectura, y ninguna si pregunta
antes de cada llamada.

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

Los **perfiles de agente** configuran una pestaña de una vez: el perfil
LLM, el perfil de prompt, el modo de protección, el sandbox, los grupos
de herramientas, las funciones de axross (interruptor principal,
funciones, red), *Files read-only*, *Allow changes to files* / *Allow
remote commands* y los servidores MCP que ofrece — elegidos **por
categoría** (la categoría del catálogo desde la que se instaló un
servidor, p. ej. *Security: Reverse Engineering*; *Category* en Agent
Settings > MCP Servers la fija a mano) y/o **por nombre** (o por la
entrada del catálogo de la que viene, así un servidor renombrado sigue
coincidiendo). La flecha junto a "+" en el dock Agent ofrece **New Tab
from Profile**, **Apply Profile…** (también en el menú contextual de una
pestaña) y **Edit Agent Profiles…**; Tools > New Agent Tab from Profile
abre una para la carpeta del pane activo. *Apply Profile…* muestra antes
lo que recibiría la pestaña; cambia sus ajustes, la carpeta y la
conversación se quedan, y una pestaña con una tarea en curso lo rechaza
(primero detenla — la tarea en curso conserva los ajustes con los que
empezó). La pestaña nombra su perfil (*Profile: …*) y lista lo que el
límite recortó o lo que falta, con **Install from Catalog…** (el catálogo
se abre en esa categoría, o busca el nombre del servidor).

Un perfil **nunca amplía Agent Settings > Access**: con las funciones de
axross apagadas allí, los servidores MCP del perfil no se ofrecen y la
pestaña lo dice; Bypass solo donde se puede elegir; un perfil de sandbox
que no existe se conserva y se rechaza, nunca "No sandbox" en silencio.
Con *Files read-only*, un servidor cuyo *Asks* es "Every call asks" no
ofrece ninguna herramienta, salvo que sea un contenedor sin red y con
carpetas de solo lectura (ver *Files read-only* arriba) — la pestaña
nombra cada servidor así y el motivo.

**Presets** incluidos (de solo lectura, marcados *(preset)*; *Copy* crea
un perfil editable a partir de uno):

| Preset | Qué configura |
|---|---|
| Files Assistant | las herramientas de archivos de axross, las conexiones remotas abiertas; los cambios preguntan; sin servidores MCP |
| Reverse Engineering | categorías *Security: Reverse Engineering* y *Security: Firmware & Forensics*; sandbox *High* |
| Forensics read-only | categoría *Security: Firmware & Forensics*; archivos de solo lectura |
| Network & Web Recon | categorías *Security: Network Recon*, *Security: Web*, *Security: OSINT*; modo Ask |
| Code & Secrets | servidores *git* y *filesystem*, categoría *Security: Code & Secrets* |
| Remote Ops | archivos remotos, conexiones guardadas, comandos remotos (cada uno pregunta); modo Ask |
| Research | servidores *fetch*, *memory*, *sequentialthinking*; no Files read-only (fetch necesita red), *Allow changes to files* desactivado |

Un preset cuyos servidores no están instalados configura igualmente el
resto de la pestaña. Agent Settings > **Profiles** edita tus propios
perfiles (New, Copy, Delete), muestra lo que recibe una pestaña dentro
de la página Access y elige el **perfil de las pestañas nuevas**. Se
guarda en `~/.config/axross/agent/settings.json` (`agent_profiles`,
`agent_profile`); una entrada editada a mano se comprueba como el resto
del archivo (las claves desconocidas se descartan, los tipos erróneos
toman su valor por defecto, un nombre ya usado — también el de un preset
— descarta la entrada).

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
sandbox; uno sin él dice *runs on this machine, not in a container*. El
token de un servidor http se guarda en el keyring. Un comando escrito
que descarga código (`npx …`, `uvx …`, `docker run …`) nunca se guarda
como programa de esta máquina: *Install in a Container* lo construye en
podman rootless (sin red), o se muestra el motivo por el que no se puede.
Un fichero de settings editado a mano con un comando así tampoco lo
arranca (el servidor se omite, con una línea de log), y una línea de
container con flags que lo amplían (`--privileged`, `--cap-add`,
namespaces del host, otros mounts) se rechaza.

*Tools → MCP Servers…* abre esta página (Edit → Settings… → Agent → MCP
Servers). **Add from Catalog…** busca en las *fuentes MCP* e instala un
servidor en **podman rootless**; nada de ello se ejecuta en el host:

- **Fuentes** (Agent Settings → MCP Sources, cada una desactivable): el
  catálogo incluido (servidores de referencia oficiales del namespace
  curado `mcp/*` de Docker más dos servidores de seguridad, fijados por
  digest, funciona sin conexión), el namespace `mcp` de Docker Hub, el
  MCP Registry oficial (`registry.modelcontextprotocol.io`) y ficheros de
  catálogo o URLs `https://` propios. *Check* lee uno y dice qué contiene
  o por qué se rechaza (esquema incorrecto, más de 1 MiB, no es JSON,
  una entrada sin digest fijado …). Lo que dice una fuente se muestra
  como texto plano.
- **c0decave MCP Hub** (activado por defecto): un catálogo del mismo
  esquema en
  `https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json`.
  Solo se aceptan imágenes bajo `ghcr.io/c0decave/` fijadas por un digest
  `sha256` real; cualquier otra entrada (otro registry, npm, pypi, remote,
  sin digest) se rechaza con su motivo. Mientras el hub no responde, la
  línea de estado dice *not reachable or not published yet* y las demás
  fuentes funcionan como siempre.
- **Discover** (activado por defecto): listas awesome curadas para
  explorar -
  [R00T-Kim/awesome-offensive-mcp](https://github.com/R00T-Kim/awesome-offensive-mcp)
  (CC0; axross incluye un snapshot, así que Discover funciona sin
  conexión) y
  [wong2/awesome-mcp-servers](https://github.com/wong2/awesome-mcp-servers)
  (MIT; solo se lee en vivo). Su README se lee como texto no fiable:
  categoría, nombre, descripción y el enlace al repositorio de GitHub,
  nada más - sin markup, sin otros enlaces. Una entrada es **installable
  via MCP Registry** o **installable via Docker Hub** solo si esa fuente
  nombra el mismo repositorio (comprobado en segundo plano, como mucho 300
  requests por pasada, 24 h en cache); si no, es **link only**: *Open
  Repository*, sin instalación - axross nunca compila desde un repositorio
  de GitHub sin más. *Refresh* vuelve a leer las listas y a comprobar.
- **Install**: una imagen se descarga por digest (en Docker Hub se
  consulta antes el digest del tag; las demás se fijan al digest que
  indica podman). Un paquete npm o pypi se instala en un contenedor de
  una imagen fijada `node:22-slim` / `python:3.13-slim` (`npm
  --ignore-scripts`, `pip --only-binary=:all:`) cuya única red es el
  registro de paquetes, y se guarda como
  `localhost/axross-mcp:<nombre>-<versión>` - nunca npx, uvx, npm ni pip
  en el host. Un servidor remoto (Streamable HTTP, https) pasa a ser un
  servidor http. Se muestra el progreso, *Cancel Install* lo detiene;
  después se prueba el servidor (initialize, tools/list) y se activa si
  la prueba pasa. **Save** lo guarda.
- **Cómo se ejecuta**: `podman run --rm -i --init --pull=never` sin
  capabilities, sin nuevos privilegios, con raíz de solo lectura, un
  `/tmp` pequeño noexec y límites de procesos y memoria. Red **None** por
  defecto; **Allowlist** solo alcanza los `host:port` indicados a través
  de un proxy en axross (para programas que respetan `HTTPS_PROXY`; los
  demás no tienen ruta); **Full** cualquier host. Carpetas solo como se
  elijan, de solo lectura salvo que se marque *Writable*. Los valores de
  entorno y los secretos (en el keyring) llegan al contenedor por un
  pipe, nunca en la línea de comandos ni en un fichero.
- **Uninstall** quita el servidor y, al guardar, su imagen por ID
  (`podman rmi`, nunca forzado: una imagen en uso, con otras etiquetas o
  que ya existía antes de la instalación se queda). **Check for Update**
  muestra un digest o una versión más nuevos; nada se actualiza solo.

**Detected on this machine** (Agent Settings → MCP Servers y la lista
Tools de cada pestaña Agent): los servidores MCP ya configurados aquí se
ofrecen con una casilla, sin escribir ningún comando - los servidores de
Claude Desktop (`claude_desktop_config.json`), Claude Code
(`~/.claude.json`, también por proyecto, y `.mcp.json` de la carpeta de
la pestaña), VS Code (`settings.json` →
`mcp.servers`, `mcp.json`, `.vscode/mcp.json`) y Cursor
(`~/.cursor/mcp.json`, `.cursor/mcp.json`), además de las imágenes de
podman que instaló axross (también si los settings perdieron el
servidor). Marcarlo en Agent Settings lo añade activado (Save lo guarda)
y desmarcarlo lo quita; marcar una línea `detected:<name>` de una pestaña
lo añade, guarda los settings y marca `mcp:<name>` en esa pestaña, así
el modelo recibe sus tools enseguida. Después es un servidor como
cualquier otro (los mismos confirm modes, "always" por defecto). **Lo que
se descarga se ejecuta en un container, nunca en esta máquina:** un
comando que trae código al arrancar (`npx`, `bunx`, `pnpm dlx`, `yarn
dlx`, `npm exec`, `uvx`, `uv tool run`, `pipx run`, `docker`/`podman run`
…) se instala de forma aislada al marcarlo - el paquete npm o pypi se
construye en el container fijado de `node`/`python` (la última versión
exacta si el comando no nombra ninguna), una imagen se descarga y se
ejecuta con la línea de podman endurecida de axross, sin red; los flags
de una línea `docker run` (`--privileged`, `--network=host`, volúmenes,
`--cap-add`, `--device`, namespaces del host, `--security-opt` …) no se
adoptan, y los detalles dicen qué se descartó. Lo que no se puede
convertir (una URL de git, `--package`, `uv run`, una opción desconocida
…) se muestra pero no se puede marcar, con el motivo. Un programa que ya
está en el disco se ejecuta tal cual, en el sandbox profile de las
pestañas nuevas (Agent Settings) o de la pestaña donde se marcó, y lo
dice: *runs on this machine, not in a container*; uno que no está en
esta máquina no se puede marcar. Los ficheros solo se leen, como datos no fiables (ficheros regulares de hasta 8 MiB,
JSON o TOML, nada se ejecuta). Los valores de entorno que parecen
secrets (por el nombre - TOKEN, PASSWORD, API_KEY … - o por la forma) y
los tokens Bearer nunca llegan a un log ni a `agent.json`: activarlo
pregunta antes y los guarda en el keyring. Los programas del PATH no se
detectan: nada identifica ahí un servidor MCP sin ejecutarlo o adivinar
por su nombre.

Un catálogo propio tiene el esquema `axross-mcp-catalog`, versión 1
(ejemplo en [USAGE.md](USAGE.md)); `kind` es `oci` (fijado por
`digest`), `npm` o `pypi` (`package` y una `version` exacta) o `remote`
(`url`, `bearer`).

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
- **Idioma:** alemán o inglés, o *seguir la respuesta*. En alemán, los
  términos IT ingleses (Server, Backup, Pull Request, …) se dicen en
  inglés; también un término que la respuesta escribe entre `{llaves}`
  (las llaves no se muestran).
- **Voces** (una pestaña por idioma): la voz que habla el idioma (alemán:
  Thorsten o Kerstin, inglés: Ryan o Lessac), si está descargada,
  **Download** (un segundo clic cancela) y **Listen** - dice dos frases de
  ejemplo con los valores de la pestaña, guardados o no, por la salida de
  *Settings > Audio*; un segundo clic para. Cada voz guarda sus propios
  valores de cómo habla: *Speed* (0,5-2×), *Pitch* (±6 semitonos; Piper no
  tiene tono propio, así que el habla se genera tanto más lenta y luego se
  remuestrea tanto más aguda - su duración se mantiene), *Expressiveness*
  y *Rhythm variation* (cuánto varían el tono y la duración de los
  sonidos, 0-200 %), *Volume* (una parte del volumen de salida, 10-100 %)
  y *Pause between sentences* (0-2 s); *Reset* devuelve un valor,
  *Reset All* todos los de la voz. Cada respuesta hablada los usa.
- **Instalación:** `pip install axross[voice]` (piper-tts, faster-whisper;
  incluido en axross-full), luego **Download** junto a una voz en la
  página Voice, o *Help > Features…*, grupo **Voice**, para las voces y un
  modelo Whisper (checksums fijados, en `~/.local/share/axross/voice/`).
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
| Appearance | Theme, compact mode, monochrome icons, icon colours (Theme default; Own colours in every theme - también en Hacker y Amber, que dibujan cada icono en un color; One colour a elegir), tamaño de letra (zoom), resaltar hidden files y su color (un color difícil de leer en el theme solo tras preguntar) |
| Toolbar | Agrupar los botones por categoría, mostrar el color de cada categoría detrás de sus botones, el color de cada categoría (Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions), *Reset to Defaults* |
| Files & Panes | Mostrar hidden files, open size limit, workspaces en RAM (sí / no, límite de tamaño, memoria que queda libre) y ficheros temporales en RAM (al siguiente arranque) |
| Network & Proxy | El proxy por defecto, lista de bypass, script PAC, una prueba |
| LLM Profiles | Los servidores LLM de los docks Agent y Analysis; *Fetch models* abre una lista con tamaño, parámetros, cuantización y el modelo cargado de cada uno, en la medida en que el servidor los indica |
| Analysis (sift) | Análisis automático del archivo seleccionado (desactivado: una selección solo nombra el archivo, *Analyse* lo explica), el perfil LLM de *Analyse with LLM* (el activo, o uno propio - el Agent conserva su elección), máximo de bytes leídos por archivo (limita también la copia de un archivo remoto), time budget por archivo, vision, context tokens (0 = lo que indica el servidor), tags por archivo, categories (una por línea), guardar los resultados de sift en la cache, *Clear Cache*; la versión de sift, o un enlace a *Help → Features…* cuando esta build no tiene sift |
| Agent | General, Prompts, Access, Sandboxes, MCP Servers, MCP Sources, Sessions |
| Voice | Leer las respuestas en voz alta, idioma hablado, la voz de cada idioma (Download, Listen) y cómo habla (velocidad, tono, expresividad, variación del ritmo, volumen, pausa entre frases), modo del micrófono, tecla de mantener, texto reconocido insertado o enviado, la pausa que termina de hablar |
| Audio | Backend de audio (Automatic, PipeWire, PulseAudio; se muestra el de esta ejecución, un cambio se aplica en el próximo arranque), dispositivo de salida y volumen (escala todo lo que axross reproduce) con *Play Test Tone*, dispositivo de entrada y volumen (ganancia) con *Test Microphone* (un medidor de nivel) y *Record 3 s and Play Back*, el resultado de la comprobación de audio y *Check Audio Again* |
| Metadata | Cómo escribe Remove Metadata, preguntar antes |
| Search | Hosts buscados a la vez por *Find on Network Hosts*; dónde están el índice offline y el de duplicados |
| Security | Paranoid security mode (se mantiene al siguiente arranque; `AXROSS_SECURITY_MODE` en el entorno tiene prioridad), recordar la contraseña de sudo |
| Extensions | Qué extensions están activadas |
| Updates | Check for updates at start, descargar updates automáticamente, *Check Now*, el último check (ver [Updates](#updates)) |

La página **Analysis (sift)** escribe `~/.config/axross/analysis.json`;
el dock Analysis abierto usa un cambio guardado al momento y vuelve a
explicar el archivo en pantalla. Los límites son los de sift: un valor que
sift rechazaría (un context de 100 tokens, una category repetida) se
nombra encima de la página y no se guarda nada. Los resultados de sift se
guardan en la cache `~/.cache/axross/sift` (`$XDG_CACHE_HOME/axross/sift`,
legible solo por ti); *Clear Cache* borra allí las entradas de sift y nada
más. Un `analysis.json` roto se lee como los valores por defecto y se
conserva al lado como `analysis.json.unreadable-…` antes de que el
siguiente guardado lo sustituya.

La página **Audio** solo toca Qt Multimedia cuando la comprobación de
audio (un proceso aparte) ha respondido; si falla, la página da el motivo,
las pruebas quedan desactivadas y el backend se puede elegir y guardar
igualmente. Un dispositivo guardado que no está conectado sigue en su
lista como *(not connected)*: hasta que vuelva suena el predeterminado
del sistema. Un dispositivo conectado con la página abierta aparece al
momento.

**OK, Apply, Cancel** funcionan igual en todas las páginas: solo se
escriben las páginas cuyos valores cambiaron; OK y Apply comprueban antes
cada página cambiada y no guardan nada mientras una tenga un problema (se
muestra esa página y el problema encima); después cada página cambiada se
guarda y surte efecto al momento. Cancel, Esc y la [x] descartan lo no
aplicado.

*Tools → Network & Proxy…, LLM Profiles…, Agent Settings…, MCP Servers…, Metadata
Settings…* y *Extensions → Manage Extensions…* abren la ventana Settings en
su página. *View → Show Hidden Files* (**Ctrl+H**), *View → Theme* y *View
→ Zoom* siguen siendo interruptores rápidos; se guardan al momento, como la
página.

## Updates

Los binarios de un solo archivo (`axross-full`, `axross-slim`, y el
`axross-slim` de macOS y de Windows) se actualizan desde los releases de
GitHub de `c0decave/axross`:

- **Check al arrancar.** Una vez por arranque, unos dos segundos después
  de mostrarse la ventana, axross pregunta a la API de GitHub por el
  último release: una petición https, en segundo plano; el arranque nunca
  la espera. Una versión más nueva aparece como **Update to X.Y.Z…** a la
  derecha de la barra de estado y en el menú *Help*. Un check fallido (sin
  red, el rate limit de GitHub) es una línea en el log y el estado en
  *Settings → Updates*, nunca un diálogo. Los releases marcados como draft
  o prerelease se ignoran.
- **Help → Check for Updates…** comprueba al momento y muestra la
  respuesta, también cuando axross está al día.
- **La ventana de update** muestra esta versión y la nueva, las release
  notes y un enlace a la página del release, y ofrece **Download and
  Install**, **Skip This Version** (ningún aviso más para esa versión;
  preguntando a mano se sigue ofreciendo) y **Remind Me Later** (ningún
  aviso hasta el siguiente arranque).
- **Download and Install** descarga el binario de este build (axross-full
  recibe axross-full, un build slim su binario slim), comprueba su SHA-256
  contra el `SHA256SUMS` del mismo release (y contra el digest propio de
  GitHub del archivo) y rechaza todo lo que no coincida: entonces no se
  sustituye nada y el archivo parcial se borra. Un archivo verificado
  sustituye al binario en marcha con un rename atómico, con los permisos
  del archivo antiguo; el antiguo queda al lado como `<name>.previous`.
  Surte efecto en el siguiente arranque; **Restart Now** cierra axross
  (pregunta por el trabajo sin guardar como en cualquier cierre) y arranca
  la versión nueva.
- **Una carpeta sin permiso de escritura** (un binario instalado por root)
  no se toca: el archivo verificado va a `~/.cache/axross/update/` y
  **Save to…** deja una copia donde elijas.
- **Windows** no puede sustituir un programa en marcha: la versión nueva
  se guarda junto a la antigua como `axross-slim-windows-x64-X.Y.Z.exe`;
  cierra axross y sustituye el archivo antiguo por ella (o arranca la
  nueva).
- **Una instalación de Python** (pip o un checkout del código) nunca se
  sustituye; la ventana indica `pip install -U axross`.

*Settings → Updates*: **Check for updates at start** (activado),
**Download updates automatically** (desactivado: el aviso ofrece la
descarga; activado: una versión encontrada al arrancar se descarga,
verifica e instala en segundo plano y espera al siguiente arranque),
**Check Now** y la hora y el resultado del último check. Solo se contacta
con `github.com`, `api.github.com` y
`release-assets.githubusercontent.com`, por https; cada redirect se
comprueba contra esa lista. Se usa el proxy por defecto (*Network &
Proxy*); sin él, `https_proxy` del entorno. El check al arrancar no se
ejecuta con `AXROSS_NO_UPDATE_CHECK=1` en el entorno ni en el paranoid
security mode; *Check Now* sigue funcionando.

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
  recordar la contraseña de sudo, hosts buscados a la vez, el security mode,
  los ajustes de update (`update_check_at_start`, `update_auto_download`,
  una versión saltada, el último check).
- `~/.config/axross/proxy.json`, `llm.json`, `extensions.json` — el proxy
  por defecto, los perfiles LLM, las extensions activadas (secretos en el
  keyring).
- `~/.config/axross/agent/voice.json` — los ajustes de Voice (`0o600`).
- `~/.config/axross/audio.json` — los ajustes de Audio: backend,
  dispositivo de salida y de entrada, volúmenes (`0o600`).
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
