# Servidor MCP — guía detallada

Axross puede ejecutarse como servidor [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) para que un cliente LLM (Claude Desktop, Cline, un agente
propio) pueda trabajar sobre un árbol de directorios local mediante
una superficie JSON-RPC de herramientas. El servidor de la CLI
(`axross --mcp-server`, stdio o HTTP) sirve el sistema de ficheros
local (`LocalFS`), confinado a la raíz MCP. Los **grupos de
capacidades** opcionales (`--mcp-tools`, §9) añaden metadatos, el
Duplicate Finder, archivos comprimidos (crear, listar, extraer), cifrado, el índice
de búsqueda, la detección de tipo de fichero, transferencias entre
backends, perfiles de conexión guardados como backends adicionales y
la lista de extensiones. Un manifiesto legible por máquina de todas las
herramientas lo da `axross --mcp-list-tools` o
[`mcp-tools.json`](mcp-tools.json) (§9.7).

El servidor habla las revisiones de MCP **2025-11-25**, **2025-06-18** y
**2024-11-05**: `initialize` responde con la revisión del cliente si es
una de ellas y, si no, con la más nueva. Desde 2025-06-18 una sesión
recibe el título y las anotaciones de cada herramienta (`readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`), `outputSchema` y
`structuredContent`, y en HTTP la cabecera `MCP-Protocol-Version`; desde
2025-11-25 los argumentos rechazados vuelven como error de herramienta
(`isError`) en lugar de -32602. Detalles: [MCP.md §1.4](MCP.md#14-protocol-revisions).

Sin la interfaz gráfica: el paquete **axross-headless-mcp** (`pip install
axross-headless-mcp`, sin PyQt6) es este servidor con las mismas opciones, stdio por
defecto; la imagen `ghcr.io/c0decave/axross-headless-mcp` es el mismo en un
contenedor ([MCP.md §1.3](MCP.md#13-without-the-gui-axross-headless-mcp-and-the-docker-image)).
Ambos se publican con cada versión, y el servidor figura en el registro
oficial de MCP como `io.github.c0decave/axross-headless-mcp`.

Idiomas: [English](MCP.md) · [Deutsch](MCP_de.md) · **Español**

---

## 1. Transportes

### 1.1 Stdio

```bash
# Solo lectura; LocalFS, raíz MCP por defecto $HOME (cámbiala con --mcp-root):
axross --mcp-server

# Variante con variable de entorno (mismo comportamiento):
AXROSS_MCP=1 axross

# Las nueve herramientas de escritura (write_file, create_directory,
# delete_path, move_path, copy_file, copy_tree, create_symlink,
# create_hardlink, set_permissions). Path-traversal
# limitado a la raíz elegida. AXROSS_MCP_WRITE=1 es el equivalente
# por variable de entorno:
axross --mcp-server --mcp-write --mcp-root ~/data

# Herramientas de script (list_scripts, get_script_api, read_script,
# write_script, delete_script, run_script) — solo stdio:
axross --mcp-server --mcp-allow-scripts

# Grupos de capacidades (§9); AXROSS_MCP_TOOLS=metadata,archive es el
# equivalente por variable de entorno, 'all' activa todos los grupos:
axross --mcp-server --mcp-tools metadata,filetype
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools all

# Comandos y scripts en hosts remotos (§9.8): un opt-in propio que
# 'all' no incluye; sin variable de entorno equivalente:
axross --mcp-server --mcp-tools remote,exec --mcp-allow-exec

# Imprimir el manifiesto de herramientas (JSON) para unos flags, sin arrancar nada:
axross --mcp-list-tools --mcp-tools all --mcp-write
```

`--mcp-write` sin `--mcp-root` se rechaza (exit 2): la raíz por
defecto es tu directorio home, demasiado amplio para ser escribible.
Un `--mcp-root` que no existe se rechaza (exit 2). Un grupo
desconocido en `--mcp-tools` se rechaza (exit 2) con una línea en
stderr que enumera los grupos válidos.

`AXROSS_MCP=1` arranca el servidor solo sin `--script`: un
`axross --script FICHERO` explícito ejecuta el script (la variable la
hereda todo lo que arranca el entorno del cliente), y `--script` junto
con `--mcp-server`, `--mcp-http` o `--mcp-list-tools` se rechaza
(exit 2). Una ejecución de script (`run_script`, el hijo
`axross --script -` de un build frozen) no recibe ninguna variable
`AXROSS_MCP*`.

El security mode `paranoid` de abajo es el vigente al arrancar:
`AXROSS_SECURITY_MODE` si está definida, si no el modo elegido en
*Edit > Settings > Security*.

`--mcp-allow-scripts` se rechaza (exit 2) en el security mode
`paranoid`, y también junto con `--mcp-http` (exit 2): no se ofrece
ejecución de scripts sobre un transporte de red. Lo que pueden
alcanzar las herramientas de script está en §2.

`--mcp-allow-exec` se rechaza (exit 2) en el security mode `paranoid`,
y también sin el grupo exec (`--mcp-tools exec`, `all` o
`AXROSS_MCP_TOOLS=exec`): el flag solo no ofrece nada. A diferencia de
las herramientas de script no ejecuta nada en el propio host del
servidor, por eso se ofrece en ambos transportes; ver §9.8.

Los ficheros secretos no se leen, sea cual sea el root (§7.12): los
tokens y claves de axross y las claves privadas de `~/.ssh` y
`~/.gnupg`. `--mcp-allow-secret-reads` deja que las herramientas los
lean; solo por stdio (rechazado junto con `--mcp-http`, exit 2).

Las peticiones llegan por stdin (JSON delimitado por líneas), las
respuestas salen por stdout. Los logs solo por stderr. Cuando se
activa el modo MCP, PyQt no se importa — el servidor corre
limpiamente en máquinas sin pantalla.

### 1.2 HTTP (+ mTLS opcional)

`--mcp-http HOST:PORT` implica `--mcp-server` (`axross --mcp-http
127.0.0.1:7331` solo sirve HTTP; antes abría la ventana).

```bash
# HTTP loopback (sin TLS fuera de loopback se rechaza), token bearer obligatorio:
axross --mcp-server --mcp-http 127.0.0.1:7331
# [::1]:7331 para loopback IPv6

# mTLS — los tres ficheros son obligatorios; solo con ellos escucha fuera
# de loopback (0.0.0.0 sin ellos se rechaza):
axross --mcp-server --mcp-http 0.0.0.0:7331 \
    --mcp-cert server.pem --mcp-key server.key --mcp-ca trusted-ca.pem
```

HTTP sin TLS solo sirve en loopback; en un contenedor el host no lo
alcanza por `-p`: allí mTLS, o `--network host` con
`--mcp-http 127.0.0.1:7331`. Los cuerpos con `Transfer-Encoding: chunked`
se rechazan (400): un POST necesita `Content-Length`.

Endpoints:

| Método + ruta                        | Propósito                                                      |
|--------------------------------------|----------------------------------------------------------------|
| `POST /messages`                     | Enviar una petición JSON-RPC, recibir una respuesta.            |
| `GET /messages` (SSE)                | Abrir un flujo de eventos para notificaciones de la sesión.     |
| `DELETE /messages`                   | Terminar la sesión explícitamente.                              |
| `GET /health`                        | Sin autenticación; devuelve `{server, version}`.                |

**Token bearer en HTTP sin TLS.** Loopback no es una credencial: todo
usuario y proceso local alcanza `127.0.0.1`. Por eso un servidor sin
mTLS responde `401` a toda petición salvo `GET /health` que no lleve
`Authorization: Bearer <token>`. Al arrancar, el token se muestra una
vez por stderr y se escribe en
`$XDG_RUNTIME_DIR/axross/mcp-http-HOST-PORT.token` (si no, en
`~/.config/axross/`; fichero con modo 0600, carpeta 0700). Es nuevo en
cada arranque; `AXROSS_MCP_HTTP_TOKEN` lo fija para la configuración de
un cliente. El cliente MCP propio de axross (los servidores MCP externos
del agente, docs/USAGE.md) envía el token guardado en el keyring. Con
mTLS autentica el certificado del cliente; el token solo se exige allí
si `AXROSS_MCP_HTTP_TOKEN` está definido. En versiones anteriores un
servidor loopback sin TLS aceptaba cualquier proceso local sin
credencial - con `--mcp-tools remote,exec --mcp-allow-exec` otro usuario
de la máquina podía abrir los perfiles guardados y ejecutar comandos.

Las sesiones son obligatorias en HTTP. El primer `POST /messages`
con `initialize` recibe un identificador de sesión nuevo en la
cabecera `Mcp-Session-Id` de la respuesta; cada petición siguiente
debe llevarla. IDs desconocidos o expirados responden 404.

mTLS se construye con `CERT_REQUIRED` + TLS 1.2 mínimo: un cliente
que no pueda presentar un certificado firmado por el bundle de CA
se rechaza durante el handshake antes de que HTTP parsee nada.

El transporte HTTP sirve las herramientas de solo lectura, (con
`--mcp-write`) las de escritura y los grupos de `--mcp-tools`; nunca
sirve las herramientas de script.

---

## 2. Superficie de herramientas

Las herramientas de ficheros de abajo son siempre la base. Todo lo
demás (metadatos, duplicados, archivos comprimidos, cifrado,
construcción del índice, tipos de fichero, transferencias, perfiles
remotos, extensiones) es un grupo de capacidades, ver §9.

### Herramientas de solo lectura (siempre disponibles)

| Nombre                | Descripción                                                         |
|-----------------------|---------------------------------------------------------------------|
| `list_directory(path)`      | Entradas del directorio.                                            |
| `get_path_info(path)`          | Nombre, tipo, tamaño, mtime.                                        |
| `read_file(path, max_bytes=, encoding=, offset=)` | Contenido en base64; tope de 4 MiB por defecto. `encoding="text"` devuelve `text` (UTF-8, `replaced=true` si se sustituyeron bytes no decodificables) — para modelos que no saben decodificar base64. `offset` empieza en ese byte; si queda más (`truncated=true`), `next_offset` dice dónde seguir (una página de texto nunca termina a mitad de un carácter). El dock del Agent ajusta cada lectura a su límite de resultados de herramientas. |
| `compute_file_checksum(path, algorithm=)`  | `sha256` (por defecto), `sha1`, `md5` o `sha512`. Usa el hash nativo del backend solo si es del algoritmo pedido; si no, hace streaming por hashlib (emite progreso). |
| `search_index(pattern, ext, min_size, max_size, max_results)` | Índice de metadatos offline, acotado al backend activo y a la raíz MCP; como mucho `max_results` resultados (por defecto 1000, como mucho 10 000), una cancelación la detiene. |
| `walk_tree(path, max_depth, max_entries)`      | Listado recursivo acotado; emite `notifications/progress`. Las carpetas que no se pudieron listar aparecen en `unreadable`; `complete` es false entonces. |
| `compute_tree_checksums(path, algorithm, max_files, max_depth, max_file_bytes)` | Hashea cada fichero bajo una ruta (por defecto salta ficheros de más de 1 GiB); un frame de progreso por fichero hasheado. Una carpeta que no se pudo listar es un registro `error` con `folder: true`; `complete` dice si se hasheó cada fichero. |
| `search_content(pattern, path, max_depth, max_matches)` | Regex sobre contenido. Salta ficheros >4 MiB, tope 500 coincidencias; emite progreso. Carpetas y ficheros ilegibles aparecen en `unreadable`; ninguna coincidencia con `complete: false` no es una respuesta. |
| `list_file_versions(path)` | Metadatos por versión donde el backend lo soporte.                 |
| `read_file_version(path, version_id, max_bytes=)` | Contenido base64 de una versión concreta.      |
| `render_preview(path, edge=256)` | Miniatura de imagen — devuelta como MCP **image content** con mimeType correcto. |

### Herramientas de escritura (solo con `--mcp-write`)

| Nombre                            | Descripción                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content \| content_b64)` | Subida: `content` como texto UTF-8 o `content_b64` como bytes en base64, exactamente uno. |
| `create_directory(path)`                     | Crear directorio.                                                          |
| `delete_path(path, recursive=False)`   | Borrar.                                                                    |
| `move_path(src, dst)`                | Renombrar / mover.                                                         |
| `copy_file(src, dst)`                  | Copia server-side donde exista; fallback por streaming.                    |
| `copy_tree(src, dst, max_files, max_depth, max_file_bytes, overwrite)` | Copia de árbol (por defecto salta ficheros de más de 10 GiB); un frame de progreso por fichero copiado. |
| `create_symlink(target, link_path)`      | `link_path` debe estar bajo la raíz; `target` **no** se comprueba contra la raíz a propósito (puede quedar colgando o apuntar fuera — las herramientas posteriores resuelven los enlaces con `_enforce_root` antes de seguirlos). No se comprueba ningún flag de capability; un backend sin symlinks hace fallar la llamada. |
| `create_hardlink(target, link_path)`     | Ambos extremos deben estar bajo la raíz. No se comprueba ningún flag de capability; un backend sin hardlinks hace fallar la llamada. |
| `set_permissions(path, mode)`               | Bits de modo POSIX. Acepta entero o string octal.                          |

Cada herramienta de escritura resuelve sus rutas primero mediante
`_enforce_root` — un payload como `/etc/passwd` se rechaza antes
de cualquier IO (la única excepción es el `target` de `create_symlink`,
ver arriba). Cada llamada emite entradas de auditoría en el logger
`core.mcp_server.audit`, con herramienta, resultado, ruta y tamaño
— nunca los bytes del payload.

### Herramientas de script (solo con `--mcp-allow-scripts`, solo stdio)

| Nombre                        | Descripción                                                       |
|-------------------------------|-------------------------------------------------------------------|
| `list_scripts()`               | Nombres de los scripts guardados en `~/.config/axross/scripts/`.  |
| `get_script_api(names?)`   | La API `axross.*` como JSON (igual que `axross.api_schema(names)` y [`scripting-api.json`](scripting-api.json)): reglas y excepciones para scripts; por función firma, parámetros con tipos, tipo de retorno, docstring completo, ejemplos, `raises`, `mutates`, `prompts`; las clases públicas, los tipos que devuelve la API y los métodos de toda sesión de backend. `names: []` da solo el índice, una lista de nombres solo esos. Solo lectura. |
| `read_script(name)`           | Código fuente de un script guardado.                              |
| `write_script(name, source)`  | Guarda `<name>.py` (modo 0600); sobrescribe.                      |
| `delete_script(name)`         | Borra un script guardado; idempotente.                            |
| `run_script(name, args?, timeout?)` | Ejecuta un script guardado en un proceso Python propio con `axross.*` disponible; `args` pasan a ser `sys.argv[1:]`. Devuelve una respuesta estructurada (abajo). |

`run_script` en detalle — en qué puede confiar un cliente:

* **Un proceso hijo, nunca el servidor.** stdin está vacío: `input()`
  recibe `EOFError` y nunca puede leer el stream JSON-RPC. El hijo
  corre en un grupo de procesos propio; al terminar la ejecución
  terminan todos los procesos que arrancó (uno que llama a `setsid` se
  escapa).
* **Wall clock.** `timeout` (por defecto 60, como máximo 600) detiene
  la ejecución: SIGTERM al grupo, SIGKILL 3 s después. `axross/tasks/start` +
  `axross/tasks/cancel` ejecutan y detienen un script en segundo plano.
* **Respuesta.** `{name, exit, timed_out, duration_ms, stdout, stderr,
  namespace_keys}`; tras una excepción no capturada además
  `error_type`, `error` y un `traceback` acotado (solo los frames del
  script). `exit` sigue a `SystemExit` con exactitud (`None` es 0, un
  int es él mismo, también por encima de 255, cualquier otra cosa va a
  stderr y da 1); una ejecución detenida tiene el número de señal
  negativo. `namespace_keys` son los nombres de nivel superior que deja
  el script (como máximo 500).
* **Salida.** stdout y stderr guardan hasta 1 MiB de caracteres cada
  uno; más detiene la ejecución y la llamada falla (`script output
  exceeded …`).
* **Sin humano.** El hijo corre con `AXROSS_NONINTERACTIVE=1`:
  `axross.confirm()` lanza `NonInteractiveError` salvo que el script
  pase `assume_yes=True`, y una escritura en un perfil marcado
  *production* se rechaza salvo que el servidor arrancara con
  `AXROSS_TARPIT_DISABLE=1`. `get_script_api` marca cada función que
  puede necesitar a un humano (`prompts`) o cambiar estado (`mutates`).
* **Argumentos.** `args`: como máximo 64 strings de como máximo 4096
  caracteres, sin NUL; un `args` o `timeout` incorrecto se rechaza
  antes de ejecutar nada (`-32602`).

**Nota de seguridad:** las herramientas de script **no** están
confinadas a la raíz MCP en absoluto. Los nombres se limitan a
`[A-Za-z0-9_-]+` dentro del directorio de scripts, pero `run_script`
ejecuta Python arbitrario con los permisos del usuario del servidor:
puede leer y escribir todo lo que ese usuario pueda, abrir conexiones
de red y usar cualquier backend de `axross.*`. Trata
`--mcp-allow-scripts` como entregarle una shell al cliente. Se rechaza
en el security mode `paranoid` y con `--mcp-http`. `write_script`,
`delete_script` y `run_script` dejan líneas attempt / ok / refused en
`core.mcp_server.audit` (nombre, tamaño, código de salida, `timed_out`,
el tipo de excepción — nunca el código fuente, los argumentos ni la
salida del script).

### Capability: resources

Cuando el servidor se construye con catálogo de recursos, se
publican tres endpoints adicionales:

| Método                         | Propósito                                                    |
|--------------------------------|--------------------------------------------------------------|
| `resources/list`               | Hasta 100 entradas directamente bajo la raíz configurada.    |
| `resources/templates/list`     | Una plantilla de URI para cualquier ruta absoluta.           |
| `resources/read`               | Obtener un `axross://<ruta>` concreto.                      |

Mimes tipo texto devuelven `{uri, mimeType, text}`; cualquier
otro (o un `.txt` cuyos bytes no sean UTF-8 válido) cae a
`{uri, mimeType: octet-stream, blob: b64(bytes)}`.

### Capability: logging

Ambos transportes instalan un único `_LogForwarder` por servidor
(stdio escribe en stdout; HTTP envía cada registro al flujo SSE de la
sesión en la que se emitió). Ciertos registros se reenvían al cliente
como frames `notifications/message`. Solo se reenvían los loggers
`core.mcp_server` y `core.mcp_server.audit` — el chatter de backends
ajenos no se filtra. El umbral por defecto es `warning`; las líneas de
auditoría son `info`, así que solo llegan al cliente si baja el nivel.

El cliente puede ajustar el umbral en vivo:

```json
{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
 "params": {"level": "debug"}}
```

Niveles aceptados: `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency`.

**En HTTP el nivel es global del servidor, no por sesión:** hay un
único forwarder compartido, así que un `logging/setLevel` desde
cualquier sesión cambia el umbral de todas las sesiones de ese
servidor. El enrutado sigue siendo por sesión — cada sesión solo
recibe sus propios registros —, pero un cliente puede hacer más o
menos verbosos los flujos de todos los clientes.

### Otros métodos

| Método          | Propósito                                                               |
|-----------------|-------------------------------------------------------------------------|
| `initialize`    | Handshake; responde versión de protocolo, info del servidor y capabilities. |
| `ping`          | Liveness check de MCP; resultado vacío.                                 |
| `tools/list`    | El catálogo de herramientas con sus input schemas.                      |
| `tools/call`    | Ejecuta una herramienta de forma síncrona.                              |
| `axross/tasks/start`   | **Extensión de Axross, no forma parte de MCP.** Lanza una herramienta en segundo plano; devuelve `task_id`. Mismo chequeo de schema, mismo rate limit y mismo timeout por herramienta que `tools/call`; como máximo 8 tareas en ejecución por scope (`MAX_RUNNING_TASKS_PER_SCOPE`). |
| `axross/tasks/status`  | Estado, último progreso y, al terminar, resultado o error.              |
| `axross/tasks/cancel`  | Cancela una tarea en ejecución.                                         |
| `axross/tasks/list`    | Resumen breve de las tareas del scope.                                  |

Las tareas tienen scope por sesión en HTTP y global del servidor en
stdio. Las tareas terminadas se conservan una hora
(`TASK_RETENTION_SECONDS`); cuando un scope supera las 100 tareas
(`MAX_TASKS_PER_SCOPE`) se expulsan antes las terminadas más antiguas.
Los resultados de más de 16 MiB se convierten en error.

---

## 3. Progreso, cancelación, timeouts

### 3.1 Progreso

Pasa `_meta.progressToken` en un `tools/call` y el servidor emite
frames `notifications/progress` desde los handlers que lo soportan:
`walk_tree` (entradas visitadas), `search_content` (ficheros escaneados), `compute_file_checksum`
(bytes hasheados, solo en el fallback por streaming),
`compute_tree_checksums` (ficheros hasheados) y `copy_tree` (ficheros
copiados), además de las herramientas largas de los grupos de §9
(`read_metadata` / `export_metadata` sobre carpetas, `strip_metadata`,
`scan_file_types`, `scan_duplicates`, `trash_duplicates`,
`build_index`, `create_archive`, `extract_archive`, `copy_path_to_backend`). `total` solo
se envía cuando se conoce (los bytes de un fichero, los ficheros de una
lista); un recorrido no conoce su cuenta, y su límite (`max_entries`,
`max_files`) no es un total, así que esos frames no lo llevan. Dentro de una tarea de `axross/tasks/start` las mismas
herramientas reportan progreso con el `task_id` como token. En stdio
los frames van a stdout por el mismo lock que cada respuesta, así que
frames de threads distintos nunca se entremezclan dentro de una línea;
en HTTP se encolan por sesión y se entregan por el flujo SSE
(`GET /messages`).

### 3.2 Cancelación

Los clientes envían `notifications/cancelled` con `requestId`. Un
registro de cancelación (por sesión en HTTP, por servidor en stdio)
activa un `threading.Event` que todo handler largo consulta mediante
`ctx.check_cancel()`. El handler lanza `CancelledError`, el
dispatcher responde -32603 con `data.type = "CancelledError"`, y el
cliente descarta la respuesta.

**Limitación conocida — stdio:** el bucle de stdio es de un solo
thread. Mientras corre un `tools/call` síncrono, el bucle lo espera y
no lee más entrada, así que un `notifications/cancelled` para esa
llamada solo se lee cuando ya ha terminado. En stdio, por tanto, un
`tools/call` síncrono solo lo detiene su timeout (§3.3). El trabajo
que deba poder cancelarse en stdio va por `axross/tasks/start` +
`axross/tasks/cancel`, que funciona en ambos transportes. En HTTP cada
petición corre en su propio thread, así que `notifications/cancelled`
sí alcanza una llamada en curso.

### 3.3 Timeouts

Toda herramienta tiene un límite de tiempo real:

| Clase (`timeout_class`) | Timeout | Herramientas                                                              |
|------------|---------|---------------------------------------------------------------------------|
| `quick`    | 15 s    | `get_path_info`, `read_file`, `list_directory`, `search_index`, `list_file_versions`, `read_file_version` y toda herramienta sin entrada propia — incluidas las de script salvo `run_script` |
| `walk_tree`     | 60 s    | `walk_tree`, `search_content`                                                            |
| `render_preview`  | 30 s    | `render_preview`                                                                 |
| `write`    | 30 s    | `write_file`, `create_directory`, `delete_path`, `move_path`, `copy_file`, `create_symlink`, `create_hardlink`, `set_permissions` |
| `stream`   | 300 s   | `compute_file_checksum`, `compute_tree_checksums`, `copy_tree`                             |
| `long`     | 1800 s  | trabajos sobre árboles enteros de los grupos (§9): `scan_duplicates`, `trash_duplicates`, `build_index`, `create_archive`, `extract_archive`, `copy_path_to_backend`, `move_file_to_backend`, `strip_metadata` |
| `script`   | 610 s   | `run_script`. Detiene a su hijo ya en su propio `timeout` (por defecto 60 s, como máximo 600 s); la clase suma el grace del kill y el drenaje de la salida, así que el deadline solo respalda |

La clase de cada herramienta de grupo está en el manifiesto (§9.7).
Una tarea de `axross/tasks/start` recibe el mismo timeout que su herramienta.

Dos mecanismos paralelos respaldan el plazo:

1. Un `threading.Timer` activa el cancel event del handler al
   expirar el plazo. Los handlers que consultan
   `ctx.check_cancel()` (`walk_tree`, `search_content`) salen limpiamente en el
   siguiente tick.
2. El dispatcher ejecuta el handler en un thread worker dedicado
   y hace join con el mismo timeout. Si el handler está atascado
   dentro de una sola llamada de IO bloqueante (`backend.read_file`
   sobre un blob enorme, `backend.checksum` hasheando SFTP lento),
   el join devuelve control al dispatcher para que el **cliente**
   se desbloquee y reciba `ERR_TIMEOUT` — aunque el thread de
   fondo pueda seguir corriendo y completar su efecto lateral
   eventualmente.

En el caso de hard-stop la respuesta lleva `data.hard_stop = true`
para que los clientes distingan que el servidor dejó de esperar
(frente a un cancel cooperativo donde el handler se detuvo en
medio del trabajo).

Código de error **-32002** con `data.type = "TimeoutError"` en
ambos casos, distinto del cancel iniciado por cliente (-32603,
`CancelledError`).

**Advertencia honesta:** el hard-stop *no* aborta la llamada del
backend. Un `write_file` con timeout puede aún escribir bytes en
el remoto. Un `delete_path` con timeout puede aún borrar la ruta. El
cliente ve una respuesta de timeout; el operador debería asumir
estado desconocido de la operación y o bien verificar o volver a
emitir con una idempotency-key adecuada. No podemos interrumpir
IO bloqueante arbitrario de forma segura; quien diga lo contrario
miente o corre bajo fork().

---

## 4. Rate limiting

Activado por defecto: burst de 30 tokens, refill de 1 token/seg
(60 llamadas por minuto en régimen estable). `tools/call` y
`axross/tasks/start` consumen del mismo bucket (uno por servidor en stdio,
uno por sesión en HTTP); `tools/list`, `initialize`, `ping`,
`resources/*`, `axross/tasks/status|cancel|list` y `logging/setLevel` siguen
libres.

Rechazo: -32001 con `data.type = "RateLimitError"`. Un `axross/tasks/start`
por encima del tope de tareas en ejecución también es -32001, con
`data.type = "TaskLimitError"`.

Ajustable mediante `ServerConfig.rate_burst` /
`rate_refill_per_sec`; desactivable con
`rate_limit_enabled = False`.

---

## 5. Multi-backend

Desde la CLI, el grupo `remote` (§9.5) es el camino a más backends:
`open_remote_profile` convierte un perfil de conexión guardado en el backend
`profile:<nombre>`, y el `LocalFS` por defecto recibe el id `local`.
Si incrustas el servidor desde Python también puedes pasar un dict
`{id: backend}` como `ServerConfig.backends` (o
`HTTPServerConfig.backends`). En ambos casos:

 - Una herramienta de solo lectura `list_backends` devuelve
   `[{id, class, name, is_default, remote}]` (los perfiles abiertos
   añaden `profile`, `protocol`, `production`) para que el LLM los
   enumere.
 - Cada otra herramienta añade un campo opcional `backend: string`
   en su inputSchema (no las que nombran sus backends ellas mismas,
   como `copy_path_to_backend`, ni las que no tocan ninguno). Sin él →
   default; con ID → routing. IDs desconocidos caen en -32602.
 - Los backends de un registro estático de librería quedan confinados
   a la raíz MCP como el de por defecto; los perfiles abiertos con
   `open_remote_profile`, no (§9.5).

Ejemplo:

```python
from core.mcp_server import ServerConfig, serve
from core.local_fs import LocalFS
from core.s3_client import S3Backend

serve(ServerConfig(
    backend=LocalFS(),           # default
    backends={
        "home": LocalFS(),
        "bucket": S3Backend(…),
    },
))
```

---

## 6. Ciclo de vida de una sesión HTTP

```
┌──────────┐                                 ┌──────────┐
│ Cliente  │  POST /messages  {initialize}   │ Servidor │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │  200  Mcp-Session-Id: <uuid>    │          │
│          │ <────────────────────────────── │          │
│          │                                 │          │
│          │  GET  /messages  (SSE)          │          │
│          │       Mcp-Session-Id: <uuid>    │          │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │   data: notifications/progress  │          │
│          │   data: notifications/message   │          │
│          │ <────────────────────────────── │          │
│          │                                 │          │
│          │  POST /messages  {tools/call}   │          │
│          │       Mcp-Session-Id: <uuid>    │          │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │  DELETE /messages               │          │
│          │       Mcp-Session-Id: <uuid>    │          │
└──────────┘                                 └──────────┘
```

 - Las sesiones ociosas se expulsan tras 10 minutos (ajustable), contados
   desde el final de su última petición. Una sesión en trabajo nunca se
   expulsa: un `tools/call` en curso, una tarea en curso o un flujo SSE
   abierto cuentan como actividad. En el tope de sesiones (256) un
   `initialize` expulsa la sesión ociosa más antigua - ociosa 30 s o más y
   sin trabajo - en vez de responder 503; con mTLS un cliente tiene como
   mucho 32 sesiones, en loopback solo cuenta el tope del servidor. Cada
   sesión tiene su propio cubo de tasa y su cliente uno compartido cuatro
   veces mayor, y una reserva de la mitad de su tasa cuando el compartido
   está vacío; como mucho 16 llamadas por sesión a la vez; 256 conexiones
   (lleno, una nueva sustituye a la más antigua que aún envía su petición;
   fuera de loopback 32 por dirección); una petición debe leerse en 15 s.
   En el tope de sesiones también se van las que solo mantienen su flujo
   SSE (30 s sin petición), las últimas y del cliente con más sesiones.
 - Tope de cola por sesión: 10 000 notificaciones. Un cliente
   que nunca drene su SSE no hace crecer la memoria sin
   control — los frames excedentes se descartan con aviso en log.
 - Keepalive SSE: una línea de comentario cada 15 s para que
   proxies idle-killer no tiren el flujo.

---

## 7. Endurecimiento de seguridad

Cada punto aquí es un guard explícito contra un escenario de
red-team que se pensó. Los tests de MCP están en
`tests/test_mcp_*.py`:

| Fichero | Cubre |
|---------|-------|
| `tests/test_mcp_error_redaction.py` | Los secretos en textos de error del backend se redactan (tools/call, tareas, compute_tree_checksums). |
| `tests/test_mcp_http_bearer_token.py` | HTTP sin TLS rechaza peticiones sin token bearer (401, `/health` exento), el fichero del token es 0600 y nunca se escribe a través de un symlink, `--mcp-http` siempre sirve con token. |
| `tests/test_mcp_http_hardening.py` | DNS rebinding (Host/Origin), tope de sesiones y expulsión por inactividad, params/ids malformados, flags TLS incompletos, cliente TCP inactivo vs. accept. |
| `tests/test_secfix_r7_host_header.py` | `Host` leído estrictamente como `host[:puerto]` (`localhost:1@evil`, rutas, espacios, IPv6 sin corchetes rechazados); dos cabeceras `Host`/`Origin` rechazadas (MCP HTTP y reverse-serve). |
| `tests/test_mcp_http_sse_lifecycle.py` | Un flujo SSE por sesión, DELETE/expulsión lo terminan, replay al reconectar. |
| `tests/test_mcp_search_root.py` | `search_index` nunca devuelve rutas indexadas fuera de la raíz. |
| `tests/test_mcp_tasks_limits.py` | Rate limit de `axross/tasks/start`, tope de tareas en ejecución, timeout de la herramienta. |
| `tests/test_mcp_write_root.py` | `--mcp-write` exige `--mcp-root`; `--mcp-allow-scripts` rechazado con `--mcp-http`. |
| `tests/test_mcp_secret_reads.py` | Los ficheros secretos (§7.12) no se leen, ni se buscan con grep, ni se hashean, ni se previsualizan, copian, mueven o enlazan con hardlink, tampoco por un symlink, una herramienta de grupo o `resources/read`; sus nombres se listan; `--mcp-allow-secret-reads` (solo stdio) permite leerlos. |
| `tests/test_mcp_http_mode.py` | `--mcp-http` solo arranca el servidor HTTP (abría la ventana) y no se separa del terminal. |
| `tests/test_mcp_script_audit.py` | Las herramientas de script escriben la auditoría, sin código fuente ni salida. |
| `tests/test_mcp_script_run_child.py` | `run_script` en un proceso hijo: timeout y kill del grupo, no queda ningún nieto, `input()` nunca lee el stream stdio, cancelación, tope de salida, validación de argumentos, respuesta estructurada. |
| `tests/test_mcp_stdio_write_lock.py` | Escritores concurrentes en stdio nunca se entremezclan dentro de una línea. |
| `tests/test_mcp_tools_flag.py` | Parseo de `--mcp-tools` / `AXROSS_MCP_TOOLS`, exit 2 con grupo desconocido, superficie por defecto sin cambios, `all` de solo lectura sin herramientas que modifican. |
| `tests/test_mcp_group_metadata_filetype.py` | Grupos `metadata` y `filetype`: escapes de la raíz, symlinks, nunca sobrescribir, auditoría. |
| `tests/test_mcp_group_duplicates_index.py` | Grupos `duplicates` e `index`: filas del índice fuera de la raíz nunca aparecen, recomprobación antes del dedupe, papelera bajo la raíz. |
| `tests/test_mcp_group_packer_archive.py` | Grupo `archive` (crear y extraer): zip-slip, la contraseña nunca en el log, cancelar no deja nada. |
| `tests/test_mcp_group_crypto.py` | Grupo `crypto`: la passphrase nunca en respuestas, errores ni auditoría; nunca sobrescribir. |
| `tests/test_mcp_group_remote_transfer.py` | Grupos `remote` y `transfer`: sin secretos en la lista, sin prompts, host keys, perfiles de producción, alcance por sesión, copia reanudable. |
| `tests/test_exec_everywhere.py` | `exec()` de Telnet, rsh, ADB, WinRM y Cisco: el estado de salida como `returncode`, stdin por un fichero temporal, claves de env comprobadas y valores entrecomillados, límites de salida, Cisco solo `show`. |
| `tests/test_mcp_group_exec.py` | Grupo `exec`: desactivado sin `--mcp-allow-exec` (también con `all`), rechazado en modo `paranoid`, backends sin shell rechazados, intérprete por backend, los perfiles de producción no ejecutan nada, auditoría sin comando, stdin ni salida. |
| `tests/test_mcp_group_extensions.py` | Grupo `extensions`: listar nunca importa una extensión. |
| `tests/test_mcp_manifest.py` | `--mcp-list-tools` y el `docs/mcp-tools.json` del repositorio siguen sincronizados con el código. |
| `tests/test_mcp_protocol_matrix.py` | Cada protocolo registrado tiene una vía: `open_remote_profile` alcanza cada protocolo de perfil (la contraseña guardada llega, se escriben y releen ficheros), el inicio de sesión en navegador y el modo `paranoid` se rechazan con su motivo, los backends solo por URL se abren con `axross.open_url`. |
| `tests/test_mcp_docs_group_table.py` | La tabla del §9.2 de este fichero y de sus versiones inglesa y alemana lista exactamente las herramientas de grupo de `docs/mcp-tools.json`. |
| `tests/test_mcp_groups_e2e.py` | El servidor real por stdio y HTTP con `--mcp-tools all`: una llamada por grupo, `axross/tasks/start` + `axross/tasks/cancel`. |
| `tests/test_fuzz_mcp.py` | Peticiones hostiles contra el dispatcher, ambos transportes y cada herramienta de grupo. |

§7.1, §7.5, §7.7, §7.8, §7.11 y el hard-stop de §7.4 aún no tienen
test propio en ese conjunto.

### 7.0 Las herramientas de script no están confinadas a la raíz

La raíz MCP (§7.1) solo confina las herramientas de ficheros. Las
herramientas de script (`--mcp-allow-scripts`, solo stdio) ejecutan
Python arbitrario como el usuario del servidor (en un proceso hijo,
así que un script no puede bloquear el servidor ni leer su stream de
protocolo) y no están confinadas a nada — ver §2.

### 7.1 Escape de filesystem — root-check que resuelve symlinks

`_enforce_root` hace dos pasadas: primero `abspath` para colapsar
`..`/`.`, luego `realpath` para resolver symlinks y volver a
chequear el prefijo contra la root resuelta. Sin la segunda
pasada, un symlink colocado bajo la root (externamente o por el
propio LLM usando la herramienta de escritura `create_symlink`) apunta
a `/` y dejaría pasar
`write_file("/root/escape/etc/cron.d/evil")`. Ahora
`PermissionError`, respondido como resultado de herramienta con
`isError` y `_meta.type = "PermissionError"` y un texto que nombra la raíz (§8). Los
grupos de capacidades (§9) pasan cada ruta local por la misma
comprobación. Las herramientas que comprueban muchas rutas en una
llamada (`search_content`, `search_index`, `compute_tree_checksums`) resuelven la root una
vez por llamada y cada ruta por separado; la siguiente llamada resuelve
la root de nuevo, así que una root redirigida mientras el servidor corre
la ve la siguiente llamada.

`delete_path`, `move_path` y `move_file_to_backend` actúan sobre la propia entrada
del directorio: tras la misma comprobación solo resuelven el padre
(`_enforce_root_entry`), así que sobre un symlink borran o mueven el
enlace, nunca la carpeta o el archivo al que apunta. Un enlace que
apunta fuera de la raíz sigue rechazado.

### 7.2 Demux de log — sin fuga entre sesiones

Hay exactamente **un** `_LogForwarder` por servidor, conectado al
árbol `core.mcp_server`. Un `contextvars.ContextVar` puesto al
entrar al dispatcher le dice a `emit()` a qué cola de sesión
rutear el record. El SSE de la sesión A nunca recibe frames
emitidos durante tool-calls de B. El diseño anterior de "un
forwarder por sesión" filtraba silenciosamente porque el logging
de Python es aditivo.

### 7.3 Forwarder se desregistra al drop de sesión

`_SessionRegistry.drop` y `evict_idle` quitan el sink del
forwarder antes de descartar la sesión. Sin ese paso, el
forwarder seguía llenando la cola muerta hasta `queue.Full`, que
logeaba un warning, que disparaba el forwarder, que escribía en
cada cola muerta — bucle amplificador de logs. Ahora: el sink va
con la sesión.

### 7.4 Timeout hard-stop

Ver §3.3. Resumen: los handlers corren en un worker thread
dedicado con `join(timeout)`. Si el worker queda atascado en una
llamada IO bloqueante de backend, el dispatcher igual retorna
`ERR_TIMEOUT` con `data.hard_stop = true`; el worker queda como
zombie (no se puede interrumpir IO bloqueante de forma segura),
pero el cliente se desbloquea.

### 7.5 Preflight contra ReDoS en search_content

Antes de `re.compile`, el patrón se valida:

 - Tope de longitud (512 caracteres).
 - Heurística de cuantificador anidado sin cota (`(…+)+`,
   `(…*)*`, etc.)

Los patrones con backtracking catastrófico se rechazan con
-32602 y mensaje accionable. No cubierto: backtracking por
alternación (`(a|a)+`) — para esos el hard-stop de 60 s de §3.3
es el backstop.

### 7.6 Rate limiter por sesión

Cada `_HttpSession` tiene su propio token bucket. Un cliente
hostil drena sus propios tokens sin afectar otras sesiones en el
mismo servidor. Config: `rate_burst`, `rate_refill_per_sec` en
`HTTPServerConfig` (defaults 30 burst, 1 token/s refill).

### 7.7 Tope por IP en el edge HTTP

Antes del parsing de body / lookup de sesión / dispatch,
`do_GET` / `do_POST` / `do_DELETE` consultan un bucket por IP
(`_PerIPRateLimiter`). Un flood de POSTs malformados o no
autenticados no puede quemar CPU en el pipeline JSON-RPC.
`/health` está exento para que los probes de reverse-proxy no se
hambreen a sí mismos. Entradas inactivas > 5 min se GCean.
Config: `http_ip_burst`, `http_ip_refill_per_sec`,
`http_ip_rate_enabled` (defaults 120 burst, 60 req/s).

### 7.8 Session-id atada al fingerprint del client cert

En `initialize`, el servidor snapshottea SHA-256 del DER del
cert del peer sobre `_HttpSession.cert_fingerprint`. Cada POST /
DELETE / SSE posterior re-deriva el fingerprint y rechaza con
403 si no coincide. Un `Mcp-Session-Id` filtrado es inútil para
quien presente otro cert. Sesiones no-TLS (loopback) no tienen
fingerprint ni binding; en su lugar cada petición debe llevar el
token bearer (§1.2), así que un session id filtrado tampoco sirve
de nada allí.

### 7.9 Audit "attempt" antes de la llamada al backend

Cada herramienta de escritura — y `write_script`, `delete_script`,
`run_script` — emite `outcome=attempt` ANTES de invocar al backend
(o al script), luego `outcome=ok` o `outcome=refused`.
Un crash entre una llamada backend exitosa y la línea "ok" deja
rastro: los operadores ven "attempt" sin outcome y saben que el
estado es desconocido.

### 7.10 Decode de URI de recurso + strip de query/fragment

`_parse_resource_uri` decodifica bytes percent-encoded
(`%2e%2e%2f` → `../`) antes de que `_enforce_root` vea el path —
así los intentos de traversal codificados los agarra la pasada
de realpath de §7.1. Los query strings y fragments se quitan
para que no filtren a paths específicos del backend.

### 7.11 `list_backends` — default único

Cuando un operador registra la misma instancia de backend bajo
dos ids, solo la primera reclama `is_default = true`. Antes el
chequeo por identidad decía que ambas eran default, lo que
confundía a los clientes eligiendo la primaria.

### 7.12 Los ficheros secretos no se leen

El root por defecto es la carpeta home, y algunos ficheros de ahí
convierten "lee mis ficheros" en las cuentas del usuario. Ninguna
herramienta entrega su contenido, sea cual sea el root
(`core.protected_places.read_refusal`):

* los tokens de axross: `~/.config/axross/*token*` (los refresh tokens
  de Google Drive, OneDrive y Dropbox de cada perfil, el token de MCP
  HTTP; también `$XDG_RUNTIME_DIR/axross/*token*`);
* sus claves: el estado de las cuentas de chat
  (`~/.local/state/axross/chat/`, claves y tokens de sincronización),
  las link keys de Bluetooth (`bluetooth-direct-keys.json`), la clave
  ADB que creó (`~/.android/adbkey`);
* todo fichero de `~/.ssh` salvo `*.pub`, `known_hosts`,
  `authorized_keys` y `config` (una clave privada puede tener cualquier
  nombre);
* `private-keys-v1.d/`, `openpgp-revocs.d/` y `secring.gpg` de GnuPG.

Rechazado: `read_file`, `compute_file_checksum`, `render_preview`, `read_file_version`,
`resources/read`; en `search_content` y `compute_tree_checksums` un fichero así consta
como ilegible; `copy_file`, `copy_tree`, `move_path` y `create_hardlink` no lo aceptan
(ni una carpeta que lo contenga) como origen; los grupos (§9) lo ven
fuera del root. Un symlink a un secreto se resuelve y se rechaza. Los
nombres se siguen listando (`list_directory`, `walk_tree`, `get_path_info`, `search_index`). En el
sandbox del agente cuenta también el home del host. En cualquier sitio
(también en una carpeta de proyecto): un fichero con una clave privada o
una base de contraseñas (una firma de KeePass al principio; `-----BEGIN …
PRIVATE KEY-----`, OpenSSH o PuTTY en su primer MiB, también tras los
certificados de un bundle), y los ficheros secretos por su nombre (`.env`,
`.env.*` salvo `.example`/`.sample`/`.template`/`.dist`, `*.env`,
`.envrc`, `.netrc`, `.git-credentials`, `.pgpass`, `.npmrc`, `.pypirc`,
`.htpasswd`, `*.tfstate`, `*.kdbx`, `id_rsa`, `id_ed25519`, `id_ecdsa` y
sus copias como `id_rsa.bak`, `*.ppk`, `*.p12`, `*.pfx`, `kubeconfig`,
`credentials.json`, `client_secret*.json`, `secrets.yaml`,
`secrets.json`, `.aws/credentials`, `.docker/config.json`,
`.kube/config`); bajo `/proc` el
`environ`, `cmdline`, `mem`, `maps`, `fd` y similares de un proceso y todo
`/proc/self` (una raíz `/` entregaría las claves de API de axross), y
`/run/secrets`. `set_permissions` rechaza un fichero con otros hard links.
`--mcp-allow-secret-reads` (solo stdio) desactiva la comprobación; las
herramientas propias del agente la mantienen siempre. El lado de
escritura (§2, los lugares protegidos de `core.protected_places`) es
una lista aparte que este interruptor no cambia. Además de los ficheros de
inicio del home y los ficheros de código de Git (sin distinguir
mayúsculas: `head`, `.GIT`), rechaza a cualquier profundidad los ficheros
de proyecto desde los que otros programas ejecutan código - las carpetas
`.claude`, `.vscode`, `.cursor`, `.idea`, `.zed`, `.devcontainer`,
`.husky` (y `.fleet`, `.gemini`, `.codex`, `.windsurf`, `.roo`, `.kiro`,
`.amazonq`, `.continue`, `.theia`) y `.mcp.json`, `.devcontainer.json`,
`*.code-workspace`, `.pre-commit-config.yaml`, `lefthook.yml`,
`.overcommit.yml` -, la carpeta que nombra `core.hooksPath` de un
repositorio (su configuración, `~/.gitconfig`, `/etc/gitconfig`,
`GIT_CONFIG_*`) y los ficheros que su configuración incluye. También rechaza los ficheros que un servidor MCP activado de los ajustes
del agente ejecuta en esta máquina (su script; junto a un script de Python
cualquier fichero de módulo, que Python importaría primero:
`core.mcp_script_pin`) - y ese servidor no arranca con ficheros que han
cambiado desde que el usuario los confirmó, hasta que el usuario lo diga
(USAGE_es.md, servidores MCP).

Se comprueba cada nombre de una ruta - tal como se escribe, tras cada
symlink del camino y resuelto - en ambos lados: una clave detrás de
`~/.ssh/id_ed25519 -> ~/keys/id_ed25519` se rechaza con cualquiera de los
dos nombres, y `~/dotfiles/kitty/kitty.conf` no se escribe cuando
`~/.config/kitty` apunta ahí (concede el destino para permitirlo). Un hard
link a un fichero secreto no se lee; un fichero con otros hard links no se
escribe (en su sitio cambiarían también los otros nombres - quizá
`~/.bashrc` o un `.git/config`).

**Default-deny al leer.** Además de los secretos, el contenido de una
entrada oculta del home (`~/.config/<app>`, `~/.mozilla`, ...) y de
`~/snap` (también `~/Library`, `%APPDATA%`) no se entrega salvo que el
operador conceda esa carpeta: un `--mcp-root` en ese sitio (para el
agente: su carpeta o una carpeta adicional ahí; basta de solo lectura;
los secretos dentro siguen sin leerse).
Un root de todo el home no levanta nada. Los nombres se siguen listando;
los demás ficheros se leen como antes. `--mcp-allow-secret-reads`
también lo levanta.

---

## 8. Códigos de error

| Código   | Nombre                  | Uso                                                   |
|----------|-------------------------|-------------------------------------------------------|
| -32700   | PARSE                   | Falló el decode del JSON.                             |
| -32600   | INVALID_REQUEST         | Falta el método, el cuerpo no es un objeto.           |
| -32601   | METHOD_NOT_FOUND        | Método / herramienta desconocidos o capability desactivada. |
| -32602   | INVALID_PARAMS          | Fallo de jsonschema, ValueError en el handler, URI inválida. |
| -32603   | INTERNAL                | Un resultado que no se puede enviar (no serializable, por encima del límite de tamaño), o una llamada cancelada por el cliente. |
| **-32001** | **RATE_LIMITED**      | `tools/call` / `axross/tasks/start` limitados, o tope de tareas en ejecución alcanzado. |
| **-32002** | **TIMEOUT**           | La herramienta superó su timeout de tiempo real.      |

Una herramienta que se ejecutó y falló (el handler lanzó algo distinto de
ValueError / TypeError: un OSError, el `PermissionError` de un escape de la
raíz o de un fichero secreto, un perfil rechazado, …) no es un error
JSON-RPC: como pide la especificación MCP, es un **resultado con
`isError: true`** (texto `tool '<name>' failed: …`, redactado como todo
mensaje de error; `_meta.type` nombra la excepción). Los argumentos
incorrectos siguen siendo -32602 y una herramienta desconocida -32601.

---

## 9. Grupos de capacidades (`--mcp-tools`)

Sin `--mcp-tools` el servidor ofrece exactamente las herramientas de
§2. `--mcp-tools GRUPO[,GRUPO...]` (repetible; `AXROSS_MCP_TOOLS` se
une a él) añade grupos; `all` añade todos. Un grupo desconocido detiene
el arranque con código de salida 2 y una línea en stderr con los grupos
válidos. El flag se llama `--mcp-tools` y no `--backend`: "backend" ya
significa un backend de protocolo en axross, y los backends remotos son
uno de los grupos.

### 9.1 Configuraciones habituales

```bash
# Solo lectura: herramientas de ficheros más lectura de metadatos y tipos
axross --mcp-server --mcp-tools metadata,filetype

# Empaquetar y extraer dentro de ~/data (las herramientas que modifican
# necesitan --mcp-write, que necesita --mcp-root)
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools archive

# Construir el índice de búsqueda y encontrar duplicados, solo lectura
axross --mcp-server --mcp-root ~/photos --mcp-tools index,duplicates

# Perfiles guardados como backends adicionales, copiar entre ellos y ~/data
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools remote,transfer

# Comandos en los perfiles abiertos (SSH, Telnet, rsh, ADB, WinRM, Cisco)
axross --mcp-server --mcp-tools remote,exec --mcp-allow-exec

# Todo, por HTTP loopback
axross --mcp-server --mcp-http 127.0.0.1:7331 --mcp-write --mcp-root ~/data --mcp-tools all
# ... o con variables de entorno
AXROSS_MCP=1 AXROSS_MCP_WRITE=1 AXROSS_MCP_TOOLS=all axross --mcp-root ~/data
```

### 9.2 Grupos y herramientas

Desde 0.15.183 los nombres de las herramientas son verbo y recurso (`list_directory`, `get_path_info`, `search_content` …); `tools/call` sigue aceptando los nombres anteriores (list_dir, stat, grep, …), que `tools/list` ya no muestra. Tres herramientas anteriores viven ahora dentro de otra y sus nombres siguen respondiendo: export_metadata_file es `export_metadata` con `out`, exec_backends es `list_backends` con `can_run_commands`, extensions_info es `list_extensions` con `name`. El grupo packer forma parte ahora de `archive`; `--mcp-tools packer` sigue funcionando. Los parámetros renombrados también siguen valiendo: needle y limit de `search_index` (`pattern`, `max_results`), timeout_s de `run_script` (`timeout`), folder de `create_archive` (`path`) y el max_depth contado desde 0 de `scan_file_types` y `copy_path_to_backend` (`subfolder_levels`).

Las herramientas de solo lectura de un grupo solo necesitan
`--mcp-tools <grupo>`; las que modifican ni siquiera se registran sin
`--mcp-write` (y `--mcp-write` se rechaza sin `--mcp-root`). El grupo
`exec` es la excepción: sus herramientas necesitan `--mcp-allow-exec`
en su lugar, y `all` deja fuera el grupo sin ese flag (§9.8).
`export_metadata` solo necesita `--mcp-tools metadata`; su `out` (guardar
la exportación en un fichero) existe con `--mcp-write`.

| Grupo | Herramienta | Tipo | Flags necesarios | Clase de timeout |
|-------|-------------|------|------------------|------------------|
| `metadata` | `read_metadata` | solo lectura | `--mcp-tools metadata` | stream |
| `metadata` | `export_metadata` | modifica | `--mcp-tools metadata` | stream |
| `metadata` | `strip_metadata` | modifica | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | long |
| `duplicates` | `scan_duplicates` | solo lectura | `--mcp-tools duplicates` | long |
| `duplicates` | `list_duplicate_scans` | solo lectura | `--mcp-tools duplicates` | quick |
| `duplicates` | `list_duplicate_groups` | solo lectura | `--mcp-tools duplicates` | quick |
| `duplicates` | `trash_duplicates` | modifica | `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR` | long |
| `archive` | `list_archive_formats` | solo lectura | `--mcp-tools archive` | quick |
| `archive` | `create_archive` | modifica | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `archive` | `list_archive_members` | solo lectura | `--mcp-tools archive` | walk |
| `archive` | `extract_archive` | modifica | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `crypto` | `encrypt_file` | modifica | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `crypto` | `decrypt_file` | modifica | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `index` | `build_index` | solo lectura | `--mcp-tools index` | long |
| `filetype` | `identify_file_type` | solo lectura | `--mcp-tools filetype` | walk |
| `filetype` | `scan_file_types` | solo lectura | `--mcp-tools filetype` | stream |
| `transfer` | `copy_path_to_backend` | modifica | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `transfer` | `move_file_to_backend` | modifica | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `remote` | `list_remote_profiles` | solo lectura | `--mcp-tools remote` | quick |
| `remote` | `open_remote_profile` | solo lectura | `--mcp-tools remote` | walk |
| `remote` | `close_remote_profile` | solo lectura | `--mcp-tools remote` | quick |
| `remote` | `list_backends` | solo lectura | `--mcp-tools remote` | quick |
| `exec` | `run_backend_command` | modifica | `--mcp-tools exec` `--mcp-allow-exec` | long |
| `exec` | `run_backend_script` | modifica | `--mcp-tools exec` `--mcp-allow-exec` | long |
| `agent` | `run_llm_agent` | solo lectura | `--mcp-tools agent` | long |
| `extensions` | `list_extensions` | solo lectura | `--mcp-tools extensions` | quick |

"Solo lectura" significa: ningún fichero del usuario cambia.
`scan_duplicates` e `build_index` sí escriben en los índices propios de
axross (el del Duplicate Finder y el de la búsqueda de metadatos, bajo
`~/.local/share/axross/`), los mismos que usa la GUI; `open_remote_profile`
abre una conexión de red.

Qué hace cada grupo:

* **metadata** — leer los metadatos de imágenes (EXIF/XMP/IPTC; JPEG,
  PNG, WebP, GIF, TIFF), ficheros de Office, PDF y audio/vídeo
  (ffprobe) de un fichero o una carpeta; exportarlos como JSON o CSV,
  como texto o a un fichero nuevo; eliminarlos escribiendo una copia
  limpia junto a cada fichero (`photo.jpg` → `photo.clean.jpg`). La
  eliminación in situ no se ofrece por MCP: guarda el original en la
  papelera de axross del directorio home, fuera de la raíz MCP.
* **duplicates** — el Duplicate Finder: hashear una carpeta en el
  índice de duplicados, listar escaneos y grupos de duplicados (cada
  copia dentro de la carpeta pedida y de la raíz — las filas que la GUI
  indexó en otro sitio nunca aparecen) y dedupe: conservar la copia más
  antigua de cada grupo y mover las demás a `<raíz>/.axross-trash`,
  tras recomprobar cada copia en disco. Es un dry run salvo con
  `dry_run=false`.
* **archive** — crear zip, tar.gz / tar.zst / tar.xz / tar.bz2, 7z (con
  contraseña: AES-256, también la lista de ficheros cifrada) y gz / zst
  / xz / bz2 de un solo fichero. ZIP no tiene opción de contraseña
  (ZipCrypto está roto). Listar entradas sin extraer; extraer en una carpeta
  nueva (`x.zip` → `x`, `x-1`, …) con las protecciones de
  `core.archive` contra zip-slip, enlaces, tamaño (1 GiB), número de
  entradas (10.000) y ratio de compresión (100:1, para entradas de
  64 MiB o más). Solo archivos locales:
  trae primero un archivo remoto con `copy_path_to_backend`.
* **crypto** — el formato `.axenc` de la GUI (AES-256-GCM,
  PBKDF2-SHA256 con 200.000 iteraciones, como máximo 1 GiB por
  fichero).
* **index** — llenar el índice de metadatos offline que lee `search_index`,
  para que `search_index` tenga datos sin la GUI; `prune` elimina filas de
  ficheros que ya no existen.
* **filetype** — identificar ficheros por su contenido (magic bytes, el
  mismo detector que la GUI) y señalar una extensión que miente.
* **transfer** — copiar ficheros o árboles, o mover un fichero, entre
  dos backends cualesquiera (`local` y los perfiles abiertos con
  `open_remote_profile`); `resumable=true` copia en segmentos de 4 MiB con un
  manifiesto bajo `$XDG_STATE_HOME/axross/resume/`, de modo que una
  copia interrumpida sigue donde se quedó al llamarla de nuevo con los
  mismos argumentos.
* **remote** — ver §9.5.
* **exec** — ejecutar comandos y scripts en hosts remotos; ver §9.8.
* **agent** — pasar una tarea al LLM propio del usuario; ver §9.9.
* **extensions** — listar las extensiones instaladas, activadas o no.
  Ninguna puede ejecutarse por MCP: `activate(api)` de una extensión
  recibe la `ExtensionAPI` de Qt y solo puede añadir acciones de menú,
  acciones de contexto y docks — no hay acción headless que llamar, y
  cargarla ejecuta su código con los derechos del usuario.

### 9.3 Modelo de seguridad

Todas las protecciones del servidor base siguen; los grupos añaden
capas:

1. **Opt-in por grupo.** Sin flag, no hay grupo.
2. **`--mcp-write` por herramienta que modifica**, que a su vez exige
   `--mcp-root`. Sin él, las herramientas que modifican no existen.
3. **Confinamiento a la raíz.** Cada ruta local pasa por la
   comprobación de raíz que resuelve symlinks de §7.1; los recorridos
   saltan symlinks y entradas que caen fuera de la raíz.
4. **Nunca se sobrescribe nada.** Archivos comprimidos, carpetas
   extraídas, ficheros cifrados y descifrados, exportaciones de
   metadatos y copias limpias reciben un nombre nuevo (`bundle (2).zip`,
   `x-1`, `a (2).txt`, `photo.clean (1).jpg`); los ficheros que crea el
   propio axross (exportaciones, texto descifrado, ciphertext) tienen
   modo 0600.
5. **Auditoría.** Cada herramienta de grupo que modifica escribe
   `attempt` y luego `ok` o `refused` en `core.mcp_server.audit` —
   rutas, nombres, cuentas y tamaños, nunca contenido de ficheros,
   passphrases ni contraseñas.
6. **Los secretos quedan fuera de las respuestas.** Las passphrases y
   la contraseña de 7z son campos `writeOnly` del schema que no
   aparecen en ningún resultado, error ni línea de auditoría;
   `list_remote_profiles` lista los perfiles mediante una lista blanca de
   campos (sin contraseña, clave, token, SAS ni connection string).
7. **Trabajo acotado.** Cada lista tiene un tope (`max_files`,
   `max_groups`, `max_entries`, …, `truncated=true` al cortar); los
   trabajos largos informan progreso, comprueban la cancelación y
   corren bajo `axross/tasks/start`; los resultados de más de 16 MiB se
   rechazan como en cualquier herramienta.

### 9.4 Security mode `paranoid`

Ningún grupo se rechaza entero. Lo que el modo `paranoid` bloquea en la
GUI y en el scripting sigue bloqueado aquí:

* `open_remote_profile` rechaza los protocolos legacy (`ftp`, `telnet`,
  `cisco-telnet`, `tftp`, `gopher`, `nntp`, `pop3`, `rsh`);
  `list_remote_profiles` los marca como `openable: false`.
* `metadata_*` no ejecutan ffprobe / ffmpeg sobre audio y vídeo (el
  informe da el motivo), igual que la GUI.
* `list_extensions` informa `allowed: false` y cada extensión
  `active: false`.
* Las herramientas de script siguen rechazadas (`--mcp-allow-scripts`
  termina con exit 2).
* El grupo `exec` sigue rechazado (`--mcp-allow-exec` termina con
  exit 2).

### 9.5 Perfiles remotos

* `list_remote_profiles` lista los perfiles guardados (nombre, protocolo,
  host, puerto, usuario, tipo de autenticación, si hay contraseña
  guardada, flag de producción) e indica por perfil si `open_remote_profile` lo
  rechazaría.
* `open_remote_profile(profile)` conecta mediante el connection manager de la
  GUI y registra el backend `profile:<nombre>`; cualquier otra
  herramienta lo alcanza con `backend: "profile:<nombre>"`.
  `close_remote_profile` lo libera.
* **Las credenciales salen del keyring**, y solo si el perfil guarda su
  contraseña ("Store password" en el diálogo de conexión). El servidor
  MCP nunca pregunta: un perfil que necesita una contraseña no
  guardada, una host key SSH que aún no está en `~/.ssh/known_hosts` o
  un inicio de sesión en el navegador (OneDrive, SharePoint, Google
  Drive, Dropbox) se rechaza con un error que lo dice. Conecta ese
  perfil una vez en la GUI.
* **`--mcp-root` no se aplica a rutas remotas**: un perfil alcanza lo
  que su servidor permite a esa cuenta. Un perfil que lleva al sistema
  de ficheros local se rechaza, porque esquivaría la raíz.
* **Los perfiles de producción son de solo lectura por MCP**: la cuenta
  atrás de la GUI antes de una operación destructiva no se puede
  mostrar, así que toda modificación sobre ellos se rechaza.
* Los perfiles abiertos son por sesión en HTTP (un cliente nunca ve los
  de otro), como máximo 8 por sesión; al terminar una sesión HTTP
  (`DELETE` o expulsión por inactividad) se cierran sus conexiones.
* No se ofrece abrir una URL arbitraria: una URL elegida por el LLM
  podría dirigir el servidor a `sftp://localhost` con el agente SSH del
  usuario, o a un fichero local (`sqlite://`, `git+local://`), y rodear
  `--mcp-root`. Un perfil guardado es decisión del propio usuario.
* Qué protocolos puede nombrar un perfil: todos los del diálogo de
  conexión. Los diez backends solo por URL (`exchange`, `git`, `ldap`, `mongodb`, `postgres`, `redis`, `rsh`, `slp`, `sqlite`, `wmi`) no
  tienen diálogo de conexión y por tanto tampoco perfil; por MCP solo
  los alcanzan las herramientas de script (`--mcp-allow-scripts`,
  stdio) con `axross.open_url`. `tests/test_mcp_protocol_matrix.py`
  mantiene esa división contra el registro de backends.

### 9.6 Una llamada JSON-RPC por grupo

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_metadata","arguments":{"path":"/home/me/data/IMG_0001.jpg"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_duplicates","arguments":{"path":"/home/me/data/photos"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_archive","arguments":{"path":"/home/me/data","names":["report","notes.txt"],"archive_name":"bundle","format":"7z","password":"…"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"extract_archive","arguments":{"path":"/home/me/data/bundle.zip"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"encrypt_file","arguments":{"path":"/home/me/data/notes.txt","passphrase":"…"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"build_index","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scan_file_types","arguments":{"path":"/home/me/data/inbox","mismatches_only":true}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"copy_path_to_backend","arguments":{"src":"/home/me/data/report","dst_backend":"profile:nas","dst":"/backup/report","resumable":true}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"open_remote_profile","arguments":{"profile":"nas"}}}
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"list_extensions","arguments":{}}}
```

Un trabajo largo en segundo plano, cancelable en ambos transportes:

```json
{"jsonrpc":"2.0","id":11,"method":"axross/tasks/start","params":{"name":"scan_duplicates","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":12,"method":"axross/tasks/status","params":{"task_id":"<task_id>"}}
{"jsonrpc":"2.0","id":13,"method":"axross/tasks/cancel","params":{"task_id":"<task_id>"}}
```

### 9.7 Manifiesto legible por máquina

`axross --mcp-list-tools` acepta los mismos flags `--mcp-tools`,
`--mcp-write`, `--mcp-allow-scripts` y `--mcp-allow-exec` (y las
variables `AXROSS_MCP_*`)
que el servidor, no arranca nada e imprime JSON: por herramienta
`name`, `group`, `mutating`, `required_flags`, `transports`,
`timeout_class`, `timeout_seconds`, `description` e `input_schema`,
además de la tabla de grupos y las siete clases de timeout (`quick`,
`walk`, `write`, `preview`, `stream`, `long`, `script`; estructura como
en el ejemplo de [MCP.md §9.7](MCP.md)).

Cada schema indica tipos, campos obligatorios, enums, valores por
defecto y límites, y las herramientas de grupo rechazan argumentos
desconocidos (`additionalProperties: false`).
[`mcp-tools.json`](mcp-tools.json) es el manifiesto para
`--mcp-tools all --mcp-write --mcp-allow-scripts --mcp-allow-exec`;
`tests/test_mcp_manifest.py` falla en cuanto deja de coincidir con el
código. [LLM_GUIDE.md](LLM_GUIDE.md) es la guía breve para clientes LLM
(en inglés); su catálogo de herramientas se genera desde este
manifiesto.

### 9.8 Comandos en hosts remotos (`exec`)

`--mcp-tools exec --mcp-allow-exec` añade dos herramientas y un campo:

* `list_backends` da a cada backend `commands` y, con
  `can_run_commands=true`, lista solo los que pueden ejecutar comandos;
  `commands` es `posix-shell` (SSH, SCP, Telnet,
  rsh, ADB), `powershell` (WinRM) o `ios-show` (Cisco Telnet). Abre
  antes un perfil guardado con `open_remote_profile` (grupo `remote`).
* `run_backend_command(backend, command, stdin?, env?, timeout?, max_output?)`
  ejecuta un comando y devuelve `{returncode, stdout, stderr,
  truncated_stdout, truncated_stderr}`. Un estado de salida distinto
  de 0 es un resultado, no un error. Telnet y ADB no tienen un canal de
  errores propio: su stderr llega dentro de `stdout`.
* `run_backend_script(backend, script, interpreter?, args?, env?, …)` envía
  el script por stdin a `sh -s --`, `bash -s --`, `python3 -` o
  `perl -` (por defecto `sh`), con los `args` entrecomillados detrás.
  Un host WinRM ejecuta el script como PowerShell
  (`interpreter: "powershell"`, sin `args`); un dispositivo Cisco no
  ejecuta scripts.

Límites y protecciones:

* **Opt-in propio.** `--mcp-allow-exec` existe solo como flag (sin
  variable `AXROSS_MCP_*`), `--mcp-tools all` sin él no registra
  ninguna de las dos herramientas, y `--mcp-write` no las habilita. El
  security mode `paranoid` rechaza el flag (exit 2).
* **Solo remoto.** Un backend sin shell remota — el sistema de ficheros
  local, S3, WebDAV, … — se rechaza con "has no remote shell". Un
  comando va solo a la shell del host al que está conectado un
  backend, nunca a un proceso local del servidor (eso lo hacen las
  herramientas de script, solo por stdio); por eso `exec` se ofrece
  también por HTTP.
* **Los perfiles de producción no ejecutan nada** (§9.5).
* **Cisco: solo comandos `show`.** Todo lo demás (`configure`,
  `reload`, `write memory`, una segunda línea) se rechaza antes de
  enviarse, igual que los modificadores de salida que escriben en flash
  (`| redirect`, `| tee`, `| append`, `>`); `| include`, `| exclude`,
  `| begin`, `| section` y `| count` siguen permitidos.
* **stdin** llega al comando por un fichero temporal en Telnet y ADB
  (eliminado después) y directamente en SSH, SCP y rsh; WinRM y Cisco
  lo rechazan.
* Los nombres de **env** deben cumplir `[A-Za-z_][A-Za-z0-9_]*`; los
  valores se entrecomillan para la shell remota (`export K='v'; ` o
  `$env:K = 'v'; `).
* **Acotado.** `timeout` 1–3600 s (por defecto 60), `max_output` hasta
  16 MiB de stdout (por defecto 1 MiB), stderr como máximo 1 MiB; los
  flags `truncated_*` indican cuándo se cortó la salida.
* **Auditoría sin contenido.** Cada llamada registra `attempt` y `ok` o
  `refused` con el backend, su clase, la longitud y los primeros 16
  dígitos hexadecimales del SHA-256 del comando, la longitud de stdin y
  el estado de salida — nunca el comando, su stdin ni su salida, que a
  menudo llevan contraseñas.

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_remote_profile","arguments":{"profile":"web01"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_backend_command","arguments":{"backend":"profile:web01","command":"df -h /","timeout":30}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_backend_script","arguments":{"backend":"profile:web01","interpreter":"python3","script":"import sys; print(sys.argv[1:])","args":["a b","c"]}}}
```

### 9.9 Pasar una tarea al LLM local (`agent`)

`--mcp-tools agent` añade `run_llm_agent(task, profile?, groups?, max_steps?)`:
el cliente - otro LLM - pasa una tarea al modelo propio del usuario, el
perfil LLM activo de la GUI de axross (LM Studio, Ollama, vLLM,
llama.cpp; cualquier servidor compatible con OpenAI) o el indicado.
Ese modelo trabaja con las herramientas de ficheros de solo lectura de
axross dentro de la raíz MCP, más las herramientas de solo lectura de
los grupos indicados en `groups`, y la llamada devuelve
`{answer, stopped, calls, profile, model}`. `remote` y `extensions`
van más allá de la raíz (conexiones guardadas con sus credenciales, el
código de las extensiones): `groups` solo puede nombrarlos si el propio
servidor se arrancó con ellos en `--mcp-tools`.

* **No cambia nada.** El agente interno no recibe ninguna herramienta
  de escritura, exec, script ni agent: en un servidor sin interfaz
  nadie podría confirmar un cambio. Los cambios con un modelo local
  pasan por el dock Agent de la GUI, que pregunta antes de cada uno.
* **El contenido se queda donde apunta el perfil.** Un perfil cuyo
  servidor no está en esta máquina ni en su red (o se alcanza a través
  de un proxy) necesita el consentimiento dado en la GUI; sin él la
  llamada se rechaza antes de enviar nada.
* **Acotado.** `max_steps` (1–30, por defecto 10) peticiones al modelo;
  los resultados de las herramientas se recortan para el modelo; la
  llamada corre en la clase de timeout `long`; `axross/tasks/cancel` la
  detiene tras la petición al modelo en curso.
* La API key sale del keyring y no aparece en ningún resultado ni línea
  de log.
