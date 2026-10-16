# Servidor MCP — guía detallada

Axross puede ejecutarse como servidor [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) para que un cliente LLM (Claude Desktop, Cline, un agente
propio) pueda trabajar sobre un árbol de directorios local mediante
una superficie JSON-RPC de herramientas. El servidor de la CLI
(`axross --mcp-server`, stdio o HTTP) sirve el sistema de ficheros
local (`LocalFS`), confinado a la raíz MCP. Los **grupos de
capacidades** opcionales (`--mcp-tools`, §9) añaden metadatos, el
Duplicate Finder, el packer, archivos comprimidos, cifrado, el índice
de búsqueda, la detección de tipo de fichero, transferencias entre
backends, perfiles de conexión guardados como backends adicionales y
la lista de extensiones. Un manifiesto legible por máquina de todas las
herramientas lo da `axross --mcp-list-tools` o
[`mcp-tools.json`](mcp-tools.json) (§9.7).

El servidor habla la versión de protocolo MCP **2024-11-05**.

Idiomas: [English](MCP.md) · [Deutsch](MCP_de.md) · **Español**

---

## 1. Transportes

### 1.1 Stdio

```bash
# Solo lectura; LocalFS, raíz MCP por defecto $HOME (cámbiala con --mcp-root):
axross --mcp-server

# Variante con variable de entorno (mismo comportamiento):
AXROSS_MCP=1 axross

# Las nueve herramientas de escritura (write_file, mkdir, remove,
# rename, copy, bulk_copy, symlink, hardlink, chmod). Path-traversal
# limitado a la raíz elegida. AXROSS_MCP_WRITE=1 es el equivalente
# por variable de entorno:
axross --mcp-server --mcp-write --mcp-root ~/data

# Herramientas de script (script_list/api_schema/read/write/delete/run) — solo stdio:
axross --mcp-server --mcp-allow-scripts

# Grupos de capacidades (§9); AXROSS_MCP_TOOLS=metadata,packer es el
# equivalente por variable de entorno, 'all' activa todos los grupos:
axross --mcp-server --mcp-tools metadata,filetype
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools all

# Imprimir el manifiesto de herramientas (JSON) para unos flags, sin arrancar nada:
axross --mcp-list-tools --mcp-tools all --mcp-write
```

`--mcp-write` sin `--mcp-root` se rechaza (exit 2): la raíz por
defecto es tu directorio home, demasiado amplio para ser escribible.
Un grupo desconocido en `--mcp-tools` se rechaza (exit 2) con una
línea en stderr que enumera los grupos válidos.

`--mcp-allow-scripts` se rechaza (exit 2) en el security mode
`paranoid`, y también junto con `--mcp-http` (exit 2): no se ofrece
ejecución de scripts sobre un transporte de red. Lo que pueden
alcanzar las herramientas de script está en §2.

Las peticiones llegan por stdin (JSON delimitado por líneas), las
respuestas salen por stdout. Los logs solo por stderr. Cuando se
activa el modo MCP, PyQt no se importa — el servidor corre
limpiamente en máquinas sin pantalla.

### 1.2 HTTP (+ mTLS opcional)

```bash
# HTTP loopback (sin TLS fuera de loopback se rechaza):
axross --mcp-server --mcp-http 127.0.0.1:7331

# mTLS — los tres ficheros son obligatorios:
axross --mcp-server --mcp-http 0.0.0.0:7331 \
    --mcp-cert server.pem --mcp-key server.key --mcp-ca trusted-ca.pem
```

Endpoints:

| Método + ruta                        | Propósito                                                      |
|--------------------------------------|----------------------------------------------------------------|
| `POST /messages`                     | Enviar una petición JSON-RPC, recibir una respuesta.            |
| `GET /messages` (SSE)                | Abrir un flujo de eventos para notificaciones de la sesión.     |
| `DELETE /messages`                   | Terminar la sesión explícitamente.                              |
| `GET /health`                        | Sin autenticación; devuelve `{server, version}`.                |

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
demás (metadatos, duplicados, packer, archivos comprimidos, cifrado,
construcción del índice, tipos de fichero, transferencias, perfiles
remotos, extensiones) es un grupo de capacidades, ver §9.

### Herramientas de solo lectura (siempre disponibles)

| Nombre                | Descripción                                                         |
|-----------------------|---------------------------------------------------------------------|
| `list_dir(path)`      | Entradas del directorio.                                            |
| `stat(path)`          | Nombre, tipo, tamaño, mtime.                                        |
| `read_file(path, max_bytes=)` | Contenido en base64; tope de 4 MiB por defecto.             |
| `checksum(path, algorithm=)`  | `sha256` (por defecto), `sha1`, `md5` o `sha512`. Usa el hash nativo del backend solo si es del algoritmo pedido; si no, hace streaming por hashlib (emite progreso). |
| `search(needle, ext, min_size, max_size)` | Índice de metadatos offline, acotado al backend activo y a la raíz MCP. |
| `walk(path, max_depth, max_entries)`      | Listado recursivo acotado; emite `notifications/progress`. |
| `recursive_checksum(path, algorithm, max_files, max_depth, max_file_bytes)` | Hashea cada fichero bajo una ruta (por defecto salta ficheros de más de 1 GiB); un frame de progreso por fichero hasheado. |
| `grep(pattern, path, max_depth, max_matches)` | Regex sobre contenido. Salta ficheros >4 MiB, tope 500 coincidencias; emite progreso. |
| `list_versions(path)` | Metadatos por versión donde el backend lo soporte.                 |
| `open_version_read(path, version_id, max_bytes=)` | Contenido base64 de una versión concreta.      |
| `preview(path, edge=256)` | Miniatura de imagen — devuelta como MCP **image content** con mimeType correcto. |

### Herramientas de escritura (solo con `--mcp-write`)

| Nombre                            | Descripción                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content_b64)`   | Subida en base64.                                                          |
| `mkdir(path)`                     | Crear directorio.                                                          |
| `remove(path, recursive=False)`   | Borrar.                                                                    |
| `rename(src, dst)`                | Renombrar / mover.                                                         |
| `copy(src, dst)`                  | Copia server-side donde exista; fallback por streaming.                    |
| `bulk_copy(src, dst, max_files, max_depth, max_file_bytes, overwrite)` | Copia de árbol (por defecto salta ficheros de más de 10 GiB); un frame de progreso por fichero copiado. |
| `symlink(target, link_path)`      | `link_path` debe estar bajo la raíz; `target` **no** se comprueba contra la raíz a propósito (puede quedar colgando o apuntar fuera — las herramientas posteriores resuelven los enlaces con `_enforce_root` antes de seguirlos). No se comprueba ningún flag de capability; un backend sin symlinks hace fallar la llamada. |
| `hardlink(target, link_path)`     | Ambos extremos deben estar bajo la raíz. No se comprueba ningún flag de capability; un backend sin hardlinks hace fallar la llamada. |
| `chmod(path, mode)`               | Bits de modo POSIX. Acepta entero o string octal.                          |

Cada herramienta de escritura resuelve sus rutas primero mediante
`_enforce_root` — un payload como `/etc/passwd` se rechaza antes
de cualquier IO (la única excepción es el `target` de `symlink`,
ver arriba). Cada llamada emite entradas de auditoría en el logger
`core.mcp_server.audit`, con herramienta, resultado, ruta y tamaño
— nunca los bytes del payload.

### Herramientas de script (solo con `--mcp-allow-scripts`, solo stdio)

| Nombre                        | Descripción                                                       |
|-------------------------------|-------------------------------------------------------------------|
| `script_list()`               | Nombres de los scripts guardados en `~/.config/axross/scripts/`.  |
| `script_api_schema()`         | La API `axross.*` como JSON (igual que `axross.api_schema()`): por función firma, parámetros con tipos, tipo de retorno, resumen, `mutates`, `prompts`; las clases públicas; los métodos de toda sesión de backend. Solo lectura. |
| `script_read(name)`           | Código fuente de un script guardado.                              |
| `script_write(name, source)`  | Guarda `<name>.py` (modo 0600); sobrescribe.                      |
| `script_delete(name)`         | Borra un script guardado; idempotente.                            |
| `script_run(name, args?, timeout_s?)` | Ejecuta un script guardado en un proceso Python propio con `axross.*` disponible; `args` pasan a ser `sys.argv[1:]`. Devuelve una respuesta estructurada (abajo). |

`script_run` en detalle — en qué puede confiar un cliente:

* **Un proceso hijo, nunca el servidor.** stdin está vacío: `input()`
  recibe `EOFError` y nunca puede leer el stream JSON-RPC. El hijo
  corre en un grupo de procesos propio; al terminar la ejecución
  terminan todos los procesos que arrancó (uno que llama a `setsid` se
  escapa).
* **Wall clock.** `timeout_s` (por defecto 60, como máximo 600) detiene
  la ejecución: SIGTERM al grupo, SIGKILL 3 s después. `tasks/start` +
  `tasks/cancel` ejecutan y detienen un script en segundo plano.
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
  `AXROSS_TARPIT_DISABLE=1`. `script_api_schema` marca cada función que
  puede necesitar a un humano (`prompts`) o cambiar estado (`mutates`).
* **Argumentos.** `args`: como máximo 64 strings de como máximo 4096
  caracteres, sin NUL; un `args` o `timeout_s` incorrecto se rechaza
  antes de ejecutar nada (`-32602`).

**Nota de seguridad:** las herramientas de script **no** están
confinadas a la raíz MCP en absoluto. Los nombres se limitan a
`[A-Za-z0-9_-]+` dentro del directorio de scripts, pero `script_run`
ejecuta Python arbitrario con los permisos del usuario del servidor:
puede leer y escribir todo lo que ese usuario pueda, abrir conexiones
de red y usar cualquier backend de `axross.*`. Trata
`--mcp-allow-scripts` como entregarle una shell al cliente. Se rechaza
en el security mode `paranoid` y con `--mcp-http`. `script_write`,
`script_delete` y `script_run` dejan líneas attempt / ok / refused en
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
| `tasks/start`   | **Extensión de Axross, no forma parte de MCP.** Lanza una herramienta en segundo plano; devuelve `task_id`. Mismo chequeo de schema, mismo rate limit y mismo timeout por herramienta que `tools/call`; como máximo 8 tareas en ejecución por scope (`MAX_RUNNING_TASKS_PER_SCOPE`). |
| `tasks/status`  | Estado, último progreso y, al terminar, resultado o error.              |
| `tasks/cancel`  | Cancela una tarea en ejecución.                                         |
| `tasks/list`    | Resumen breve de las tareas del scope.                                  |

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
`walk` (entradas visitadas), `grep` (ficheros escaneados), `checksum`
(bytes hasheados, solo en el fallback por streaming),
`recursive_checksum` (ficheros hasheados) y `bulk_copy` (ficheros
copiados), además de las herramientas largas de los grupos de §9
(`metadata_read` / `metadata_export` sobre carpetas, `metadata_remove`,
`file_type_scan`, `duplicates_scan`, `duplicates_dedupe`,
`index_build`, `pack`, `archive_extract`, `transfer_copy`). Dentro de una tarea de `tasks/start` las mismas
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
que deba poder cancelarse en stdio va por `tasks/start` +
`tasks/cancel`, que funciona en ambos transportes. En HTTP cada
petición corre en su propio thread, así que `notifications/cancelled`
sí alcanza una llamada en curso.

### 3.3 Timeouts

Toda herramienta tiene un límite de tiempo real:

| Clase (`timeout_class`) | Timeout | Herramientas                                                              |
|------------|---------|---------------------------------------------------------------------------|
| `quick`    | 15 s    | `stat`, `read_file`, `list_dir`, `search`, `list_versions`, `open_version_read` y toda herramienta sin entrada propia — incluidas las de script salvo `script_run` |
| `walk`     | 60 s    | `walk`, `grep`                                                            |
| `preview`  | 30 s    | `preview`                                                                 |
| `write`    | 30 s    | `write_file`, `mkdir`, `remove`, `rename`, `copy`, `symlink`, `hardlink`, `chmod` |
| `stream`   | 300 s   | `checksum`, `recursive_checksum`, `bulk_copy`                             |
| `long`     | 1800 s  | trabajos sobre árboles enteros de los grupos (§9): `duplicates_scan`, `duplicates_dedupe`, `index_build`, `pack`, `archive_extract`, `transfer_copy`, `transfer_move`, `metadata_remove` |
| `script`   | 610 s   | `script_run`. Detiene a su hijo ya en su propio `timeout_s` (por defecto 60 s, como máximo 600 s); la clase suma el grace del kill y el drenaje de la salida, así que el deadline solo respalda |

La clase de cada herramienta de grupo está en el manifiesto (§9.7).
Una tarea de `tasks/start` recibe el mismo timeout que su herramienta.

Dos mecanismos paralelos respaldan el plazo:

1. Un `threading.Timer` activa el cancel event del handler al
   expirar el plazo. Los handlers que consultan
   `ctx.check_cancel()` (`walk`, `grep`) salen limpiamente en el
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
el remoto. Un `remove` con timeout puede aún borrar la ruta. El
cliente ve una respuesta de timeout; el operador debería asumir
estado desconocido de la operación y o bien verificar o volver a
emitir con una idempotency-key adecuada. No podemos interrumpir
IO bloqueante arbitrario de forma segura; quien diga lo contrario
miente o corre bajo fork().

---

## 4. Rate limiting

Activado por defecto: burst de 30 tokens, refill de 1 token/seg
(60 llamadas por minuto en régimen estable). `tools/call` y
`tasks/start` consumen del mismo bucket (uno por servidor en stdio,
uno por sesión en HTTP); `tools/list`, `initialize`, `ping`,
`resources/*`, `tasks/status|cancel|list` y `logging/setLevel` siguen
libres.

Rechazo: -32001 con `data.type = "RateLimitError"`. Un `tasks/start`
por encima del tope de tareas en ejecución también es -32001, con
`data.type = "TaskLimitError"`.

Ajustable mediante `ServerConfig.rate_burst` /
`rate_refill_per_sec`; desactivable con
`rate_limit_enabled = False`.

---

## 5. Multi-backend

Desde la CLI, el grupo `remote` (§9.5) es el camino a más backends:
`remote_open` convierte un perfil de conexión guardado en el backend
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
   como `transfer_copy`, ni las que no tocan ninguno). Sin él →
   default; con ID → routing. IDs desconocidos caen en -32602.
 - Los backends de un registro estático de librería quedan confinados
   a la raíz MCP como el de por defecto; los perfiles abiertos con
   `remote_open`, no (§9.5).

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

 - Las sesiones ociosas se expulsan tras 30 minutos (ajustable).
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
| `tests/test_mcp_error_redaction.py` | Los secretos en textos de error del backend se redactan (tools/call, tareas, recursive_checksum). |
| `tests/test_mcp_http_hardening.py` | DNS rebinding (Host/Origin), tope de sesiones y expulsión por inactividad, params/ids malformados, flags TLS incompletos, cliente TCP inactivo vs. accept. |
| `tests/test_mcp_http_sse_lifecycle.py` | Un flujo SSE por sesión, DELETE/expulsión lo terminan, replay al reconectar. |
| `tests/test_mcp_search_root.py` | `search` nunca devuelve rutas indexadas fuera de la raíz. |
| `tests/test_mcp_tasks_limits.py` | Rate limit de `tasks/start`, tope de tareas en ejecución, timeout de la herramienta. |
| `tests/test_mcp_write_root.py` | `--mcp-write` exige `--mcp-root`; `--mcp-allow-scripts` rechazado con `--mcp-http`. |
| `tests/test_mcp_script_audit.py` | Las herramientas de script escriben la auditoría, sin código fuente ni salida. |
| `tests/test_mcp_script_run_child.py` | `script_run` en un proceso hijo: timeout y kill del grupo, no queda ningún nieto, `input()` nunca lee el stream stdio, cancelación, tope de salida, validación de argumentos, respuesta estructurada. |
| `tests/test_mcp_stdio_write_lock.py` | Escritores concurrentes en stdio nunca se entremezclan dentro de una línea. |
| `tests/test_mcp_tools_flag.py` | Parseo de `--mcp-tools` / `AXROSS_MCP_TOOLS`, exit 2 con grupo desconocido, superficie por defecto sin cambios, `all` de solo lectura sin herramientas que modifican. |
| `tests/test_mcp_group_metadata_filetype.py` | Grupos `metadata` y `filetype`: escapes de la raíz, symlinks, nunca sobrescribir, auditoría. |
| `tests/test_mcp_group_duplicates_index.py` | Grupos `duplicates` e `index`: filas del índice fuera de la raíz nunca aparecen, recomprobación antes del dedupe, papelera bajo la raíz. |
| `tests/test_mcp_group_packer_archive.py` | Grupos `packer` y `archive`: zip-slip, la contraseña nunca en el log, cancelar no deja nada. |
| `tests/test_mcp_group_crypto.py` | Grupo `crypto`: la passphrase nunca en respuestas, errores ni auditoría; nunca sobrescribir. |
| `tests/test_mcp_group_remote_transfer.py` | Grupos `remote` y `transfer`: sin secretos en la lista, sin prompts, host keys, perfiles de producción, alcance por sesión, copia reanudable. |
| `tests/test_mcp_group_extensions.py` | Grupo `extensions`: listar nunca importa una extensión. |
| `tests/test_mcp_manifest.py` | `--mcp-list-tools` y el `docs/mcp-tools.json` del repositorio siguen sincronizados con el código. |
| `tests/test_mcp_groups_e2e.py` | El servidor real por stdio y HTTP con `--mcp-tools all`: una llamada por grupo, `tasks/start` + `tasks/cancel`. |
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
propio LLM usando la herramienta de escritura `symlink`) apunta
a `/` y dejaría pasar
`write_file("/root/escape/etc/cron.d/evil")`. Ahora
`PermissionError`, respondido como -32603 con
`data.type = "PermissionError"` y un mensaje que nombra la raíz. Los
grupos de capacidades (§9) pasan cada ruta local por la misma
comprobación.

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

### 7.5 Preflight contra ReDoS en grep

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
fingerprint y no tienen binding — trade-off explícito por
ergonomía de desarrollo local.

### 7.9 Audit "attempt" antes de la llamada al backend

Cada herramienta de escritura — y `script_write`, `script_delete`,
`script_run` — emite `outcome=attempt` ANTES de invocar al backend
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

---

## 8. Códigos de error

| Código   | Nombre                  | Uso                                                   |
|----------|-------------------------|-------------------------------------------------------|
| -32700   | PARSE                   | Falló el decode del JSON.                             |
| -32600   | INVALID_REQUEST         | Falta el método, el cuerpo no es un objeto.           |
| -32601   | METHOD_NOT_FOUND        | Método / herramienta desconocidos o capability desactivada. |
| -32602   | INVALID_PARAMS          | Fallo de jsonschema, ValueError en el handler, URI inválida. |
| -32603   | INTERNAL                | Una excepción distinta de ValueError/TypeError en el handler (OSError, el `PermissionError` de un escape de la raíz, un perfil rechazado, …; `data.type` la nombra), o cancelación. |
| **-32001** | **RATE_LIMITED**      | `tools/call` / `tasks/start` limitados, o tope de tareas en ejecución alcanzado. |
| **-32002** | **TIMEOUT**           | La herramienta superó su timeout de tiempo real.      |

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
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools packer,archive

# Construir el índice de búsqueda y encontrar duplicados, solo lectura
axross --mcp-server --mcp-root ~/photos --mcp-tools index,duplicates

# Perfiles guardados como backends adicionales, copiar entre ellos y ~/data
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools remote,transfer

# Todo, por HTTP loopback
axross --mcp-server --mcp-http 127.0.0.1:7331 --mcp-write --mcp-root ~/data --mcp-tools all
# ... o con variables de entorno
AXROSS_MCP=1 AXROSS_MCP_WRITE=1 AXROSS_MCP_TOOLS=all axross --mcp-root ~/data
```

### 9.2 Grupos y herramientas

Las herramientas de solo lectura de un grupo solo necesitan
`--mcp-tools <grupo>`; las que modifican ni siquiera se registran sin
`--mcp-write` (y `--mcp-write` se rechaza sin `--mcp-root`).

| Grupo | Herramienta | Tipo | Flags necesarios | Clase de timeout |
|-------|-------------|------|------------------|------------------|
| `metadata` | `metadata_read` | solo lectura | `--mcp-tools metadata` | stream |
| `metadata` | `metadata_export` | solo lectura | `--mcp-tools metadata` | stream |
| `metadata` | `metadata_export_file` | modifica | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | stream |
| `metadata` | `metadata_remove` | modifica | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | long |
| `duplicates` | `duplicates_scan` | solo lectura | `--mcp-tools duplicates` | long |
| `duplicates` | `duplicates_scans` | solo lectura | `--mcp-tools duplicates` | quick |
| `duplicates` | `duplicates_groups` | solo lectura | `--mcp-tools duplicates` | quick |
| `duplicates` | `duplicates_dedupe` | modifica | `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR` | long |
| `packer` | `pack_formats` | solo lectura | `--mcp-tools packer` | quick |
| `packer` | `pack` | modifica | `--mcp-tools packer` `--mcp-write` `--mcp-root DIR` | long |
| `archive` | `archive_list` | solo lectura | `--mcp-tools archive` | walk |
| `archive` | `archive_extract` | modifica | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `crypto` | `encrypt` | modifica | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `crypto` | `decrypt` | modifica | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `index` | `index_build` | solo lectura | `--mcp-tools index` | long |
| `filetype` | `file_type` | solo lectura | `--mcp-tools filetype` | quick |
| `filetype` | `file_type_scan` | solo lectura | `--mcp-tools filetype` | stream |
| `transfer` | `transfer_copy` | modifica | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `transfer` | `transfer_move` | modifica | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `remote` | `remote_profiles` | solo lectura | `--mcp-tools remote` | quick |
| `remote` | `remote_open` | solo lectura | `--mcp-tools remote` | walk |
| `remote` | `remote_close` | solo lectura | `--mcp-tools remote` | quick |
| `remote` | `list_backends` | solo lectura | `--mcp-tools remote` | quick |
| `extensions` | `extensions_list` | solo lectura | `--mcp-tools extensions` | quick |
| `extensions` | `extensions_info` | solo lectura | `--mcp-tools extensions` | quick |

"Solo lectura" significa: ningún fichero del usuario cambia.
`duplicates_scan` e `index_build` sí escriben en los índices propios de
axross (el del Duplicate Finder y el de la búsqueda de metadatos, bajo
`~/.local/share/axross/`), los mismos que usa la GUI; `remote_open`
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
* **packer** — zip, tar.gz / tar.zst / tar.xz / tar.bz2, 7z (con
  contraseña: AES-256, también la lista de ficheros cifrada) y gz / zst
  / xz / bz2 de un solo fichero. ZIP no tiene opción de contraseña
  (ZipCrypto está roto).
* **archive** — listar entradas sin extraer; extraer en una carpeta
  nueva (`x.zip` → `x`, `x-1`, …) con las protecciones de
  `core.archive` contra zip-slip, enlaces, tamaño (1 GiB), número de
  entradas (10.000) y ratio de compresión (100). Solo archivos locales:
  trae primero un archivo remoto con `transfer_copy`.
* **crypto** — el formato `.axenc` de la GUI (AES-256-GCM,
  PBKDF2-SHA256 con 200.000 iteraciones, como máximo 1 GiB por
  fichero).
* **index** — llenar el índice de metadatos offline que lee `search`,
  para que `search` tenga datos sin la GUI; `prune` elimina filas de
  ficheros que ya no existen.
* **filetype** — identificar ficheros por su contenido (magic bytes, el
  mismo detector que la GUI) y señalar una extensión que miente.
* **transfer** — copiar ficheros o árboles, o mover un fichero, entre
  dos backends cualesquiera (`local` y los perfiles abiertos con
  `remote_open`); `resumable=true` copia en segmentos de 4 MiB con un
  manifiesto bajo `$XDG_STATE_HOME/axross/resume/`, de modo que una
  copia interrumpida sigue donde se quedó al llamarla de nuevo con los
  mismos argumentos.
* **remote** — ver §9.5.
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
   `remote_profiles` lista los perfiles mediante una lista blanca de
   campos (sin contraseña, clave, token, SAS ni connection string).
7. **Trabajo acotado.** Cada lista tiene un tope (`max_files`,
   `max_groups`, `max_entries`, …, `truncated=true` al cortar); los
   trabajos largos informan progreso, comprueban la cancelación y
   corren bajo `tasks/start`; los resultados de más de 16 MiB se
   rechazan como en cualquier herramienta.

### 9.4 Security mode `paranoid`

Ningún grupo se rechaza entero. Lo que el modo `paranoid` bloquea en la
GUI y en el scripting sigue bloqueado aquí:

* `remote_open` rechaza los protocolos legacy (`ftp`, `telnet`,
  `cisco-telnet`, `tftp`, `gopher`, `nntp`, `pop3`, `rsh`);
  `remote_profiles` los marca como `openable: false`.
* `metadata_*` no ejecutan ffprobe / ffmpeg sobre audio y vídeo (el
  informe da el motivo), igual que la GUI.
* `extensions_list` informa `allowed: false` y cada extensión
  `active: false`.
* Las herramientas de script siguen rechazadas (`--mcp-allow-scripts`
  termina con exit 2).

### 9.5 Perfiles remotos

* `remote_profiles` lista los perfiles guardados (nombre, protocolo,
  host, puerto, usuario, tipo de autenticación, si hay contraseña
  guardada, flag de producción) e indica por perfil si `remote_open` lo
  rechazaría.
* `remote_open(profile)` conecta mediante el connection manager de la
  GUI y registra el backend `profile:<nombre>`; cualquier otra
  herramienta lo alcanza con `backend: "profile:<nombre>"`.
  `remote_close` lo libera.
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

### 9.6 Una llamada JSON-RPC por grupo

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"metadata_read","arguments":{"path":"/home/me/data/IMG_0001.jpg"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"duplicates_scan","arguments":{"path":"/home/me/data/photos"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pack","arguments":{"folder":"/home/me/data","names":["report","notes.txt"],"archive_name":"bundle","format":"7z","password":"…"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"archive_extract","arguments":{"path":"/home/me/data/bundle.zip"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"encrypt","arguments":{"path":"/home/me/data/notes.txt","passphrase":"…"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"index_build","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"file_type_scan","arguments":{"path":"/home/me/data/inbox","mismatches_only":true}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"transfer_copy","arguments":{"src":"/home/me/data/report","dst_backend":"profile:nas","dst":"/backup/report","resumable":true}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"remote_open","arguments":{"profile":"nas"}}}
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"extensions_list","arguments":{}}}
```

Un trabajo largo en segundo plano, cancelable en ambos transportes:

```json
{"jsonrpc":"2.0","id":11,"method":"tasks/start","params":{"name":"duplicates_scan","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":12,"method":"tasks/status","params":{"task_id":"<task_id>"}}
{"jsonrpc":"2.0","id":13,"method":"tasks/cancel","params":{"task_id":"<task_id>"}}
```

### 9.7 Manifiesto legible por máquina

`axross --mcp-list-tools` acepta los mismos flags `--mcp-tools`,
`--mcp-write` y `--mcp-allow-scripts` (y las variables `AXROSS_MCP_*`)
que el servidor, no arranca nada e imprime JSON: por herramienta
`name`, `group`, `mutating`, `required_flags`, `transports`,
`timeout_class`, `timeout_seconds`, `description` e `input_schema`,
además de la tabla de grupos y las clases de timeout (estructura como
en el ejemplo de [MCP.md §9.7](MCP.md)).

Cada schema indica tipos, campos obligatorios, enums, valores por
defecto y límites, y las herramientas de grupo rechazan argumentos
desconocidos (`additionalProperties: false`).
[`mcp-tools.json`](mcp-tools.json) es el manifiesto para
`--mcp-tools all --mcp-write --mcp-allow-scripts`;
`tests/test_mcp_manifest.py` falla en cuanto deja de coincidir con el
código.
