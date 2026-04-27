# Servidor MCP — guía detallada

Axross puede ejecutarse como servidor [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) para que un cliente LLM (Claude Desktop, Cline, un agente
propio) pueda manejar cualquier backend configurado mediante una
superficie JSON-RPC de herramientas.

El servidor habla la versión de protocolo MCP **2024-11-05**.

Idiomas: [English](MCP.md) · [Deutsch](MCP_de.md) · **Español**

---

## 1. Transportes

### 1.1 Stdio

```bash
# Solo lectura; backend por defecto: LocalFS con raíz en $HOME.
axross --mcp-server

# Variante con variable de entorno (mismo comportamiento):
AXROSS_MCP=1 axross

# Herramientas de escritura (write_file, mkdir, remove, rename,
# copy, symlink, hardlink, chmod). Path-traversal limitado a la
# raíz elegida:
axross --mcp-server --mcp-write --mcp-root /home/yo/data
```

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

---

## 2. Superficie de herramientas

### Herramientas de solo lectura (siempre disponibles)

| Nombre                | Descripción                                                         |
|-----------------------|---------------------------------------------------------------------|
| `list_dir(path)`      | Entradas del directorio.                                            |
| `stat(path)`          | Nombre, tipo, tamaño, mtime.                                        |
| `read_file(path, max_bytes=)` | Contenido en base64; tope de 4 MiB por defecto.             |
| `checksum(path, algorithm=)`  | Huella nativa cuando existe (S3 ETag, sha256, md5).         |
| `search(needle, ext, min_size, max_size)` | Índice de metadatos offline, acotado al backend activo. |
| `walk(path, max_depth, max_entries)`      | Listado recursivo acotado; emite `notifications/progress`. |
| `grep(pattern, path, max_depth, max_matches)` | Regex sobre contenido. Salta ficheros >4 MiB, tope 500 coincidencias. |
| `list_versions(path)` | Metadatos por versión donde el backend lo soporte.                 |
| `open_version_read(path, version_id)` | Contenido base64 de una versión concreta.                  |
| `preview(path, edge=256)` | Miniatura de imagen — devuelta como MCP **image content** con mimeType correcto. |

### Herramientas de escritura (solo con `--mcp-write`)

| Nombre                            | Descripción                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content_b64)`   | Subida en base64.                                                          |
| `mkdir(path)`                     | Crear directorio.                                                          |
| `remove(path, recursive=False)`   | Borrar.                                                                    |
| `rename(src, dst)`                | Renombrar / mover.                                                         |
| `copy(src, dst)`                  | Copia server-side donde exista; fallback por streaming.                    |
| `symlink(target, link_path)`      | Solo backends con `supports_symlinks=True`.                                |
| `hardlink(target, link_path)`     | Solo backends con `supports_hardlinks=True`.                               |
| `chmod(path, mode)`               | Bits de modo POSIX. Acepta entero o string octal.                          |

Cada herramienta de escritura resuelve su ruta primero mediante
`_enforce_root` — un payload como `/etc/passwd` se rechaza antes
de cualquier IO. Cada llamada emite una entrada de auditoría en
el logger `core.mcp_server.audit`, con herramienta, resultado,
ruta y tamaño — nunca los bytes del payload.

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

Cuando el servidor instala un `_LogForwarder` (stdio lo hace por
defecto; HTTP lo hace por sesión), ciertos registros se reenvían
al cliente como frames `notifications/message`. Solo se reenvía
el árbol del logger `core.mcp_server` — el chatter de backends
ajenos no se filtra.

El cliente puede ajustar el umbral en vivo:

```json
{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
 "params": {"level": "debug"}}
```

Niveles aceptados: `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency`.

---

## 3. Progreso, cancelación, timeouts

### 3.1 Progreso

Pasa `_meta.progressToken` en un `tools/call` y el servidor emite
frames `notifications/progress` desde los handlers que lo soportan
(`walk` hoy, otros de tipo recorrido en el futuro). En stdio los
frames van directos a stdout; en HTTP se encolan por sesión y se
entregan por el flujo SSE (`GET /messages`).

### 3.2 Cancelación

Los clientes envían `notifications/cancelled` con `requestId`. Un
registro de cancelación por sesión activa un `threading.Event`
que todo handler largo consulta mediante `ctx.check_cancel()`. El
handler lanza `CancelledError`, el dispatcher responde -32603 con
`data.type = "CancelledError"`, y el cliente descarta la respuesta.

### 3.3 Timeouts

Toda herramienta tiene un límite de tiempo real:

| Categoría  | Timeout | Herramientas                                                              |
|------------|---------|---------------------------------------------------------------------------|
| Rápidas    | 15 s    | `stat`, `read_file`, `list_dir`, `checksum`, `search`, `list_versions`, `open_version_read` |
| Recorrido  | 60 s    | `walk`, `grep`                                                            |
| Preview    | 30 s    | `preview`                                                                 |
| Escritura  | 30 s    | toda herramienta de escritura                                             |

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
(60 `tools/call` por minuto en régimen estable). Solo `tools/call`
está limitado; `tools/list`, `initialize`, `ping`, `resources/*`
y `logging/setLevel` siguen libres.

Rechazo: -32001 con `data.type = "RateLimitError"`.

Ajustable mediante `ServerConfig.rate_burst` /
`rate_refill_per_sec`; desactivable con
`rate_limit_enabled = False`.

---

## 5. Multi-backend

Pasa un dict `{id: backend}` como `ServerConfig.backends`
(o `HTTPServerConfig.backends`). Si existe:

 - Una nueva herramienta de solo lectura `list_backends` devuelve
   `[{id, class, name, is_default}]` para que el LLM los enumere.
 - Cada otra herramienta añade un campo opcional `backend: string`
   en su inputSchema. Sin él → default; con ID → routing. IDs
   desconocidos caen en -32602.

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
red-team que se pensó. Tests en
`tests/test_hardening_regressions.py` (clases `McpServerTests`
y `McpHttpTransportTests`).

### 7.1 Escape de filesystem — root-check que resuelve symlinks

`_enforce_root` hace dos pasadas: primero `abspath` para colapsar
`..`/`.`, luego `realpath` para resolver symlinks y volver a
chequear el prefijo contra la root resuelta. Sin la segunda
pasada, un symlink colocado bajo la root (externamente o por el
propio LLM usando la herramienta de escritura `symlink`) apunta
a `/` y dejaría pasar
`write_file("/root/escape/etc/cron.d/evil")`. Ahora
`PermissionError` → -32602.

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

Cada herramienta de escritura emite `outcome=attempt` ANTES de
invocar al backend, luego `outcome=ok` o `outcome=refused`.
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