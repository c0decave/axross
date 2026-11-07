# Scripting y REPL

Axross es más que un gestor de ficheros — incluye un **REPL de
Python embebido**, una **API `axross.*` curada** que envuelve cada
backend, un **panel de documentación buscable**, un **directorio
de scripts persistente** y una **superficie de herramientas MCP**
que permite a un agente LLM escribir y ejecutar sus propios scripts.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

**Contenido**

- [Formas de ejecutar código contra axross](#formas-de-ejecutar-código-contra-axross)
- [El dock Scripts](#el-dock-scripts)
- [La API `axross.*`](#la-api-axross)
  - [Abrir / conectar](#abrir--conectar)
  - [E/S de ficheros](#es-de-ficheros)
  - [Cifrado + archivos](#cifrado--archivos)
  - [Bookmarks](#bookmarks)
  - [Directorio de scripts](#directorio-de-scripts)
  - [Accesos directos por protocolo](#accesos-directos-por-protocolo)
  - [Helpers de red](#helpers-de-red)
  - [Metadata de ficheros](#metadata-de-ficheros)
  - [Seguridad + diagnósticos](#seguridad--diagnósticos)
  - [Índice de duplicados](#índice-de-duplicados)
- [Comandos slash del REPL](#comandos-slash-del-repl)
- [Scripts de ejemplo incluidos](#scripts-de-ejemplo-incluidos)
- [Superficie de herramientas MCP](#superficie-de-herramientas-mcp)
- [Scripts que ejecuta una máquina](#scripts-que-ejecuta-una-máquina)
- [Véase también](#véase-también)

---

## Formas de ejecutar código contra axross

| Superficie | Cuándo | Punto de entrada |
|---|---|---|
| **Dock Scripts** | Escribir, guardar, gestionar y ejecutar scripts en la GUI | *View > Panels > Scripts* (junto a *Console*) |
| **Dock Console** (REPL) | Exploración interactiva en la GUI | Dock inferior, pestaña *Console* |
| **`axross --script <fichero>`** | Headless / cron / CI | `axross --script myscript.py` |
| **Comandos slash del REPL** | Guardar / cargar / ejecutar scripts desde el prompt | `.save name`, `.run name` |
| **Scheduled Jobs** | Ejecutar un script guardado a intervalos | *View > Scheduled Jobs…* |
| **Herramientas MCP `script_*`** | Un agente LLM controla axross | Arrancar con `--mcp-allow-scripts` |

Todas usan por debajo el mismo módulo `core.scripting`: lo que se
puede hacer en el REPL se puede hacer igual en un script, headless o a
través de un LLM. *Help > Scripting Guide* muestra esta guía (en el
idioma de la interfaz) y la referencia completa de la API dentro de la
app; *F1* lista las teclas del dock Scripts y los comandos slash.

---

## El dock Scripts

*View > Panels > Scripts* abre el gestor de scripts, en una pestaña
junto a la Console. A la izquierda: los scripts guardados
(`~/.config/axross/scripts/`) y los **Examples** incluidos. En el
centro: un editor de Python con resaltado de sintaxis, números de línea
y auto-indent (Tab inserta cuatro espacios, Shift+Tab des-indenta,
ambos también sobre una selección entera). Abajo: la salida de la
última ejecución.

| Acción | Qué hace |
|---|---|
| **New** | Crea `<name>.py` a partir de una plantilla corta (nombres: letras, dígitos, `_`, `-`) |
| **Save** (Ctrl+S) | Escribe el texto del editor (modo 0600). Un script modificado muestra `*` |
| **Save As…** | Guarda el texto del editor con un nombre nuevo; el fichero original no cambia |
| **Rename…** / **Delete** | Renombra o borra el fichero; Delete pregunta antes |
| **Run** (Ctrl+Return) | Guarda los cambios pendientes y ejecuta el script **en su propio proceso de Python** |
| **Stop** | Termina la ejecución; si no ha acabado tras 3 s, la mata |
| **Run in Console** | Ejecuta el script guardado en el namespace vivo de la Console (como `.run`) |
| **Copy to My Scripts** | Crea una copia editable de un example incluido (los examples son de solo lectura); al final lleva la llamada del example como sección "Try it" comentada |
| **Run** / **Run in Console** sobre un example | Muestra la llamada Usage del example para ajustarla (rutas, hosts, perfiles) y lo ejecuta con ella |

Cómo se comporta una ejecución:

- El hijo corre con el mismo namespace `axross` que `axross --script`
  (`__name__ == "__main__"`, `__file__` es la ruta del script), en el
  directorio de scripts, aislado con `python -I` para que un script
  guardado llamado `json.py` no sustituya la biblioteca estándar de los
  demás. La ventana nunca lo espera; una ejecución a la vez.
- stdout y stderr (en rojo) llegan en vivo al panel de salida, que
  guarda las 10 000 líneas más recientes y corta las líneas de más de
  1 000 caracteres. La línea de estado muestra el código de salida y la
  duración, o *stopped*.
- Una línea de traceback que apunta al script es un enlace: un clic
  salta a esa línea en el editor.
- Cerrar la ventana termina un script en ejecución. Cambiar a otro
  script, o cerrar la ventana, con cambios sin guardar pregunta Save,
  Discard o Cancel.
- Una ejecución aparte no tiene terminal: `axross.confirm()` lanza
  `axross.NonInteractiveError` en vez de responder por usted (pase
  `assume_yes=True` para responder que sí sin preguntar), y
  `axross.message()` imprime. Use **Run in Console** para scripts que
  necesitan diálogos — entonces corren en el hilo de la GUI y la
  ventana espera a que terminen.
- Los scripts que ejecuta un Scheduled Job llevan `[scheduled]`;
  renombrar o borrar uno avisa antes, porque el job lo nombra.
- En el modo de seguridad **paranoid** (*Edit > Settings > Security*)
  Run y Run in Console están desactivados (el tooltip explica por qué);
  `.run` y el proceso hijo también se niegan.

---

## La API `axross.*`

El namespace curado cubre **más de cien nombres públicos**
(`len(axross.__all__)`; `axross.api_schema()` los lista todos) en los
grupos conexión/backend, perfiles, E/S de ficheros, cifrado/archivos,
bookmarks, scripts, accesos directos por protocolo, DNS/red, helpers de
red, SNMP, búsqueda cross-backend, inspección de contenido,
seguridad/diagnósticos, helpers de UI y referencia. Cada función tiene
docstring; el panel de docs del REPL y `axross.help()` los leen
directamente.

### Abrir / conectar

```python
b = axross.open("backup-server")            # por el nombre de un perfil guardado
b = axross.open_url("sftp://alice@host/")   # por URL
local = axross.localfs()                     # el sistema de ficheros del equipo
ram = axross.ramfs(max_bytes=64 * 1024 ** 2) # espacio de trabajo volátil en el proceso

axross.list_profiles()      # nombres de los perfiles guardados
axross.get_profile(name)    # obtener el ConnectionProfile
axross.save_profile(p)      # añadir o sustituir
axross.delete_profile(name)

axross.list_backends()      # todos los protocolos registrados
axross.available_backends() # solo los que tienen sus dependencias instaladas
```

### E/S de ficheros

```python
axross.copy(b1, src, b2, dst)       # copia entre backends
axross.move(b1, src, b2, dst)       # mover entre backends (rename o copia+borrado)
axross.copy(b1, src, b2, dst, overwrite=True)  # sustitución explícita
axross.remove(b, path, confirm=True)           # borrado permanente
axross.trash(b, path, confirm=True)            # borrado recuperable
axross.checksum(b, path)            # checksum nativo si es barato, si no hash en streaming
axross.read_bytes(b, path)
axross.write_bytes(b, path, data, overwrite=True)
axross.read_text(b, path)
axross.write_text(b, path, text, overwrite=True)
axross.hash_bytes(data, "sha256")
axross.hash_file(b, path, "sha256")
```

Copy/write/encrypt rechazan destinos existentes por defecto. Pase
`overwrite=True` solo cuando quiera sustituirlos. `remove()` y
`trash()` exigen `confirm=True` para que los scripts headless no borren
por accidente.

### Cifrado + archivos

```python
axross.encrypt(b, "/secret.txt", "passphrase")     # conserva /secret.txt
axross.encrypt(b, "/secret.txt", "passphrase", keep_original=False)
axross.decrypt(b, "/secret.txt.axenc", "passphrase")
axross.extract_archive("/tmp/x.zip", "/tmp/out")   # protegido contra zip-bomb / zip-slip
axross.is_archive("/tmp/x.zip")
```

### Bookmarks

```python
axross.list_bookmarks()
axross.add_bookmark(name="logs", path="/var/log", backend_name="Local")
axross.remove_bookmark(index)
```

### Directorio de scripts

```python
axross.script_dir()                   # ~/.config/axross/scripts/, modo 0700
axross.list_scripts()                 # nombres de todos los scripts guardados
axross.save_script("hello", "...")    # modo 0600 desde el principio
axross.load_script("hello")           # el código como str
axross.run_script("hello")            # exec en un namespace nuevo; lo devuelve
axross.delete_script("hello")
```

### Accesos directos por protocolo

```python
axross.find_tftp_files(tftp_session)              # wordlist incluida + caché
axross.slp_discover("10.0.0.10", scope="DEFAULT") # mitigado contra CVE-2023-29552
axross.nntp_post(nntp_session, "alt.test", subject, body)
axross.git_push(git_session)                      # solo fast-forward, nunca force-push
```

### Helpers de red

```python
axross.dns_resolve("example.com", family="any")
axross.port_open("10.0.0.1", 22, timeout=3.0)
```

### Metadata de ficheros

```python
report = axross.metadata(b, "/photos/IMG_0001.jpg")      # MetadataReport
for f in report.fields:
    print(f.group, f.name, f.value, "kept" if not f.removable else "")
axross.remove_metadata(b, "/photos/IMG_0001.jpg")        # en el sitio, Ctrl+Z lo restaura
axross.remove_metadata(b, "/photos", recursive=True, mode="copy")  # name.clean.ext
axross.export_metadata(b, "/photos", fmt="csv", recursive=True, out="/tmp/meta.csv")
```

Las imágenes conservan solo la orientación EXIF y el perfil ICC y nunca
se recodifican; quitarla de un PDF necesita el extra `[metadata]`
(pypdf), audio / vídeo necesita ffmpeg. Una llamada a `remove_metadata`
es un paso de deshacer.

### Seguridad + diagnósticos

```python
axross.preview_delete(local, ["/tmp/old"])
axross.preview_transfer(src, dst, ["/logs"], "/backup", operation="copy")
axross.diagnose(src, root="/", write_test=False)
axross.recovery_scan(src, "/")
axross.recent_operations(20)
axross.security_mode("paranoid")  # bloquea vistas previas, scripts y protocolos heredados
```

### Índice de duplicados

El índice del Duplicate Finder (*View > Duplicate Finder…*,
Ctrl+Shift+D) y su historial de escaneos (*View > Duplicate Index &
History…*). Cada grupo lista sus copias en orden de conservación: la
más antigua por fecha de modificación primero, en empate la ruta más
corta y después la primera alfabéticamente; las copias sin fecha van al
final.

```python
for scan in axross.duplicate_scans():            # la más reciente primero
    print(scan.scan_id, scan.status, scan.root, scan.duplicate_groups)
groups = axross.duplicates(folder="/home/me/Photos")   # o scan=<id>
plan = axross.dedupe(folder="/home/me/Photos")   # simulación: no toca nada
print(plan.render())                             # conservar / papelera por grupo
axross.dedupe(folder="/home/me/Photos", dry_run=False)  # a la papelera de axross
```

`dedupe(dry_run=False)` conserva la primera copia de cada grupo y mueve
las demás a la papelera de axross (recuperables), tras volver a
comprobar cada fichero y la copia conservada en el backend real; solo
actúa sobre los `backends` que se le pasan (por defecto: el sistema de
ficheros local).

---

## Comandos slash del REPL

Se teclean en el prompt `>>> `; no son Python. Nunca tocan el
namespace del intérprete.

| Comando | Efecto |
|---|---|
| `.help` | Esta lista |
| `.scripts` | Nombres de todos los scripts guardados |
| `.save <name>` | Guardar el historial de la sesión actual en `<name>.py`; un script existente con ese nombre nunca se sustituye (bórrelo antes con `.delete`) |
| `.load <name>` | Imprimir el código de un script guardado |
| `.run <name>` | Ejecutar un script guardado en el namespace vivo del REPL (rechazado en modo paranoid) |
| `.delete <name>` | Eliminar un script guardado |
| `.open` | Imprimir la ruta del directorio de scripts |

---

## Scripts de ejemplo incluidos

32 scripts de ejemplo bajo `resources/scripts/`. Cada uno define
funciones; el bloque `Usage::` de su docstring muestra la llamada, así
que un fichero ejecutado tal cual no imprime nada. En la GUI aparecen
bajo **Examples** en el dock Scripts: **Run** o **Run in Console**
muestra esa llamada para ajustarla y ejecuta el example con ella,
**Copy to My Scripts** crea una copia editable con la llamada como
sección "Try it" comentada. Una ejecución que solo definió funciones lo
dice en la línea de estado.

Los ejemplos de la API pública `axross.*` están en
[`examples/scripting_api/`](../examples/scripting_api/). Son módulos
Python normales con smoke tests locales y pruebas opcionales de
protocolos contra el lab Docker.

| Script | Qué hace | Probado E2E |
|---|---|:---:|
| `mirror.py` | Sincronización incremental, consciente de hashes, entre dos backends cualesquiera | ✓ |
| `dedupe.py` | Encontrar ficheros duplicados por sha256 en un árbol | ✓ |
| `du.py` | Árbol de uso de disco ordenado por tamaño — `du -sh` para cualquier backend | ✓ |
| `bulk_rename.py` | Renombrar con regex en un directorio, en simulación por defecto | ✓ |
| `find_secrets.py` | Buscar claves AWS, JWTs, bloques de clave privada, valores de .env | ✓ |
| `port_scan.py` | Prueba TCP concurrente sobre hosts × COMMON_PORTS | ✓ |
| `redact.py` | Cifrar con `.axenc` cada fichero que coincide con una regex | ✓ |
| `hash_audit.py` | Verificar un manifiesto `<sha256>\\t<path>` contra un backend | ✓ |
| `fingerprint_diff.py` | Diff sha256 de dos árboles: añadidos / eliminados / cambiados / iguales | ✓ |
| `sqlite_export.py` | Empaquetar un árbol de directorios en un fichero SQLite-FS | ✓ |
| `ramfs_decrypt.py` | Descifrar `.axenc` directamente en RAM, sin tocar el disco | ✓ |
| `bookmarks_export.py` | Volcar / restaurar los bookmarks guardados en JSON o CSV | ✓ |
| `s3_inventory.py` | Número de objetos + bytes totales + top-N + histograma de extensiones | ✓ |
| `git_changelog.py` | Recorrer una rama Git-FS y emitir líneas `<sha>  <subject>` | ✓ |
| `gopher_archive.py` | Descargar recursivamente un agujero Gopher | ✓ |
| `tftp_audit.py` | Escaneo con wordlist sobre una lista de hosts TFTP | smoke |
| `slp_inventory.py` | Descubrimiento de servicios SLPv2 sobre una lista de hosts | smoke |
| `nntp_subjects.py` | Asuntos de los últimos N artículos de un grupo Usenet | smoke |
| `webdav_quota.py` | `disk_usage` RFC 4331 sobre endpoints WebDAV | smoke |
| `cisco_collect.py` | `show running-config` + versión + interfaces de hosts IOS | smoke |
| `imap_archive.py` | Descargar cada mensaje de una carpeta IMAP como `.eml` | smoke |
| `lab_smoke.py` | Smoke test "¿Responde cada backend configurado?" | smoke |

Las filas "smoke" compilan e importan correctamente; no se prueban de
extremo a extremo porque necesitan infraestructura en marcha (un
servidor TFTP, un daemon SLP, un buzón IMAP, un equipo Cisco, …) que el
entorno de pruebas por defecto no incluye.

---

## Superficie de herramientas MCP

La misma maquinaria de scripting está disponible para clientes MCP
(Claude Desktop, Cline, agentes propios). Arranque con
`--mcp-allow-scripts` para exponer:

| Tool | Descripción | Habilitada por |
|---|---|---|
| `script_list` | Nombres de todos los scripts guardados | `--mcp-allow-scripts` |
| `script_api_schema` | La API `axross.*` como JSON (`axross.api_schema()`) | `--mcp-allow-scripts` |
| `script_read` | Código de un script guardado | `--mcp-allow-scripts` |
| `script_write` | Guardar código Python como `<name>.py` (modo 0o600) | `--mcp-allow-scripts` |
| `script_run` | Ejecutar un script guardado en su propio proceso (`args`, `timeout_s`); devuelve el código de salida, stdout/stderr y una excepción no capturada | `--mcp-allow-scripts` |
| `script_delete` | Eliminar un script guardado | `--mcp-allow-scripts` |

`script_run` ejecuta Python arbitrario como el usuario del servidor —
en un proceso hijo con stdin vacío, timeout de wall clock y grupo de
procesos propio, pero con todos los permisos de ese usuario—; por eso
la opción es **independiente de `--mcp-write`**: no active el scripting
para un cliente LLM al que no confiaría ya la ejecución de código
arbitrario. Con ambas opciones desactivadas, la superficie MCP queda de
solo lectura. [MCP_es.md](MCP_es.md) §2 describe el formato completo de
la respuesta.

---

## Scripts que ejecuta una máquina

Un LLM (o cron, CI, cualquier llamador sin un humano al teclado)
necesita algunas garantías que el REPL nunca tuvo que dar. Lo que
ofrece la API:

- **Consultar antes de escribir.** `axross.api_schema()` (MCP:
  `script_api_schema`; versionado como
  [`scripting-api.json`](scripting-api.json)) es la API como JSON,
  construida desde el código: reglas y excepciones para scripts, los
  nombres por tema, por función la firma con tipos, el docstring
  completo, sus ejemplos, lo que lanza, `mutates` (puede cambiar
  ficheros, estado remoto o ajustes) y `prompts` (puede necesitar a un
  humano); más los métodos de toda sesión de backend y los tipos que
  devuelve la API (`FileItem` y los resultados).
  `axross.api_schema(names=[])` es solo el índice,
  `axross.api_schema(["copy"])` una función completa.
  `axross.docs(name)` es la prosa de una función;
  [LLM_GUIDE.md](LLM_GUIDE.md) §9 y §12 son el camino corto para un
  modelo de lenguaje.
- **Nadie a quien preguntar.** Sin ventana Qt y sin terminal en stdin
  — o con `AXROSS_NONINTERACTIVE=1`, que `script_run` activa —
  `axross.confirm()` lanza `axross.NonInteractiveError` (un
  `PermissionError`) en vez de adivinar una respuesta. `assume_yes=True`
  responde que sí sin preguntar en ese caso; `axross.is_interactive()`
  le dice al script en qué caso está. Una escritura en un perfil
  marcado *production* se rechaza igual, salvo que el entorno que
  arranca axross defina `AXROSS_TARPIT_DISABLE=1`. Una ejecución desde
  el panel Scripts sigue teniendo la cuenta atrás: su salida es en vivo
  y Stop la termina, así que un humano puede verla y detenerla.
- **Cerrar lo que se abre.** Toda sesión admite `with`; al salir del
  bloque se cierra la conexión, también tras una excepción:

  ```python
  with axross.open("backup-server") as b:
      print(axross.summarize(b, "/var/log").render())
  ```
- **Argumentos y código de salida.** `script_run` pasa `args` al
  script como `sys.argv[1:]` y devuelve `sys.exit(n)` como `exit`; una
  excepción no capturada vuelve como `error_type`, `error` y
  `traceback`.

---

## Véase también

- [USAGE.md](USAGE.md) / [USAGE_de.md](USAGE_de.md) / [USAGE_es.md](USAGE_es.md) — recorrido completo de la GUI
- [MCP.md](MCP.md) / [MCP_de.md](MCP_de.md) / [MCP_es.md](MCP_es.md) — referencia del servidor MCP
- [OPSEC.md](OPSEC.md) — configuración OPSEC por defecto
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — revisión adversarial de cada backend
