# Scripting y REPL

Axross es más que un gestor de ficheros — incluye un **REPL de
Python embebido**, una **API `axross.*` curada** que envuelve cada
backend, un **panel de documentación buscable**, un **directorio
de scripts persistente** y una **superficie de herramientas MCP**
que permite a un agente LLM escribir y ejecutar sus propios scripts.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

---

## Formas de ejecutar código contra axross

| Superficie | Cuándo | Punto de entrada |
|---|---|---|
| **Dock Scripts** | Escribir, gestionar y ejecutar scripts en la GUI | *View > Panels > Scripts* (junto a *Console*) |
| **Dock Console** (REPL) | Exploración interactiva en la GUI | Dock inferior, pestaña *Console* |
| **`axross --script <fichero>`** | Headless / cron / CI | `axross --script myscript.py` |
| **Comandos slash del REPL** | Guardar / cargar / ejecutar scripts desde el prompt | `.save name`, `.run name` |
| **Scheduled Jobs** | Un script guardado a intervalos | *View > Scheduled Jobs…* |
| **Herramientas MCP `script_*`** | Agente LLM controla axross | Arrancar con `--mcp-allow-scripts` |

Todas comparten el mismo módulo `core.scripting` — lo que funciona
en el REPL funciona idéntico en script, headless o vía LLM. *Help >
Scripting Guide* muestra esta guía (en el idioma de la interfaz) y la
referencia de la API dentro de la app; *F1* lista las teclas del dock
Scripts y los comandos slash.

---

## El dock Scripts

*View > Panels > Scripts*: a la izquierda los scripts guardados
(`~/.config/axross/scripts/`) y los **Examples** incluidos (solo
lectura; **Copy to My Scripts** crea una copia editable), en el centro
un editor de Python con resaltado de sintaxis, números de línea y
auto-indent (Tab = cuatro espacios, Shift+Tab des-indenta), abajo el
output.

- **New**, **Save** (Ctrl+S), **Save As…**, **Rename…** y **Delete**
  gestionan el fichero; un script modificado muestra `*`, y cambiar o
  cerrar con cambios sin guardar pregunta Save / Discard / Cancel.
- **Run** (Ctrl+Return) guarda primero y ejecuta el script **en su
  propio proceso de Python** (`python -I`, cwd = directorio de scripts,
  el mismo namespace `axross` que `--script`). La ventana nunca espera;
  stdout/stderr llegan en vivo (las 10 000 líneas más recientes) y
  después el exit status y la duración. **Stop** termina la ejecución,
  con kill tras 3 s. Cerrar la ventana también la termina.
- Una línea de traceback que apunta al script es un enlace a esa línea.
- **Run in Console** lo ejecuta en el namespace vivo de la Console
  (como `.run`); entonces la ventana espera a que termine. En un
  proceso propio `axross.confirm()` no puede preguntar a nadie: lanza
  `axross.NonInteractiveError` en vez de usar el valor por defecto
  (`assume_yes=True` responde que sí sin preguntar).
- Los scripts de un Scheduled Job llevan `[scheduled]`; Rename y Delete
  avisan antes.
- En modo **paranoid** Run y Run in Console están desactivados (el
  tooltip explica por qué); `.run` y el proceso hijo también se niegan.

---

## La API `axross.*`

La superficie curada cubre **más de cien nombres públicos**
(`len(axross.__all__)`; `axross.api_schema()` los lista todos) en grupos de
conexión/backend, perfiles, IO de ficheros, cifrado/archivos,
bookmarks, scripts, passthroughs por protocolo, DNS/red, helpers de
red, SNMP, búsqueda cross-backend, inspección de contenido,
seguridad/diagnósticos, helpers UI y referencia. Cada función tiene
docstring; el panel de docs y `axross.help()` los leen directamente.

```python
# Conectar
b = axross.open("backup-server")
b = axross.open_url("sftp://alice@host/")
local = axross.localfs()
ram = axross.ramfs()

# IO de ficheros
axross.copy(b1, src, b2, dst)
axross.copy(b1, src, b2, dst, overwrite=True)  # reemplazo explicito
axross.remove(b, path, confirm=True)           # borrado permanente
axross.trash(b, path, confirm=True)            # mover a la papelera Axross
axross.checksum(b, path)
axross.read_text(b, path)
axross.write_text(b, path, text, overwrite=True)

# Cifrado + archivos
axross.encrypt(b, "/secret.txt", "frase")
axross.encrypt(b, "/secret.txt", "frase", keep_original=False)
axross.decrypt(b, "/secret.txt.axenc", "frase")
axross.extract_archive("/tmp/x.zip", "/tmp/out")

# Bookmarks + perfiles
axross.add_bookmark(name="logs", path="/var/log")
axross.save_profile(profile)

# Directorio de scripts
axross.save_script("hola", "...")
axross.run_script("hola")

# Por protocolo
axross.find_tftp_files(tftp_session)
axross.slp_discover("10.0.0.10")     # mitigado contra CVE-2023-29552
axross.nntp_post(session, "alt.test", subject, body)
axross.git_push(git_session)         # solo fast-forward, nunca force-push

# Red
axross.dns_resolve("example.com")
axross.port_open("10.0.0.1", 22)
```

Copy/write/encrypt rechazan destinos existentes por defecto.
`overwrite=True` es el opt-in explicito para reemplazar. `remove()` y
`trash()` solo se ejecutan con `confirm=True`.

### Metadata de ficheros

```python
report = axross.metadata(b, "/photos/IMG_0001.jpg")      # MetadataReport
for f in report.fields:
    print(f.group, f.name, f.value, "kept" if not f.removable else "")
axross.remove_metadata(b, "/photos/IMG_0001.jpg")        # in place, Ctrl+Z restores
axross.remove_metadata(b, "/photos", recursive=True, mode="copy")  # name.clean.ext
axross.export_metadata(b, "/photos", fmt="csv", recursive=True, out="/tmp/meta.csv")
```

Las imágenes conservan solo la orientación EXIF y el perfil ICC y nunca
se recodifican; PDF necesita el extra `[metadata]` (pypdf), audio / vídeo
necesita ffmpeg. Una llamada a `remove_metadata` es un paso de undo.

### Seguridad + diagnósticos

```python
axross.preview_delete(local, ["/tmp/old"])
axross.preview_transfer(src, dst, ["/logs"], "/backup", operation="copy")
axross.diagnose(src, root="/", write_test=False)
axross.recovery_scan(src, "/")
axross.recent_operations(20)
axross.security_mode("paranoid")
```

---

## Comandos slash del REPL

Tecleados en el prompt `>>> ` — no son Python y no tocan el
namespace del intérprete.

| Comando | Efecto |
|---|---|
| `.help` | Esta lista |
| `.scripts` | Nombres de scripts guardados |
| `.save <nombre>` | Guardar la historia actual como `<nombre>.py` |
| `.load <nombre>` | Imprimir el código de un script |
| `.run <nombre>` | Ejecutar un script en el namespace REPL activo (rechazado en modo paranoid) |
| `.delete <nombre>` | Eliminar un script |
| `.open` | Mostrar la ruta del directorio de scripts |

---

## Scripts de ejemplo incluidos

32 scripts listos para usar bajo `resources/scripts/`. Arráncalos
con `axross --script resources/scripts/<name>.py` o cópialos a
`~/.config/axross/scripts/` y llámalos desde el REPL con
`.run <name>`.

Los ejemplos de la API publica `axross.*` estan en
[`examples/scripting_api/`](../examples/scripting_api/). Son modulos
Python normales con smoke tests locales y pruebas opcionales de
protocolos contra el lab Docker.

La versión inglesa lista cada script con su descripción; ver
[SCRIPTING.md](SCRIPTING.md#bundled-example-scripts).

---

## Superficie de herramientas MCP

Con `--mcp-allow-scripts` se exponen seis herramientas adicionales
a clientes MCP (Claude Desktop, Cline, agentes propios):

| Tool | Descripción |
|---|---|
| `script_list` | Nombres de los scripts guardados |
| `script_api_schema` | La API `axross.*` como JSON (`axross.api_schema()`) |
| `script_read` | Código fuente de un script |
| `script_write` | Guarda código como `<name>.py` (modo 0o600) |
| `script_run` | Ejecuta un script en su propio proceso (`args`, `timeout_s`); devuelve el código de salida, stdout/stderr y una excepción no capturada |
| `script_delete` | Elimina un script |

`script_run` ejecuta Python arbitrario como el usuario del servidor —
en un proceso hijo con stdin vacío, timeout de wall clock y grupo de
procesos propio, pero con todos los permisos de ese usuario—; por eso
la opción es **independiente de `--mcp-write`**. Quien no quiera ceder
ejecución de código al LLM la deja apagada. Con ambos flags
desactivados → MCP queda estrictamente de solo lectura. El formato de
la respuesta está en [MCP_es.md](MCP_es.md) §2.

---

## Scripts que ejecuta una máquina

Un LLM (o cron, CI, cualquier llamador sin un humano al teclado)
necesita garantías que el REPL nunca tuvo que dar:

- **Consultar antes de escribir.** `axross.api_schema()` (MCP:
  `script_api_schema`) es la API como JSON, construida desde el
  código: por función la firma con tipos, el primer párrafo del
  docstring, `mutates` (puede cambiar ficheros, estado remoto o
  ajustes) y `prompts` (puede necesitar a un humano), más los métodos
  de toda sesión de backend. `axross.docs(name)` es la prosa de una
  función.
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

- [USAGE_es.md](USAGE_es.md) — recorrido completo de la GUI
- [MCP_es.md](MCP_es.md) — referencia del servidor MCP
- [OPSEC.md](OPSEC.md) — configuración por defecto OPSEC
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — revisión adversarial
