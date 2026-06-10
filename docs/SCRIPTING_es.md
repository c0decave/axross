# Scripting y REPL

Axross es más que un gestor de ficheros — incluye un **REPL de
Python embebido**, una **API `axross.*` curada** que envuelve cada
backend, un **panel de documentación buscable**, un **directorio
de scripts persistente** y una **superficie de herramientas MCP**
que permite a un agente LLM escribir y ejecutar sus propios scripts.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

---

## Cuatro formas de ejecutar código contra axross

| Superficie | Cuándo | Punto de entrada |
|---|---|---|
| **Dock Console** (REPL) | Exploración interactiva en la GUI | Dock inferior, pestaña *Console* |
| **`axross --script <fichero>`** | Headless / cron / CI | `axross --script myscript.py` |
| **Comandos slash del REPL** | Guardar / cargar / ejecutar scripts desde el prompt | `.save name`, `.run name` |
| **Herramientas MCP `script_*`** | Agente LLM controla axross | Arrancar con `--mcp-allow-scripts` |

Todas comparten el mismo módulo `core.scripting` — lo que funciona
en el REPL funciona idéntico en script, headless o vía LLM.

---

## La API `axross.*`

La superficie curada cubre **90 nombres públicos** en grupos de
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
| `.run <nombre>` | Ejecutar un script en el namespace REPL activo |
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

Con `--mcp-allow-scripts` se exponen cinco herramientas adicionales
a clientes MCP (Claude Desktop, Cline, agentes propios):

| Tool | Descripción |
|---|---|
| `script_list` | Nombres de los scripts guardados |
| `script_read` | Código fuente de un script |
| `script_write` | Guarda código como `<name>.py` (modo 0o600) |
| `script_run` | Ejecuta un script, devuelve stdout/stderr + claves del namespace |
| `script_delete` | Elimina un script |

`script_run` ejecuta Python en el proceso del servidor — la opción
es **independiente de `--mcp-write`**. Quien no quiera ceder
ejecución de código al LLM la deja apagada. Con ambos flags
desactivados → MCP queda estrictamente de solo lectura.

---

## Véase también

- [USAGE_es.md](USAGE_es.md) — recorrido completo de la GUI
- [MCP_es.md](MCP_es.md) — referencia del servidor MCP
- [OPSEC.md](OPSEC.md) — configuración por defecto OPSEC
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — revisión adversarial
