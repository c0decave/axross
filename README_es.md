<p align="center">
  <img src="resources/logo/axross-logo-256.png" alt="Axross" width="160"/>
</p>

# Axross

**Una UI, más de 30 protocolos, un REPL de Python embebido y una
superficie de herramientas MCP para que un LLM lo controle todo.**

Axross es un gestor de ficheros multiprotocolo y caja de herramientas
de seguridad construido sobre Python y PyQt6. SFTP, SMB, S3, WebDAV,
servicios cloud, IMAP, Usenet, Cisco IOS, FS de impresoras, BSD
r-services — todo en la misma UI con paneles divididos, todo
invocable mediante la misma API `axross.*`, todo accesible vía MCP
para un agente LLM.

Idiomas: [English](README.md) · [Deutsch](README_de.md) · **Español**

---

## 22 puntos fuertes

1. **Más de 30 protocolos, una UI consistente.** SFTP/SCP, FTP/FTPS,
   SMB/CIFS, WebDAV, S3-compatible, Rsync, NFS, Azure Blob/Files,
   OneDrive, SharePoint, Google Drive, Dropbox, iSCSI, IMAP, POP3,
   TFTP, Telnet, WinRM, WMI/DCOM, Exchange (EWS), DFS-N, ADB, MTP,
   **Gopher (RFC 1436)**, **NNTP / Usenet** (lib propia, compatible
   con Python 3.13 — `nntplib` ha desaparecido del stdlib), **SQLite-
   FS / PostgreSQL-FS / Redis-FS / MongoDB GridFS**, **Git como FS
   (dulwich)**, **PJL FS de impresoras** con sondeo de seguridad
   obligatorio, **SLP (RFC 2608)** descubrimiento sólo lectura, **rsh
   / rcp** legacy en texto plano, **Cisco IOS Telnet** con fichero
   virtual `/show/<cmd>.txt`, más un **espacio de trabajo volátil
   sólo en RAM** (RamFS).

2. **Flujo multipanel estilo Total Commander.** Tantos paneles como
   quieras, divisiones horizontales/verticales, drag-and-drop entre
   dos cualesquiera — incluyendo **transferencias relay entre
   protocolos** (S3 → SFTP, WebDAV → Rsync, …) sin pasar por disco.

3. **Layout-presets con tecla rápida cíclica.** `single`, `dual`,
   `quad-files`, `commander`, `dev-shells`, `triage`, `shells-quad`.
   `Ctrl+Alt+L` rota hacia adelante, `Ctrl+Alt+Shift+L` hacia atrás.

4. **REPL Python embebido con 90 nombres públicos de scripting.** Dock
   inferior `Console`, API `axross.*` curada con verbos de fichero,
   helpers ping/whois/snmp/tls/http, diagnósticos, recovery, previews
   de seguridad y clases de resultado, historia persistente,
   tab-completion sin efectos colaterales (no dispara getters
   `@property`), comandos slash `.save / .load / .run / .scripts /
   .delete`. Ver
   [docs/SCRIPTING_es.md](docs/SCRIPTING_es.md) +
   [docs/SCRIPTING_REFERENCE.md](docs/SCRIPTING_REFERENCE.md).

5. **Panel de documentación con pestañas.** Junto al REPL — cuatro
   pestañas: `API` (todas las funciones `axross.*` con búsqueda y
   docstring completo), `Slash` (todos los comandos slash),
   `Scripts` (los 32 scripts incluidos), `Protocol` (la interfaz
   `FileBackend` que cada backend implementa).

6. **32 scripts listos para usar.** mirror, dedupe, find_secrets,
   port_scan, slp_inventory, recopilación Cisco IOS, archivo IMAP,
   diff sha256, exportar bookmarks, mac_lookup, time_skew,
   ssh_hostkey_collect, tls_cert_survey, http_probe_batch,
   snmp_walk, ramfs_pipeline, … — bajo
   [`resources/scripts/`](resources/scripts/), todos invocables vía
   `axross --script` o desde el REPL con `.run name`.

7. **Modo servidor MCP para agentes LLM.** Headless `axross
   --mcp-server` habla JSON-RPC sobre stdio o HTTPS+mTLS. Sólo
   lectura por defecto; `--mcp-write` abre la mutación de ficheros;
   **`--mcp-allow-scripts` permite al LLM escribir y ejecutar sus
   propios scripts Python** a través del servidor. Ver
   [docs/MCP_es.md](docs/MCP_es.md).

8. **Overlay cifrado (`.axenc`).** Formato de fichero sellado con
   AEAD que se deja caer en cualquier backend. Descifrar
   directamente en RamFS — el texto plano nunca toca disco. El
   script `redact.py` cifra cada fichero bajo una ruta que coincida
   con un regex.

9. **Defaults conscientes de OPSEC.** Supresión per-perfil del
   historial de shell (zsh + bash + dash, desactivable), avisos de
   credenciales en texto plano en cada sesión legacy (Telnet, rsh,
   NNTP en 119), banner de cliente camuflado como OpenSSH /
   Firefox-ESR, sondeo de seguridad PJL obligatorio (sin imprimir
   bytes accidentalmente en una impresora no-PJL). Detalles en
   [docs/OPSEC.md](docs/OPSEC.md).

10. **Capa de seguridad operacional.** Las operaciones mutantes
    escriben logs estructurados redactados y un journal JSONL
    append-only; los flujos de delete, trash y transfer se pueden
    previsualizar antes de ejecutarlos; el menú Tools y la API
    `axross.*` exponen diagnósticos de backend, recovery scans e
    historial reciente de operaciones. El modo `paranoid` bloquea
    viewers externos, previews automáticas, scripts, protocolos
    legacy y overrides de proxy privado.

11. **Verbos de workflow multi-sistema.** `axross.where_was_i()`
    recuerda el último directorio + ops recientes en cualquier host
    que tocaste. `compare_file([h1, h2, h3], "/etc/nginx.conf")`
    sondea el mismo path en N hosts en paralelo y emite un diff
    unificado. `inspect_targets` hace lo mismo para una lista
    heterogénea de pares `(backend, path)` («¿el /tmp/foo.bin local
    es realmente el mismo archivo que el objeto S3 y la copia
    SFTP?»). `federated_search([…])` traduce una consulta a la
    búsqueda nativa más eficiente por backend — IMAP SEARCH para
    IMAP, `find_by_query` para DB-FS, walker genérico si no.
    `dashboard()` rinde estado de federación en una pantalla (text /
    markdown / json). El pulse de connection-health prueba cada
    sesión con el no-op más barato del protocolo; el countdown de
    production-tarpit dispara la primera vez que haces algo
    destructivo en un perfil `production=True`. Ver
    [docs/MULTI_SYSTEM.md](docs/MULTI_SYSTEM.md) y
    [docs/DAILY_DRIVER.md](docs/DAILY_DRIVER.md).

12. **Reverse-serve sobre S3 / WebDAV.** `axross.serve_s3(backend)`
    y `axross.serve_webdav(backend)` exponen cualquier backend
    abierto en axross como endpoint localhost. restic / aws-cli /
    terraform / rclone / gnome-files / davfs2 / macOS Finder
    funcionan sin más — toda herramienta que ya hable S3 o WebDAV
    accede al instante al protocolo que axross esté fronteando
    (SFTP, SMB, RamFS, Postgres-FS, IMAP-as-FS, …). Bind localhost
    por defecto + auth Bearer-token + modo read-only + rechazo de
    path-traversal. Ver
    [docs/REVERSE_SERVE.md](docs/REVERSE_SERVE.md).

13. **Transferencias cross-backend resilientes.**
    `axross.resumable_copy()` divide la fuente en segmentos, escribe
    un manifest tras cada uno, y en re-run sigue desde el primer
    segmento incompleto tras verificar los hashes guardados en
    destino. Sobrevive a Ctrl-C, caídas de VPN, intérpretes
    crasheados. Junto al chunk adaptativo (por BDP, reasesado por
    histéresis, 16 KiB ≤ chunk ≤ 16 MiB) las transferencias largas
    encuentran un tamaño útil en LAN Gbit, 4G y satélite por igual.

14. **Time-lapse / trail.** `axross.snapshot_now(backend, path)`
    junto a `start_trail()` mantiene un ledger SQLite de snapshots
    periódicos de metadata para cualquier árbol de directorios en
    cualquier backend que axross hable. Diff entre dos snapshots
    para ver archivos añadidos / removidos / modificados; opcional
    hash de drift sobre los primeros 32 KiB. Reconstrucción forense
    de timeline + change-tracking + monitoreo de crecimiento sin
    instrumentación del lado servidor. Ver
    [docs/TRAIL.md](docs/TRAIL.md).

15. **Inspección de directorios LLM-friendly.**
    `axross.summarize(backend, path)` produce una síntesis de un
    párrafo en un round-trip — counts, histograma de extensiones,
    age buckets, top-5 por tamaño. Sin lecturas de body.
    `explain(backend, path)` corre una librería de 15 patrones y
    responde «¿qué ES esto?» — repo git, datadir PostgreSQL,
    config-tree nginx, manifests k8s, Maildir, dir de logs,
    proyectos Python / Node / Docker, … Diseñado para que un agente
    LLM planee sin un dump de list_dir de N-mil entradas.

16. **Pruebas de credenciales autorizadas.** `axross.bruteforce()`,
    `spray()`, `enumerate_users()` para engagements de pentest con
    autorización por escrito. Puerta dura `authorized=True` (sin
    override por env-var, bloqueada en modo `paranoid`), defaults
    lockout-first, password-spray-by-default. Oráculos integrados
    para POP3 + FTP/FTPS + fallback estadístico de timing si no.
    Ver [docs/CRED_ATTACK.md](docs/CRED_ATTACK.md).

17. **Mitigación de CVE por diseño.** El backend SLP nunca construye
    un paquete `SrvReg` — el camino de amplificación SLP
    ([CVE-2023-29552](https://curesec.com/blog/article/CVE-2023-29552-Service-Location-Protocol-Denial-of-Service-Amplification-Attack-212.html))
    es estructuralmente imposible. Los destinos multicast se rechazan
    duro a nivel de socket.

18. **Guard SSRF en cada salto proxy.** Deny-por-defecto contra
    endpoints de cloud-metadata (169.254.169.254 + variantes AWS
    IMDS) y rangos RFC1918; opt-in vía
    `AXROSS_ALLOW_PRIVATE_PROXY=1` cuando realmente necesites pasar
    por una LAN privada. En modo `paranoid`, ese override de proxy
    privado se ignora.

19. **SOCKS5 / HTTP-CONNECT explícito.** Los backends con soporte
    real de proxy usan `core.proxy` — SSH/SCP, Telnet, Cisco-Telnet,
    FTP/FTPS, IMAP, POP3, NNTP, WebDAV, SMB/DFS-N, Gopher, PJL,
    WinRM y transportes cloud compatibles. Los backends que no pueden
    respetar SOCKS/HTTP avisan en vez de conectarse directo en silencio. Ver
    [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md).

20. **Primitivas agnósticas al backend.** Papelera universal,
    escrituras atómicas (temp-sibling + rename), línea-temporal de
    snapshots, almacén content-addressable, extracción de archivos
    con guardas zip-bomb / zip-slip — todo uniforme en cada backend.

21. **Pure-Python donde es posible.** Lib NNTP propia, WebDAV propio
    (sin SDK de terceros), constructor SLPv2 propio, lector Gopher
    propio, reverse-server S3 + WebDAV minimum-viable propio sobre
    `http.server` del stdlib. Árbol de dependencias más pequeño, sin
    SDK lock-in, sin sorpresas con Python 3.13 cuando módulos del
    stdlib desaparecen.

22. **Headless y GUI desde la misma fuente.** Gestor PyQt6, servidor
    MCP stdio/HTTP, o el ejecutador `axross --script <fichero>`.
    AppImage + imágenes Docker en la página de releases; la imagen
    `Dockerfile.mcp` excluye PyQt6 explícitamente para mantenerse
    libre de copyleft.

---

## Inicio rápido

Desde PyPI, cuando haya una release publicada:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install "axross[all]"
axross              # arrancar la GUI
axross --mcp-server # o exponer backends como herramientas MCP a un LLM
```

Desde un checkout del código:

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross              # arrancar la GUI
axross --mcp-server # o exponer backends como herramientas MCP a un LLM
```

```python
# Desde el REPL embebido — dock Console, abajo en la ventana
>>> b = axross.open_url("sftp://alice@example.com/")
>>> for f in b.list_dir("/var/log")[:5]:
...     print(f.name, f.size)
>>> axross.copy(b, "/etc/motd", axross.localfs(), "/tmp/motd")
>>> axross.preview_delete(axross.localfs(), ["/tmp/motd"])
>>> axross.diagnose(b)
>>> axross.help()         # o haz clic en el panel de docs a la derecha
```

Tabla completa de extras + herramientas de sistema por protocolo:
**[INSTALL.md](INSTALL.md)**.

---

## Documentación

| Documento | Cubre |
|---|---|
| [INSTALL.md](INSTALL.md) | Prerrequisitos, extras por protocolo, OAuth, build de wheel, dev. |
| [docs/USAGE.md](docs/USAGE.md) · [USAGE_de.md](docs/USAGE_de.md) · [USAGE_es.md](docs/USAGE_es.md) | Guía de usuario — conexiones, paneles, transferencias, terminal, acciones de menú. |
| [docs/SCRIPTING.md](docs/SCRIPTING.md) · [SCRIPTING_de.md](docs/SCRIPTING_de.md) · [SCRIPTING_es.md](docs/SCRIPTING_es.md) | REPL + API `axross.*` + comandos slash + 32 scripts incluidos + tools MCP de scripting. |
| [docs/SCRIPTING_REFERENCE.md](docs/SCRIPTING_REFERENCE.md) | Referencia auto-generada de cada función con firma + docstring completo. |
| [docs/MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) · [MCP_es.md](docs/MCP_es.md) | Referencia del servidor MCP — herramientas, sesiones, mTLS, rate limits, hardening. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Manual completo en alemán (workflows, diálogos, atajos de teclado). |
| [docs/OPSEC.md](docs/OPSEC.md) | Modelo de amenazas + análisis de qué revela el cliente al servidor. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT por protocolo. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | Recetas de registro de app para OneDrive / SharePoint / Google Drive / Dropbox. |
| [docs/MULTI_SYSTEM.md](docs/MULTI_SYSTEM.md) · [MULTI_SYSTEM_de.md](docs/MULTI_SYSTEM_de.md) · [MULTI_SYSTEM_es.md](docs/MULTI_SYSTEM_es.md) | Verbos de workflow cross-host — `where_was_i`, `compare_file`, `federated_search`, `dashboard`, `resumable_copy`, … |
| [docs/DAILY_DRIVER.md](docs/DAILY_DRIVER.md) · [DAILY_DRIVER_de.md](docs/DAILY_DRIVER_de.md) · [DAILY_DRIVER_es.md](docs/DAILY_DRIVER_es.md) | Tarpit de producción + chunk adaptativo — primitivas debajo de los verbos multi-sistema. |
| [docs/REVERSE_SERVE.md](docs/REVERSE_SERVE.md) · [REVERSE_SERVE_de.md](docs/REVERSE_SERVE_de.md) · [REVERSE_SERVE_es.md](docs/REVERSE_SERVE_es.md) | Exponer cualquier backend axross por API S3 / WebDAV minimum-viable — toda herramienta que ya las hable accede al instante. |
| [docs/TRAIL.md](docs/TRAIL.md) · [TRAIL_de.md](docs/TRAIL_de.md) · [TRAIL_es.md](docs/TRAIL_es.md) | Time-lapse / change-tracking — snapshots periódicos de metadata de cualquier árbol de directorios. |
| [docs/CRED_ATTACK.md](docs/CRED_ATTACK.md) · [CRED_ATTACK_de.md](docs/CRED_ATTACK_de.md) · [CRED_ATTACK_es.md](docs/CRED_ATTACK_es.md) | Pruebas de credenciales autorizadas — fuerza bruta, password spray, enumeración de usuarios con defaults OPSEC. |
| [docs/RED_TEAM_NOTES.md](docs/RED_TEAM_NOTES.md) | Revisión adversaria de cada backend — hallazgos cerrados, riesgos aceptados, follow-ups abiertos. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Suite de tests, lab Docker, matriz de cobertura por protocolo. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | Release PyPI/sdist/wheel, bundle PyInstaller, AppImage, imagen Docker MCP headless. |
| [SECURITY.md](SECURITY.md) | Política de divulgación de vulnerabilidades. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Alcance de PRs, estilo de código, licencia de contribución. |

---

## Contribuir

Pull-requests bienvenidos — ver [CONTRIBUTING.md](CONTRIBUTING.md).
Reportes de seguridad: [SECURITY.md](SECURITY.md).

## Licencia

El código fuente de Axross está bajo **Apache License 2.0** — ver
[LICENSE](LICENSE), [NOTICE](NOTICE), y atribuciones por dependencia
en [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Tres capas de distribución a tener en cuenta:

1. **Árbol fuente** (este repositorio) — Apache-2.0. El usuario
   instala PyQt6 por su cuenta vía `pip install`; ningún componente
   GPL viene en la fuente.
2. **Bundles PyInstaller pre-construidos** (`dist/axross-slim`,
   `dist/axross-full`, el AppImage) — enlazan PyQt6 estáticamente,
   que es GPL-3.0-or-commercial de Riverbank. Cualquier binario así
   redistribuido por nosotros se ofrece bajo **GPL-3.0**. Para un
   binario no-GPL, recompila contra PySide6 (LGPL-3.0) desde la
   misma fuente Apache-2.0.
3. **`Dockerfile.mcp`** — excluye PyQt6 explícitamente; la imagen
   resultante es Apache-2.0 únicamente, sin herencia copyleft.

Copyright © 2026 Marco Lux.
