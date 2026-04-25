# Axross

Un gestor de ficheros multiprotocolo flexible construido con Python
y PyQt6. Navega, transfiere y gestiona ficheros sobre SFTP, SMB, S3,
WebDAV, los principales servicios cloud y otros 16 protocolos —
todo desde una única interfaz estilo Total Commander con paneles
divididos, cola de transferencias y terminal SSH integrado.

Idiomas: [English](README.md) · [Deutsch](README_de.md) · **Español**

## Qué hace

- **22 protocolos, una UI.** SFTP, SCP, FTP/FTPS, SMB/CIFS, WebDAV,
  compatible con S3, Rsync, NFS, Azure Blob/Files, OneDrive,
  SharePoint, Google Drive, Dropbox, iSCSI, IMAP, Telnet, WinRM,
  WMI/DCOM, Exchange (EWS), DFS-N, ADB, MTP.
- **Workflow multi-panel.** Tantos panels como quieras, divididos
  horizontal/vertical, drag-and-drop entre cualesquiera dos panels
  — incluyendo transferencias relay cross-protocolo.
- **Primitivas agnósticas al backend.** Papelera universal,
  escrituras atómicas, overlays cifrados, línea temporal de
  versiones, almacenamiento direccionable por contenido, extracción
  de archivos con guards anti zip-bomb / zip-slip.
- **Modo servidor MCP.** Expone cualquier backend como una
  superficie de herramientas JSON-RPC para que un cliente LLM
  (Claude Desktop, Cline, un agente propio) lo maneje. Solo
  lectura por defecto; `--mcp-write` opt-in para mutaciones.

## Quick start

```bash
git clone https://github.com/c0decave/axross
cd axross
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
axross
```

La instalación base solo descarga lo que necesitan los protocolos
siempre disponibles (SFTP, SCP, FTP/FTPS, Telnet, IMAP). El resto se
añade como extras:

```bash
pip install -e ".[smb]"          # SMB / CIFS + DFS-N
pip install -e ".[s3]"           # compatible con S3
pip install -e ".[onedrive]"     # OneDrive + SharePoint
pip install -e ".[gdrive]"       # Google Drive
pip install -e ".[dropbox]"      # Dropbox
pip install -e ".[all]"          # todos los livianos a la vez
```

Tabla completa de extras + herramientas del sistema por protocolo:
**[INSTALL.md](INSTALL.md)**.

## Documentación

| Documento | Qué cubre |
|---|---|
| [INSTALL.md](INSTALL.md) | Prerequisitos, extras por protocolo, setup OAuth, build de wheel, setup de dev. |
| [docs/USAGE_es.md](docs/USAGE_es.md) · [USAGE.md](docs/USAGE.md) · [USAGE_de.md](docs/USAGE_de.md) | Guía de uso — conexiones, panels, transferencias, terminal, acciones de menú contextual. |
| [docs/HANDBUCH.md](docs/HANDBUCH.md) | Manual completo en alemán (workflows, referencia de diálogos, atajos). |
| [docs/MCP_es.md](docs/MCP_es.md) · [MCP.md](docs/MCP.md) · [MCP_de.md](docs/MCP_de.md) | Referencia del servidor MCP — herramientas, sesiones, mTLS, endurecimiento. |
| [docs/OPSEC.md](docs/OPSEC.md) | Modelo de amenazas + análisis por finding de qué revela el cliente al servidor. |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | Recetas de registro de app para OneDrive / SharePoint / Google Drive / Dropbox. |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Suite de tests, lab Docker, matriz de cobertura por protocolo. |
| [docs/PROXY_SUPPORT.md](docs/PROXY_SUPPORT.md) | SOCKS5 / SOCKS4 / HTTP-CONNECT por protocolo. |
| [docs/PACKAGING.md](docs/PACKAGING.md) | Bundle PyInstaller, AppImage, imagen Docker MCP headless. |
| [SECURITY.md](SECURITY.md) | Política de divulgación de vulnerabilidades. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Scope de PR, estilo de código, licencia de contribuciones. |

## Aspectos destacados

- **Atomicidad de primera clase.** Las escrituras van a un fichero
  temporal hermano y se renombran al hacer commit. En S3, Azure,
  Dropbox, GDrive, OneDrive, IMAP, Rsync el upload subyacente es ya
  atómico; en el resto el rename es el punto de commit.
- **Cobertura honesta.** La matriz de cobertura por protocolo en
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) te dice exactamente qué
  backends se ejercitan contra implementaciones reales vs. mock vs.
  sin tests. Sin teatro de CI verde.
- **Defaults conscientes de OpSec.** Los banners identificables del
  cliente se mezclan con la mayoría OpenSSH / Firefox ESR; los
  uploads rsync stripean uid/gid/permisos locales por defecto;
  overrides por perfil para keepalive SSH, nombre de workstation
  SMB, NAWS de Telnet. Desglose completo: [docs/OPSEC.md](docs/OPSEC.md).
- **Listo para MCP.** `axross --mcp-server` headless expone el
  backend configurado como herramientas JSON-RPC (stdio o
  HTTP+mTLS). 17 herramientas, rate limits por sesión, streaming
  SSE de progreso.

## Contribuir

Pull requests bienvenidos — ver [CONTRIBUTING.md](CONTRIBUTING.md).
Reportes de seguridad: [SECURITY.md](SECURITY.md).

## Licencia

El código fuente de Axross se distribuye bajo la **Apache License
2.0** — ver [LICENSE](LICENSE), [NOTICE](NOTICE) y atribución por
dependencia en [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Tres capas de distribución que conviene distinguir:

1. **Árbol de fuentes** (este repositorio) — Apache-2.0. Los
   usuarios instalan PyQt6 ellos mismos con `pip`; ningún
   componente GPL viene empaquetado con las fuentes.
2. **Bundles PyInstaller preconstruidos** (`dist/axross-slim`,
   `dist/axross-full`, el AppImage) — enlazan PyQt6 estáticamente,
   que es GPL-3.0-o-comercial de Riverbank. Cualquier binario así
   redistribuido por nosotros se ofrece por tanto bajo términos
   **GPL-3.0**. Si necesitas un binario no-GPL, recompila contra
   PySide6 (LGPL-3.0) desde el mismo fuente Apache-2.0.
3. **`Dockerfile.mcp`** — excluye PyQt6 explícitamente; la imagen
   resultante es Apache-2.0 only, sin herencia de copyleft.

Copyright © 2026 Marco Lux.
