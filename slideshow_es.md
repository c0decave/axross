# Slideshow de axross

Todas las capturas de pantalla de axross, cada una con lo que muestra. Volver al [README](README_es.md).

## Subida a SFTP

![Subida de un panel local a SFTP con el dock Transfers](docs/screenshots/remote-transfer.png)

Cuatro fotos copiadas del panel local al NAS; el dock Transfers muestra cada archivo con su dirección, tamaño y estado.

## Workspaces

![Workspaces como pestañas, un panel de archivos y una shell local lado a lado](docs/screenshots/workspaces.png)

Layouts de paneles con nombre como pestañas - aquí **Website** con su panel de archivos y una shell local al lado. Un workspace se separa en su propia ventana y vuelve como pestaña.

## Toolbar

![La toolbar con un icono por herramienta sobre dos paneles y la barra de bookmarks](docs/screenshots/toolbar.png)

Un botón por herramienta - Agent, Analysis (sift), Terminal, Find Files, Scripts, consola Python, Tags, Trash, Media Player, Audio & Video Settings, Treemap, Drives, Settings, Features. En una ventana estrecha las herramientas pasan a una segunda fila en lugar de desaparecer. Los botones se agrupan por categoría - Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions - con un separador entre los grupos, y el color de cada categoría es un tinte sutil detrás de sus botones que nunca hace difícil leer un icono. Un botón se mueve arrastrándolo dentro de su grupo; el orden se conserva, y el menú contextual de la toolbar tiene Reset Toolbar Order. Edit → Settings… → Toolbar desactiva la agrupación y los colores y fija el color de cada categoría.

## Tags

![La ventana Tagged Files con los archivos de un tag](docs/screenshots/tags.png)

Puntos de colores en la columna Name; **Tagged Files** lista cada tag y sus archivos en cualquier backend, **Go to File** abre la carpeta en un panel.

## Editor de texto

![El editor de texto con pestañas, resaltado de Python y la barra de búsqueda](docs/screenshots/editor.png)

Pestañas para archivos locales y remotos, resaltado con Pygments, buscar y reemplazar con regex, encoding y line endings en la barra de estado.

## Find Files

![Find Files con presets de tipo y resultados de varias carpetas](docs/screenshots/find-files.png)

Nombre, contenido, tamaño, fecha, tag y presets de tipo, también dentro de archivos comprimidos; con un clic la búsqueda queda como **Smart Folder**.

## Media Player

![El panel Media Player con portada, espectro, ecualizador y playlist](docs/screenshots/media-player.png)

Un panel de extensión: portada y título, un espectro animado, un ecualizador de 10 bandas con presets y una playlist que se llena con drag & drop.

## Imágenes de disco

![Las particiones de una imagen de disco, listas para montarse read-only](docs/screenshots/disk-image.png)

Las particiones y sistemas de archivos de una imagen, leídos sin escribir nada; **Mount Read-Only** lleva una a un panel.

## Voice

![Settings, página Voice: respuestas habladas, push-to-talk y la tecla de mantener](docs/screenshots/voice.png)

Respuestas habladas en alemán o inglés, una voz por idioma con su velocidad, tono, expresividad, volumen y pausa (Listen reproduce una muestra), push-to-talk con una tecla mantenida, y adónde va el texto reconocido.

## Bookmarks

![Manage Bookmarks con grupos, un bookmark de terminal y ubicaciones remotas](docs/screenshots/bookmarks.png)

Grupos, ubicaciones locales y remotas y un bookmark de terminal en un solo gestor; ordena, mueve y edita varios a la vez.

## Settings

![Edit, Settings: todos los settings en un diálogo con campo de búsqueda](docs/screenshots/settings.png)

Todos los ajustes en un diálogo, con campo de búsqueda.

## Features

![Help, Features: qué está instalado, qué falta y cómo conseguirlo](docs/screenshots/features.png)

Qué está instalado y qué falta, con el comando o la descarga que lo añade.

## Amber Mode

![El preset de layout quad-files en Amber Mode](docs/screenshots/quad-files.png)

El preset de layout `quad-files`: cuatro paneles, cada uno con su barra de ruta, filtro y columnas de permissions y owner. `Ctrl+Alt+L` recorre los presets.

## Dock Scripts

![El dock Scripts con un script propio](docs/screenshots/scripts-panel.png)

Tus scripts junto a los ejemplos read-only, escritos contra la API `axross.*`; se ejecutan en el dock o en la Console.

## Duplicate Finder

![El Duplicate Finder con dos grupos](docs/screenshots/duplicate-finder.png)

Archivos idénticos por hash de contenido, agrupados; la copia más antigua de cada grupo aparece en negrita.

## Metadatos

![Metadatos de una foto con datos EXIF y GPS](docs/screenshots/metadata.png)

Campos EXIF y la posición GPS de una foto; **Remove Metadata** los quita antes de compartirla — in place o como copia limpia (**Tools → Metadata Settings…**).

## Dock Analysis (sift)

![El dock Analysis explica un archivo CSV](docs/screenshots/analysis.png)

El extra opcional `sift` explica el archivo seleccionado — aquí un CSV, sin ningún LLM. Se abre con clic derecho → **Analyse with sift** (una carpeta: **Analyse Folder with sift**), **Tools → Analyse with sift** o `Ctrl+Shift+I`; el botón de la toolbar y la barra de título muestran el tamiz de sift. Edit → Settings… → Analysis (sift) desactiva el análisis automático y fija el límite de lectura de sift, el time budget, vision, context, tags, categories, la cache (con *Clear Cache*) y un perfil LLM propio.

## Tema Modern claro

![Dos paneles en la vista de miniaturas, tema claro](docs/screenshots/thumbnails.png)

Dos paneles en la vista de miniaturas con el tema Modern claro. Imágenes, vídeos y PDF muestran una miniatura, las carpetas su icono; View → Thumbnail View (Ctrl+Shift+G) cambia un panel entre lista y miniaturas, y el tema sigue el esquema claro u oscuro del escritorio.

## Dock Log

![El dock Log tras un copy y un move](docs/screenshots/log-dock.png)

Cada copy y move queda registrado con su comprobación de integridad (sha256) y una entrada en el journal de operaciones.

## Topics

![El menú Topics de un tab de Agent](docs/screenshots/agent-topics.png)

Tareas listas — inventario, servicios, logs, uso de disco, resumen de una carpeta — rellenan la petición; cada tab es su propia sesión.

## La conexión de un panel, prestada al agente

![El agente lee un archivo de un panel remoto](docs/screenshots/agent-remote-pane.png)

El panel izquierdo está conectado a un almacenamiento remoto; el agente lee `/reports/q3.txt` a través de él, sin login propio.

## Perfiles de sandbox

![Agent Settings, página Sandboxes](docs/screenshots/agent-sandboxes.png)

Engine (bubblewrap, podman, docker), nivel de `lax` a `paranoid`, hosts permitidos y carpetas extra — aplicados antes de cada tarea.

## Access por tab

![El diálogo Access de un tab de Agent](docs/screenshots/agent-access.png)

Qué funciones de axross puede usar el agente, qué hosts alcanza y qué carpetas ve, read-only o con escritura.

## Servidores MCP

![Agent Settings, página MCP Servers](docs/screenshots/agent-mcp-servers.png)

Más servidores MCP para el agente — aquí el propio axross por stdio, probado: 11 tools.

## Agent Stats

![La ventana Agent Stats sobre la ventana principal](docs/screenshots/agent-stats.png)

La extensión incluida cuenta tareas, tool calls, errores y tokens, de todos los tabs y del último.

## Perfiles de agente

![El menú + del dock Agent con New Tab from Profile y los siete presets](docs/screenshots/agent-profiles.png)

La flecha junto a **+** abre un nuevo tab de Agent desde un perfil - siete presets (Files Assistant, Reverse Engineering, Forensics read-only, Network & Web Recon, Code & Secrets, Remote Ops, Research) o uno propio. El tab nombra su perfil y lo que aún falta, con **Install from Catalog…**.

## Página Profiles

![Settings, Agent, Profiles: el preset Reverse Engineering y lo que recibe un tab](docs/screenshots/agent-profile-settings.png)

Un perfil agrupa LLM, perfil de prompt, protection mode, sandbox, grupos de tools, funciones de axross y servidores MCP por categoría o nombre. Los presets son read-only, **Copy** crea uno editable y la vista previa muestra lo que recibe un tab dentro de la página Access.

## Catálogo MCP

![Add MCP Server from Catalog con los servidores del c0decave MCP Hub](docs/screenshots/mcp-catalog.png)

El c0decave MCP Hub añade 17 herramientas de seguridad - binwalk, capa, Nmap, YARA, The Sleuth Kit y más - como imágenes fijadas por digest; cada una corre en podman sin capabilities, con la raíz read-only y sin red salvo que la permitas. Una entrada de terceros como REA dice quién la mantiene.

## Cut y Paste

![Dos archivos cortados en un panel, Paste arriba del menú contextual del otro](docs/screenshots/cut-paste.png)

Ctrl+X o clic derecho **Cut** solo marca los archivos (atenuados); **Paste** en cualquier panel los mueve por la cola de transferencias, y cada origen se elimina solo cuando su copia terminó y fue verificada. Esc vacía el filtro.

## Colores de iconos

![Amber Mode con cada icono en su propio color y Settings, Appearance](docs/screenshots/icon-colours.png)

**Settings → Appearance → Icon colours**: el default del tema, colores propios en cada tema - aquí en Amber Mode, cuyo default dibuja cada icono en ámbar - o un color propio.

## Self-update

![Software Update: hay un axross más nuevo, con Download and Install](docs/screenshots/update.png)

`axross-full` y `axross-slim` buscan una release nueva una vez por arranque, muestran **Update to …** en la barra de estado y se reemplazan tras la comprobación SHA-256; el binario anterior se conserva.

## Los ejemplos corren directamente

![El dock Scripts ejecuta el ejemplo incluido du con una llamada a ajustar](docs/screenshots/scripts-example.png)

**Run** en un ejemplo incluido muestra su llamada Usage para ajustarla - rutas, hosts, perfiles - y lo ejecuta; el output aparece debajo.

## Software de terceros

![Help, Third-Party Software: los proyectos que axross usa o incluye, con licencias](docs/screenshots/third-party.png)

**Help → Third-Party Software…** lista los 222 proyectos que axross usa o incluye, con propósito, licencia, cómo te llega y enlace.
