# Uso de axross

Esta guía cubre lo que puedes hacer con axross una vez que está
corriendo. Para la instalación, ver [INSTALL.md](../INSTALL.md); el
manual en alemán es [USAGE_de.md](USAGE_de.md).

Idiomas: [English](USAGE.md) · [Deutsch](USAGE_de.md) · **Español**

## De un vistazo

axross es un gestor de ficheros estilo Total Commander para más de 30
protocolos, construido en torno a tres ideas:

- **Layout multi-panel.** Divide horizontal o verticalmente en
  tantos panels como quepan en la ventana; cada panel se conecta a su propio backend
  (local, SFTP, S3, IMAP, lo que sea).
- **Primitivas agnósticas al backend.** Papelera, escrituras
  atómicas, overlays cifrados, línea temporal de versiones,
  almacenamiento direccionable por contenido — todo funciona en
  cada protocolo, incluso aquellos cuya API nativa no lo soporta.
- **Modo servidor MCP.** axross puede correr headless y exponer
  cualquier backend configurado como herramientas MCP, de modo que
  un cliente LLM puede manejarlo. Solo lectura por defecto;
  `--mcp-write` opt-in para mutaciones.

## Manual y tours

- **Help → Handbook** (**F1**) muestra esta guía dentro de axross, en el
  idioma de la interfaz (el alemán y el español tienen la suya; cualquier
  otro idioma recibe la inglesa): el índice a la izquierda, encima un campo
  de búsqueda (Return busca la siguiente coincidencia), enlaces entre sus
  secciones. No carga ninguna imagen ni otro recurso y muestra el HTML
  crudo como texto; los enlaces a los otros documentos los abren en GitHub
  en el navegador.
- **F1 abre la sección del área en la que estás**: un panel de ficheros
  abre *Layout multi-panel*, su campo de dirección o de filtro *Path bar*,
  el dock Transfers *Transferencias*, el dock Agent *Dock Agent*, *Connection
  Manager* abre *Conexiones*, y en *Edit → Settings…* F1 abre la parte
  de la página mostrada (*Logging*, *Updates*, las páginas del Agent …; el
  resto *Settings*). En cualquier otro sitio F1 abre el índice. La lista de
  atajos de teclado está en **Ctrl+F1** (*Help → Keyboard Shortcuts*).
- **Help → Tours…** lista tours guiados sobre la ventana real: *Getting
  started*, *Connect to a server*, *Copy and sync safely*, *Find and
  organize*, *Automate* y *Extensions and features*. Un tour oscurece la
  ventana alrededor de la parte que explica y la enmarca - esa parte sigue
  usable - y un recuadro al lado dice *Step k of n* con **Back**, **Next**
  y **End Tour**; **Esc** también termina el tour. Un paso cuya parte no
  está en la ventana (un dock o una extension desactivados, un panel
  cerrado, una toolbar oculta) se salta, y el paso siguiente dice cuáles
  se saltaron; un dock Agent, Scripts o Console cerrado se abre para su
  paso y se cierra de nuevo al terminar el tour.
- **El primer arranque** ofrece el tour *Getting started* una vez, como
  aviso en la barra de estado (*Take the Getting Started Tour*, *No
  Thanks*) - nunca como diálogo. *Edit → Settings… → General → Tours* lo
  ofrece de nuevo en el siguiente arranque, o nunca (`offer_tour_at_start`
  en `settings.json`).

## Conexiones

El Connection Manager (Ctrl+Shift+N) es el sitio para crear perfiles;
Quick Connect (Ctrl+N) abre uno guardado. Cada
perfil selecciona un protocolo y guarda host / usuario / autenticación
/ proxy / opciones por protocolo. Los campos sensibles (passwords,
secretos OAuth, cadenas de conexión Azure) van al keyring del SO; el
JSON de perfil mismo nunca lleva credenciales en plano. Guardar un
perfil con un nombre nuevo lleva sus bookmarks, bookmarks de terminal,
Smart Folders y panels guardados al nombre nuevo. Un perfil renombrado en
un axross sigue renombrado cuando otro axross se cierra. Un perfil nuevo no puede llamarse
`local`: es el nombre de la shell local en los bookmarks de terminal y los
layouts guardados.

- **Dónde se abre una conexión.** Mientras el panel de destino no se ha
  usado - un panel local todavía en tu carpeta personal, sin navegar, sin
  selección ni filtro -, una conexión nueva se abre en su lugar; en el
  primer arranque el servidor ocupa así la mitad derecha de la ventana en
  vez de un tercer panel estrecho. El último panel local nunca se
  reemplaza: una segunda conexión se abre junto a la primera. Si no, se
  abre en un panel nuevo a la derecha. Para tener siempre un panel nuevo,
  mantén **Shift** al hacer clic en la conexión (o en *Connect*), marca *Open in a new pane* en el
  Connection Manager o, con clic derecho sobre un perfil en Quick Connect,
  elige *Connect in New Pane*.

- **Cómo está protegida una conexión.** Un icono junto a cada conexión -
  la cabecera del panel, la pestaña del workspace (su conexión más débil),
  los marcadores, Quick Connect - muestra texto claro, solo firmado, TLS
  (con una debilidad), cifrado SSH o de extremo a extremo; su tooltip dice
  exactamente qué y si se negoció en la conexión viva o solo está
  configurado (FTP en claro, FTPS TLS 1.3 con certificado verificado, SMB
  3.1.1 cifrado o solo firmado, WebDAV http o https, NFS AUTH_SYS en claro,
  IMAP, POP3 y LDAP con STARTTLS ...); WinRM por HTTP (5985) o con un
  certificado sin comprobar muestra TLS con una debilidad.

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
  controla axross; la página externa de consent del navegador puede
  usar la configuración proxy del navegador o del sistema. Receta de
  registro de app por proveedor:
  [OAUTH_SETUP.md](../OAUTH_SETUP.md). Un inicio de sesión caducado o revocado
  lo dice y pide reconectar; solo Conectar o Reconectar abre el navegador, y
  el inicio de sesión allí debe terminarse en 5 minutos.
- **Soporte de proxy.** Por perfil SOCKS5 / SOCKS4 / HTTP-CONNECT
  para backends con un hook de transporte real. SOCKS5 resuelve
  nombres de host en el lado del servidor (sin fuga DNS). SOCKS4
  depende del transporte: los backends raw-socket pueden usar SOCKS4a
  para resolución remota, mientras que stacks HTTP SDK pueden resolver
  localmente. Usa SOCKS5 si importa evitar fugas DNS. rsync envía por
  SOCKS4 los nombres de host como SOCKS4a. Con un proxy, *IP Version* IPv4
  o IPv6 necesita la dirección IP del servidor: con un nombre de host SFTP
  y SCP no conectan, porque el proxy resuelve los nombres; un host rsync con
  caracteres de shell se rechaza. Los backends sin
  soporte SOCKS/HTTP limpio avisan en vez de ignorar campos de proxy
  en silencio. S3 solo usa HTTP-CONNECT; Rsync puede pasar
  `proxy_username` mediante OpenBSD `nc`, pero no `proxy_password`.
  Las sesiones SDK basadas en requests que controla axross ignoran
  `HTTP_PROXY` / `HTTPS_PROXY` del entorno del proceso; el perfil es
  la fuente de la ruta.
- **Servidores de producción.** *Production (confirm destructive
  operations with a countdown)* en el grupo Connection de Connect to
  Server marca el perfil: el primer borrado, movimiento, renombrado o
  sobrescritura en él desde un panel espera unos segundos con una cuenta
  atrás que Cancel o Esc detienen. Ver
  [DAILY_DRIVER_es.md](DAILY_DRIVER_es.md#tarpit-de-producción).
- **Overrides OpSec.** Los campos de perfil controlan keepalive
  SSH, nombre de workstation SMB, NAWS de Telnet, stripping de
  metadata rsync. Ver [OPSEC.md](OPSEC.md) para el modelo de
  amenazas.
- **SFTP con la red caída y servidores lentos.** Cuando el servidor no
  envía nada durante 60 s, axross pregunta a la conexión SSH si sigue
  viva (una petición keepalive, solo entonces - sin cadencia fija, ver
  [OPSEC.md](OPSEC.md)). Sin respuesta: la petición falla con "no
  respondió a tiempo" en lugar de esperar para siempre (Wi-Fi caída, VPN
  desconectada); la siguiente acción abre un canal nuevo. Con respuesta:
  el servidor vive pero es lento (una recuperación de cinta o HSM, un
  archivo en la nube por niveles) y axross sigue esperando, hasta 30
  minutos por petición. Lo mismo vale para los comandos que axross
  ejecuta en el servidor - la suma de comprobación tras cada subida, una
  copia en el servidor: uno largo se espera, una red muerta lo termina.
  Los 60 s son por perfil: **Conectar → SFTP time-out** (*Default (60 s)*,
  hasta 3600 s). Cancelar detiene una transferencia SFTP o SCP al
  instante, también mientras espera a la red o a la suma; una
  transferencia atascada tras un enlace muerto cierra la conexión 10 s
  después (reconecta entonces) - salvo que terminales u otros paneles
  usen la conexión y esta aún responda: entonces solo se cierra el canal
  de la transferencia.
- **Google Drive: Docs, Sheets, Slides y unidades compartidas.** Un
  Google Doc aparece como `<nombre>.docx`, una hoja como `.xlsx`, unas
  Slides como `.pptx`, un dibujo como `.pdf` - sin tamaño - y se lee
  (abre, copia) como esa exportación; Google exporta como máximo 10 MB
  de un documento. Aquí son de solo lectura: sobrescribir uno se
  rechaza, guarda con otro nombre. Moverlo fuera de Drive se rechaza
  antes de copiar nada - a la exportación le faltan comentarios,
  sugerencias, historial de versiones y permisos, y mover borraría el
  original: cópialo en su lugar. Borrar un Google Doc, una hoja, unas
  Slides o una carpeta lo deja en la papelera de Drive (recuperable allí
  30 días); un archivo normal se borra. Un formulario o un sitio no tiene
  forma de archivo y lo dice al leerlo. Los elementos de una unidad
  compartida accesibles desde My Drive (compartidos contigo, la carpeta
  de un acceso directo) funcionan como cualquier otro; las unidades
  compartidas en sí no se listan (aún no hay carpeta
  `/Shared drives/<nombre>`) - ábrelas en el navegador o añade un acceso
  directo en My Drive; subir, crear carpetas y compartir funcionan
  también con esos elementos. Una sobrescritura cancelada en OneDrive o
  Google Drive cuya última parte quizá ya llegó al servidor se deshace
  como cualquier escritura interrumpida, así vuelve el fichero antiguo.
- **Correo como archivos (IMAP, POP3, Exchange).** Un mensaje es
  `<id>_<asunto>.eml`, el nombre entero como máximo 200 bytes UTF-8 (el
  id y `.eml` enteros, un asunto largo cortado en un carácter), para
  poder copiarlo a cualquier carpeta local; un adjunto conserva su
  extensión. Los nombres que antes eran más largos (asuntos CJK o con
  emoji, los ItemId largos de Exchange) ahora son más cortos; IMAP y POP3
  siguen aceptando el nombre antiguo, y un dock de correo no toma el
  mensaje renombrado por nuevo. La carpeta `<uid>` junto a un mensaje
  IMAP lista sus adjuntos; no se puede borrar por sí sola - borra el
  `.eml` para borrar el mensaje. POP3 se reconecta tras perder la
  conexión; los borrados enviados por esa conexión no se confirmaron
  (POP3 confirma solo con QUIT) y un error lo dice, igual que cuando
  falla el QUIT al desconectar. En un servidor POP3 sin UIDL, tras
  reconectar, un mensaje se vuelve a encontrar por sus cabeceras y su
  tamaño; si dos son idénticos, se rechaza el borrado.
- **Repositorios Git por URL.** Una sesión `git+https://` (ssh, git,
  file) es un clon en caché que sigue al remoto: al abrir se hace fetch,
  una rama sin nada pendiente de push sigue a origin (también tras un
  force-push o un borrado), y cada guardado se confirma y se hace push
  al momento (solo fast-forward). Si el push falla, el commit queda en
  la caché y el guardado lo informa; la línea de estado del panel
  muestra "not pushed to origin: main (1)" hasta que el siguiente
  guardado lo envía. Si otra persona hizo push a la rama, un guardado se
  pone al día primero: los cambios en otros archivos se conservan y el
  tuyo va encima; si cambió el mismo archivo, el guardado se rechaza
  (actualiza y repítelo). Los commits aún sin push se aplican sobre la
  nueva punta de origin cuando tocan otros archivos; si no, quedan en una
  rama nueva `axross/unpushed-<fecha>-<hora>` - el mensaje la nombra - y
  la rama muestra la versión de origin: abre esa rama para copiar tus
  archivos de vuelta. Esa rama se sube a origin con el mismo nombre, así
  sobrevive a una caché borrada; si origin la rechaza, el mensaje dice que
  solo está en la caché local (`~/.cache/axross/git/...`) - copia los
  archivos pronto. No se pierde nada. Los ficheros bajo una carpeta
  `.git` (en cualquier mayúscula) no se pueden guardar ni mover a un
  repositorio, y una rama nueva necesita un nombre de rama git válido. Renombrar (un archivo o una carpeta
  entera) es un commit y un push: llega completo o nada. Guardados muy
  seguidos (a menos de 2 s del último fetch o push) no preguntan antes a
  origin; su push sigue sin sobrescribir trabajo ajeno y se pone al día
  como arriba. Si el remoto no es accesible, la copia en caché se abre en solo
  lectura y la línea de estado dice "offline". Los scripts pueden pasar
  `auto_push=False` y hacer push con `axross.git_push()`.

- **Bases de datos, directorios y más en Conectar a servidor.** SQLite
  (*archivo de base de datos*), Git (*repositorio*: una URL,
  `user@host:ruta` o una ruta local), PostgreSQL y MongoDB (*base de
  datos*: un nombre), Redis (*base de datos*: un número, *usar TLS*), LDAP
  (Bind DN, *LDAPS*), SLP (*ámbito*) y Exchange (*servidor* - vacío usa
  autodiscover desde la *dirección de correo*, no combinable con un proxy)
  se conectan desde un perfil guardado; SVN toma una *URL del repositorio*
  con usuario y contraseña opcionales. Las casillas TLS de IMAP, POP3, NNTP
  y LDAP cambian el puerto entre 993/143, 995/110, 563/119 y 636/389; un
  perfil importado sin puerto recibe el de su protocolo; *versión IP* solo
  aparece donde el protocolo la respeta. Sin SSL/TLS, IMAP, POP3 y LDAP
  cifran con STARTTLS (STLS, StartTLS) antes del login y comprueban el
  certificado; un servidor que no lo ofrece, o una red que lo quita, se
  rechaza antes de que salga la contraseña, y lo que el servidor envió
  antes del upgrade no se cree después. Desmarca *STARTTLS before the
  login* solo para un servidor sin TLS en absoluto: la contraseña viaja
  entonces en claro. Los perfiles guardados antes también usan STARTTLS.
  En scripts `imap://`, `pop3://` y `ldap://` cifran, `imap+plain://`,
  `pop3+plain://` y `ldap+plain://` van en claro, `ldaps://` es TLS en 636.
  Esperas: Git 15 s para conectar y
  60 s por respuesta (HTTP(S), SSH, git://), PostgreSQL 10 s para conectar, Redis
  10 s / 30 s por comando, MongoDB 10 s / 60 s por respuesta - las opciones
  propias de una URL mandan. Una conexión NNTP que el servidor cerró por
  inactividad se abre de nuevo sola. Exchange abandona un servidor ocupado
  tras 60 s en total, una contraseña incorrecta falla al instante (sin
  reintentos que bloqueen la cuenta), su caché de autodiscover está en
  `~/.cache/axross/exchangelib`, y un correo reenviado adjunto como
  elemento se descarga como su fuente `.eml`. LDAP nunca sigue una
  referencia (llevaría la contraseña a otro host).

- **Conexiones SSH, FTP y de shell.** *Versión IP* la respetan SFTP, SCP,
  FTP, FTPS, rsync, Telnet, Cisco Telnet y rsh (TFTP solo IPv4). FTPS en el
  puerto 21 es explícito (AUTH TLS), en 990 implícito; *verificar el
  certificado TLS del servidor* (FTPS, WinRM) está activado por defecto.
  WinRM: el puerto 5985 es HTTP, 5986 HTTPS (*usar HTTPS*); lecturas de
  cualquier tamaño, subidas hasta 32 MiB. rsh no necesita usuario, y rsh y
  WMI funcionan como perfiles (WMI toma `DOMAIN\user`, una cuenta con
  permisos WMI remotos; *probar conexión* inicia sesión de verdad). TFTP
  muestra solo los archivos nombrados en *archivos* que el servidor tiene,
  hasta *archivo más grande*. Las transferencias SCP corren junto a la
  navegación, SCP lista carpetas de unas 300 000 entradas y acepta nombres
  que no son UTF-8; un handshake atascado se abandona tras 10 s. Un
  keepalive sin respuesta muestra la conexión SSH como desconectada; las
  claves de host se comparan sin mayúsculas; el inicio con agente necesita
  un ssh-agent en marcha con claves; `%h` / `%r` de un ProxyCommand rechazan
  caracteres de shell y un `-` inicial. Importar una config SSH ya no
  lee los bloques `Match` como parte del host de arriba, convierte
  `ProxyJump` en el ProxyCommand correspondiente (`ssh -J … -W %h:%p`),
  que se pregunta al conectar como cualquier ProxyCommand importado, y
  omite los patrones negados (`!host`); *Deploy SSH Key* pregunta antes de
  ejecutar un ProxyCommand importado. La importación también lee los
  ficheros que una config incluye con `Include` (relativos a `~/.ssh`,
  como mucho 16 niveles), toma el primer valor de un ajuste como hace ssh
  y expande `%h` en HostName; *Deploy SSH Key* lee un `authorized_keys`
  remoto de hasta 4 MiB. rsync por SSH necesita una clave o
  el agente (no se puede escribir una contraseña) y una clave de host
  confirmada una vez con un perfil SFTP; el puerto 873 o vacío significa 22
  en modo SSH y al revés; las descargas fluyen y se pueden cancelar, las
  subidas terminan como un bloque. rsh y Telnet transfieren con progreso y
  cancelación (Telnet por trozos si el servidor tiene `dd` y `wc`). Una
  subida rsh va a un fichero temporal junto al destino y lo reemplaza solo
  cuando han llegado todos los datos; una subida cancelada o fallida deja
  el fichero del servidor intacto, con sus permisos. Un
  comando Telnet expira tras 30 s sin salida, no 30 s en total, y cierra la
  conexión (la siguiente acción vuelve a iniciar sesión). Cisco Telnet
  informa enseguida de una contraseña incorrecta; los comandos show pueden
  tardar hasta 300 s. Un listado FTP se detiene en 300 000 entradas. Cisco Telnet responde al
  `[confirm]` de clear counters. Sin base64, uuencode ni xxd en el
  servidor, una subida Telnet solo admite texto sin caracteres de control
  (tampoco tabuladores). Un montaje NFSv3 del kernel encuentra mountd por
  rpcbind, como mount. En S3 y Azure un objeto cuya clave tiene una parte
  vacía, `.` o `..` (como `a//x`) se lista con un nombre con carácter de
  reemplazo; no se puede abrir, copiar ni cambiar en axross, y una copia
  de carpeta lo lista como no utilizable en vez de omitirlo. WinRM: copiar
  una carpeta copia una junction o un enlace simbólico dentro de ella como
  enlace, con el mismo destino, nunca lo que apunta; borrar una carpeta quita una junction o un enlace simbólico dentro de ella como
  enlace, nunca lo que apunta; una carpeta con entradas solo se borra de
  forma recursiva; un nombre que termina en punto o espacio se rechaza; un
  comando se detiene en su timeout (exec) o tras una hora. ADB: la
  respuesta de un comando es de como mucho 64 MiB, y exec se detiene en su
  timeout. Exchange envía cada petición por el proxy del perfil. La caché
  de Git en `~/.cache/axross/git` es privada (0700) y no guarda ninguna
  contraseña ni token de la URL remota. iSCSI con CHAP necesita root, o
  sudo que pueda ejecutar `cat` y `tee` sobre `/etc/iscsi/nodes`; el
  secreto nunca va en una línea de comandos. SNMP: `snmp_get` de un objeto
  que falta lanza `FileNotFoundError`; SNMPv3 conoce SHA-224 a SHA-512 y
  AES-192/256, y un nombre de protocolo desconocido es un error.

- **Recursos compartidos, dispositivos y almacenes de objetos.** SMB y
  DFS-N tienen una fila *Workstation* (el nombre de estación NTLM;
  WORKSTATION por defecto, nunca el nombre real del equipo); un recurso
  que falta o se rechaza se nombra así. MTP no tiene host ni puerto sino
  *Dispositivo* (el número que lista el montador, 1 es el primero) y
  *Montador* (automático, jmtpfs, simple-mtpfs o go-mtpfs). Azure tiene una
  sola fila *Cuenta*; un token SAS de un solo contenedor o recurso conecta
  (necesita el permiso List). WebDAV espera hasta 10 minutos el trabajo del
  servidor tras PUT, MOVE, COPY o DELETE (un Nextcloud que ensambla una
  subida grande); con inicio de sesión en dos pasos usa una contraseña de
  aplicación. Al subir, borrar, renombrar o crear una carpeta, WebDAV
  sigue un redirect solo a la misma dirección (una barra final, http a
  https); cualquier otro - una página de login, otro host - es un error
  que nombra adónde apuntaba, y allí no se hace nada. Usuario y contraseña
  van en UTF-8, así funcionan contraseñas con €, diéresis o letras
  cirílicas. Borrar o renombrar un blob de Azure con snapshots borra
  también sus snapshots. NFS sin root ni sudo sin contraseña: pon un nombre de máquina
  o UID en el perfil para usar el cliente integrado, que no monta nada; un
  montaje del kernel cuyo servidor ya no está se muestra desconectado tras
  unos 10 s. Contraseñas incorrectas, buckets o contenedores que faltan y
  puertos cerrados se nombran como tales, y un teléfono desenchufado, un
  servidor NFS o una sesión iSCSI que desaparece se notan, así que
  Reconectar abre una sesión nueva.

- **Teléfonos Android (ADB).** Dos modos en el perfil. *TCP / Wi-Fi*:
  conecta el teléfono por USB una vez, activa la depuración USB, ejecuta
  `adb tcpip 5555` y usa la IP del teléfono y el puerto 5555 (se puede usar
  un proxy SOCKS o HTTP). *USB / servidor adb*: el teléfono en el cable. La lista Dispositivo
  (Actualizar la vuelve a leer) muestra los teléfonos conectados ahora con
  su estado - listo, aún no permitido (acepta la pregunta en el teléfono),
  offline, sin permiso; elegir uno rellena su número de serie (como lo
  muestra `adb devices`), vacío es el único teléfono en USB. Si el servidor
  adb de las platform tools corre en 127.0.0.1:5037 (`adb start-server`,
  Android Studio o cualquier orden `adb` lo arranca), axross llega al
  teléfono a través de él y lo comparte con el `adb` de la consola - también
  se pueden elegir teléfonos que el servidor tiene por Wi-Fi
  (`adb connect`); sin servidor axross abre el teléfono por USB él mismo.
  El modo TCP hacia localhost:5037 usa también el servidor. axross solo usa
  un servidor adb en este ordenador: un `ADB_SERVER_SOCKET` con otro equipo
  se ignora. No hay login: axross usa la clave de la
  herramienta adb `~/.android/adbkey` y la crea si falta; el teléfono no
  conoce ningún nombre de usuario ni de equipo. En la primera conexión el
  teléfono pregunta "¿Permitir depuración USB?" - desbloquéalo y acepta en
  un minuto (axross muestra "Check the phone" mientras espera) y marca
  "Permitir siempre desde este ordenador"; sin eso cada conexión nueva
  vuelve a preguntar, y una transferencia comparte entonces la única
  conexión, así que navegar espera por ella. La *depuración inalámbrica*
  de Android 11 (código de emparejamiento, puerto aleatorio, TLS) no está
  soportada - usa `adb tcpip 5555`. USB en Linux necesita libusb-1.0 del
  sistema (`pip install 'axross[adb]'` trae la parte de Python); se nombra un programa que no es un servidor adb y retiene el teléfono, y
  sin permiso sobre el dispositivo añade una regla udev para dispositivos
  Android, tu usuario al grupo `plugdev` y vuelve a conectar el teléfono.
  Tras una conexión caída la siguiente acción se reconecta sola; las
  acciones largas en el teléfono (una suma de comprobación, copiar o mover
  allí, borrar una carpeta grande, instalar un APK) se esperan hasta una
  hora; los archivos subidos reciben `rw-r--r--`, conservan la fecha de
  modificación del origen y van primero a un nombre temporal junto al
  archivo, que lo sustituye al completarse - una subida rota deja el
  archivo antiguo como estaba.

- **La ventana Dispositivo Android.** En un panel ADB, clic derecho > Más
  > *Dispositivo Android…* (o *Pane > Dispositivo Android…* en la barra de
  menús) abre una ventana del propio teléfono, una por conexión. *Info*:
  fabricante, modelo, versión de Android, parche de seguridad, número de
  serie, el IMEI donde el teléfono se lo da al shell, batería y
  almacenamiento libre; *Reiniciar…* en Android, recovery o el bootloader.
  *Apps*: las apps instaladas, filtradas por nombre y tipo; *Detalles…*
  muestra la versión, las fechas de instalación y los permisos de una app
  (*Conceder…*, *Revocar…*); *Iniciar*, *Detener*, *Desinstalar…*,
  *Instalar APK…* y *Copiar APK…* (los ficheros APK en una carpeta, con
  nombres nuevos). *SMS*: los mensajes de una carpeta, donde Android deja
  leerlos al shell; *Escribir en el almacén…* guarda un mensaje sin
  enviarlo, *Preparar SMS…* abre la app de SMS del teléfono con número y
  texto - axross nunca envía, una persona en el teléfono pulsa Enviar.
  *Logcat*: las líneas más recientes por prioridad, tag o app, *Seguir* las
  lee cada dos segundos, *Pausa* detiene la vista, *Guardar…* las escribe
  en un fichero. *Captura*: la pantalla, *Guardar…* como PNG. Cada cambio
  pregunta antes; Desinstalar y Reiniciar cuentan tres segundos (Esc los
  detiene), y en un perfil marcado como producción cada cambio pasa por la
  cuenta atrás de producción. En el security mode paranoid los cambios
  están desactivados. El teléfono se consulta en segundo plano: uno lento
  nunca bloquea la ventana. Las mismas herramientas son el grupo `adb` del
  servidor MCP (docs/MCP_es.md, §9.10). La interfaz está en inglés o
  alemán; los nombres de arriba traducen los de la versión inglesa.

## Layout multi-panel

- Añade panels dividiendo con **Ctrl+Shift+H** /
  **Ctrl+Shift+V**, cierra con **Ctrl+W**; el teclado se queda en la lista
  de ficheros (tras cerrar, en la del panel activo). **Retroceso**, el
  botón Up y `..` abren la carpeta padre con la carpeta recién dejada
  seleccionada, así Return vuelve a entrar.
- El panel activo lleva borde azul; el panel **destino** (donde
  aterrizan las copias) lleva borde verde. El último panel
  enfocado se vuelve destino.
- Un panel se vuelve activo cuando el ratón descansa en él 0,5 s.
  **Edit → Settings… → General → Activate a pane** fija 0,5, 1, 2 o 3 s, u
  **When clicked**. El foco del
  teclado solo sigue desde la lista de archivos de otro panel, nunca
  desde un campo de texto.
- **Alt+Izq / Alt+Der** recorren la historia de panels;
  **Tab** / **Shift+Tab** en una lista de archivos ciclan los panels.
- **Ctrl+F6** / **Ctrl+Shift+F6** (View → Focus Next Area / Focus
  Previous Area) llevan el foco del teclado al área siguiente / anterior
  de la ventana: los panels, Transfers y cada otro panel a la vista. Tab
  nunca se detiene en un panel oculto detrás de otra pestaña.
- Drag-and-drop entre panels inicia una transferencia (funciona
  para local↔remoto, remoto↔remoto, cross-protocolo). **Ctrl+X** /
  **Ctrl+V** hacen cut y paste entre dos carpetas cualesquiera (ver
  Transferencias).
- **Nombres.** Un nombre que ninguna carpeta puede contener y que lista
  un servidor SFTP, SCP o SVN (`../x`, `a/b`) es una fila inutilizable -
  se muestra, nunca se actúa sobre ella y una copia de carpeta la lista
  como no utilizable. *Rename*, *New Folder*, *New File…* y *Batch
  Rename…* aceptan una barra invertida en un nombre local en
  Linux/macOS, como las copias.
- **Compare Panes** (*View → Compare Panes…*): *Delete…* elimina solo
  entradas que se sabe que existen en un solo lado; una fila cuyo otro
  lado no se pudo leer se deja intacta.

### Workspaces — varios layouts, en varias pantallas

Un workspace es un layout de paneles propio y con nombre. **Workspace →
New Workspace → With File List** (**Ctrl+Alt+N**) abre uno con un panel
local, **With Terminal** (**Ctrl+Alt+Shift+N**) uno con una shell local; a
partir del segundo, los workspaces aparecen como tabs sobre los paneles.
**Ctrl+Alt+PgDown / PgUp** los cambian, y cada uno conserva su propio
panel de origen y de destino.

- **Varias shells:** **Workspace → Add Terminal Pane** (también en el
  menú del clic derecho del tab) pone otra shell local en el workspace,
  junto a los paneles que ya están. Un pane de terminal fijado
  (**Ctrl+Shift+P**) recibe cada tecla pulsada en su ventana, tenga quien
  tenga el foco; los diálogos, los menús y la barra de búsqueda del propio
  terminal conservan sus teclas.
- **Renombrar:** doble clic en el tab, su menú del clic derecho, o
  **Workspace → Rename Workspace…**.
- **Detach to Window** (menú Workspace o clic derecho en el tab) pone el
  workspace en una ventana propia — por ejemplo en otra pantalla. Al
  cerrar esa ventana, el workspace vuelve como tab.
- **Enviar un panel a otro workspace:** clic derecho en el panel →
  **Send to Workspace** - en la lista de un panel de archivos (sobre un
  archivo o sobre el área vacía, al final de *More ▸*), en la cabecera de un
  panel o en un terminal - y elige un workspace o **New Workspace**. Los
  workspaces van numerados como están sus tabs (**1: Workspace 1**,
  **2: Logs**; uno separado lleva *(window)*), y del 1 al 9 la cifra
  elige la entrada mientras el menú está abierto. **Workspace → Send Pane
  to Workspace** hace lo mismo con el panel activo; o arrastra la
  cabecera del panel sobre un panel de otro workspace o ventana. Los
  paneles de archivos y los de terminal se arrastran igual (un panel de
  terminal también con su botón ⇄); un workspace cuyo último panel se va
  se cierra; si mantienes un panel arrastrado medio
  segundo sobre un tab de workspace, ese tab se abre, así un panel
  llega también a un workspace en segundo plano.
- **Paneles de extensiones** (Media Player, Drives Overview, Markdown
  Preview, …) están en todos los workspaces hasta que pones uno en un
  workspace: el botón ⇄ de su barra de título (o un clic derecho en
  ella, *Send to Workspace*) ofrece cada workspace (el suyo marcado),
  **New Workspace** y **All Workspaces**, y
  **Workspace → Add Extension Panel** (también en el menú del clic
  derecho del tab) lleva un panel a un workspace - también el dock
  **Agent**, que allí es un panel más como los de extensiones
  (**Ctrl+Shift+K** trae su workspace al frente). Allí es un panel más:
  solo aparece con su workspace, se va con él cuando se separa en una
  ventana, se arrastra por su barra de título sobre otro panel y acepta
  paneles arrastrados, cambia de tamaño con el splitter y **Equalize
  Pane Sizes** lo iguala. Su [x] lo saca del workspace; mostrado de nuevo
  desde el menú **Extensions**, vuelve a su sitio. Al cerrar el
  workspace, sus paneles se aparcan en All Workspaces (ocultos, con su
  estado); al apagar la extensión sus paneles salen y al encenderla
  vuelven.
- **Show Only on Workspace** deja un dock como dock pero lo ata a un
  workspace - cualquier dock: Agent, Log, Transfers, Terminal, Console,
  Scripts, Bookmarks y Analysis, y también los paneles de extensión del
  área de docks (Media Player, Bluetooth …). La chincheta de su barra de
  título (o un clic derecho en ella) ofrece **All Workspaces**, cada
  workspace y **New Workspace**; la chincheta se ilumina mientras el dock
  está atado y su tooltip nombra el workspace. Un dock atado conserva su
  sitio pero solo aparece mientras su workspace está en la ventana (uno
  separado: mientras es el actual); abrirlo en otro workspace (View →
  Panels, su botón de la barra) trae su workspace al frente. Cerrado en
  su workspace sigue cerrado; al cerrar el workspace vuelve a estar en
  todos. La atadura vuelve en el siguiente inicio.
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
  layout de los docks (cuáles están abiertos y dónde, y qué tabs hizo
  axross por sí mismo) y el theme;
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
layout por defecto; el motivo queda en el log. Un `session.json` que se
lee pero no se puede restaurar se guarda como
`session.json.unrestorable-<hora>-<id>` a su lado antes de que el layout
por defecto lo reemplace; uno que no se puede leer en absoluto (no es JSON,
no es UTF-8) se aparta como `session.json.unreadable-<hora>-<id>`, y uno de
más de 1 MB no se vuelve a escribir. Un layout de más de 256 entradas
vuelve hasta donde cabe: los primeros workspaces, en orden.
Las preferencias guardadas en un axross se conservan cuando otro se cierra,
y un terminal de un perfil que ya no existe vuelve como un marcador que lo
dice, nunca como shell local. **File > Restore Last
Session** (**Ctrl+Shift+R**) sigue reconstruyendo el layout guardado
a petición, y ahí los panels remotos sí conectan.

### Docks: la columna derecha y los tabs automáticos

- La columna de docks de la derecha (Analysis, Agent, conversaciones
  separadas, extension panels como el Media Player) llega hasta el
  borde inferior de la ventana; el área inferior (Transfers, Terminal,
  Log, Console, Scripts) es tan ancha como los panels y la columna de
  Bookmarks. La columna de Bookmarks termina encima del área inferior,
  así sus tablas y líneas de terminal siguen anchas.
- Cuando los docks de una columna necesitan más altura de la que tiene
  la columna - cada uno una parte útil de su contenido (200 px, o todo
  si necesita menos), no solo su barra de título -, los docks vecinos
  se juntan en tabs hasta que caben; los tabs quedan abajo del grupo.
  Nada se superpone, tampoco cuando un window manager mantiene la
  ventana más pequeña (tiling, maximizada).
- Cuando vuelve a haber sitio (ventana más grande, un dock cerrado,
  flotante o movido a otro lugar), los docks que axross juntó en tabs
  vuelven a apilarse donde estaban. Los docks que juntaste tú siguen en
  tabs, y un dock que sacas de un grupo automático no se vuelve a
  juntar por eso - solo si la columna no pudiera ni siquiera con las
  barras de título de los docks.
- Mientras un botón del ratón está pulsado (se arrastra un separador o
  un dock) nada se mueve; la comprobación llega cuando el resize se ha
  calmado. Los panels colocados en un workspace son panes allí y no
  forman parte de ninguna columna.
- Qué tabs hizo axross se guarda en `session.json` con el layout de los
  docks, así que tras reiniciar se separan otra vez cuando hay sitio.

## Transferencias

Antes de encolar una copia o un move (F5, F6, arrastrar y soltar), axross
comprueba el destino en segundo plano y pregunta por cada nombre que ya
existe allí: Overwrite, Overwrite if Newer, Skip, Rename
(`name (1).ext`), cada una opcionalmente para todos los conflictos
restantes, o Cancel (no se copia nada). Las carpetas se combinan; se
pregunta por los nombres de dentro. En un destino que no distingue
mayúsculas de minúsculas en los nombres (SMB, Windows, macOS, un disco
FAT o exFAT) también se pregunta por un nombre que solo se diferencia en
eso. Un move omitido conserva su origen, y un fichero que aparece en el
destino después de la pregunta hace fallar su job en vez de
sobrescribirse.

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
rechazado o un panel cerrado. Salir mientras hay transferencias en
curso o en espera pregunta antes (salir las cancela); una carpeta que no
se puede leer al recorrerla es una fila fallida de la lista, y un
recorrido que se detiene a medias dice cuánto se encoló. Una copia o un
move sobre un enlace duro de su origen no hace nada y lo dice; los dos
nombres quedan. Un move conserva un origen local en el que se escribió o
que se reemplazó mientras se copiaba, aunque tenga el mismo tamaño.

- **Semántica atómica.** Cada escritura va a un fichero temporal
  hermano oculto (`.<nombre>.part-<job>-<fingerprint>`) y se renombra
  en su sitio al final. En
  S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync el
  upload subyacente ya es atómico; en el resto el rename es el
  punto de commit.
- **Resume.** Las transferencias fallidas pueden reanudarse; los
  bytes parciales en el destino se retoman donde quedaron. Una
  transferencia que falla porque el destino está lleno borra su
  fichero parcial. Antes de continuar un parcial se comparan con el
  origen sus primeros y últimos 64 KiB y ventanas repartidas por él (una
  cada 256 MiB, al menos una). En el disco local el parcial solo se
  continúa mientras sea un fichero normal tuyo con un solo nombre (nunca a través
  de un enlace que otro haya puesto en su lugar en una carpeta
  compartida), y cada fichero temporal se escribe por el descriptor con
  que se abrió, creado con el modo del origen (una clave 0600 nunca es
  legible por otros, ni un instante) - también por SFTP, SCP y en un
  montaje NFS, donde el fichero temporal se crea con ese modo.
- **Retry.** "Retry Failed" reintenta cada transferencia en estado
  de error, cada una una sola vez.
- **Cancel All** detiene también una copia o un move cuyo recorrido
  de carpetas sigue en marcha: ninguno de sus ficheros entra en cola.
- **Mientras se ejecuta.** Una copia de carpetas primero lee las
  carpetas y las crea en el destino, luego pone en cola cada fichero y
  después los copia: las carpetas pueden aparecer mucho antes que sus
  ficheros. La barra de estado lo dice hasta que la copia termina,
  también con el dock Transfers cerrado: "Preparing: 3,210 files
  queued…", luego "Copying 1,210 of 10,000 files – 12 %"; un clic en
  ella abre el dock Transfers. La línea de estado del panel de destino
  muestra "Copy in progress: 1,210 of 10,000" con una barra fina, y la
  barra general del dock "12 % – 1,210 of 10,000 files".
- **Muchos ficheros pequeños.** Hacia y desde SFTP los ficheros pequeños
  de una carpeta van por lotes (hasta 64 ficheros de 64 KiB como mucho,
  sus peticiones en vuelo a la vez): cada fichero se sigue escribiendo en
  su propio fichero temporal oculto, se comprueba su tamaño, se mira el
  destino justo antes del rename (una respuesta como "no reemplazar" vale
  también para un fichero que apareció entretanto), se renombra a su
  sitio y se anota en el diario por separado; si uno falla, falla solo.
  axross confirma enseguida lo que envía el servidor (TCP_QUICKACK en
  Linux), así que un servidor que retiene su segunda respuesta hasta esa
  confirmación (Nagle) no espera 40 ms por ella. Una carpeta de 10 000
  ficheros de unos pocos bytes se copia en segundos, no en minutos,
  también de un servidor SFTP a otro. La comprobación de integridad de
  un lote calcula el hash de todos sus ficheros con un solo `sha256sum` en
  el servidor (cada nombre entrecomillado, los lotes largos divididos), no
  con una orden por fichero; un fichero cuya línea en la respuesta no es
  clara se comprueba por separado.
- **Enlaces dentro de una carpeta.** Un enlace simbólico dentro de una
  carpeta copiada se copia como enlace, con el mismo destino: a un
  fichero, a una carpeta o a nada, dentro de la carpeta copiada o fuera
  de ella. Aquello a lo que apunta no se lee ni se sigue, y un move
  mueve el enlace. Donde un lado no admite enlaces simbólicos (S3 y
  otros almacenes de objetos, FTP, WebDAV, un servidor SFTP que no lee
  enlaces) el enlace se omite con una nota en el dock Transfers
  ("skipped: symbolic link not copied …"); la copia sigue. Un enlace que
  seleccionas solo se copia como antes: un enlace a un fichero como ese
  fichero; un enlace a una carpeta se rechaza con un motivo.
- **Moves dentro de un servidor.** Un move cuyo origen y destino están
  en la misma conexión (soltar sobre una carpeta del mismo panel, F6
  entre dos paneles de una conexión, Cut y Paste) renombra cada fichero
  en el servidor (SFTP RENAME, FTP RNFR/RNTO, WebDAV MOVE, SMB, copia S3
  en el servidor): ningún byte pasa por axross. Un nombre que las
  respuestas al conflicto permiten sobrescribir, un enlace o un rename
  que el servidor rechaza va por la copia normal.
- **Fechas de modificación.** Una copia conserva la fecha de
  modificación del origen en discos locales, SFTP (segundos enteros),
  SMB y servidores FTP que anuncian `MFMT`. WebDAV y S3 no pueden
  fijarla: la copia allí lleva la hora de subida, que Compare Panes y
  *Overwrite if Newer* leen como la más nueva. *Overwrite if Newer*
  compara segundos enteros.
- **Qué pasó.** Cuando una copia o un move termina, la barra de estado
  lo resume: "2 copied, 1 skipped (destination kept)", "3 skipped
  (destinations not older)", con los fallos contados. La barra total
  del dock termina en *Done* solo cuando todos los jobs de la tanda
  acabaron bien; si no, en rojo con "N failed" / "N cancelled".
- **Undo.** *Edit → Undo Last Operation* (`Ctrl+Z`) deshace el move o
  Move to Trash más reciente cuya conexión está abierta, entero: un F5 /
  F6 / soltar / Paste, o un Move to Trash de una selección, es una
  operación y una pregunta. Una carpeta movida vuelve con sus carpetas
  (las que el move creó se quitan si están vacías, las de origen se
  crean de nuevo) y con sus etiquetas; un nombre que vuelve a existir
  detiene el undo antes de que nada se mueva, y lo que no pudo volver
  queda para el siguiente `Ctrl+Z`. Una copia no se puede deshacer.
- **Conexiones de producción.** Toda escritura que sobrescribe o borra
  en una conexión marcada *production* espera primero su cuenta atrás:
  F5 / F6 / arrastrar y soltar / Paste con sobrescritura, un move desde
  o hacia ella, y Compare Panes → *Sync* por cada lado que el sync
  sobrescribe.
- **Verify.** El flag `verify_checksum` por job re-hashea el
  destino tras el upload y rechaza en caso de mismatch.
- **Parallel transfers.** *Edit → Settings… → Files & Panes →
  Parallel transfers* (1–8, 1 por defecto) deja correr varios jobs a
  la vez, iniciados en el orden de la cola; así se ocultan los round
  trips de muchos ficheros pequeños en un enlace lento. Una conexión
  que no puede llevar dos jobs a la vez (SCP y cualquier otro
  protocolo salvo ficheros locales, workspaces en RAM, SFTP, SMB, FTP,
  WebDAV y S3) sigue con sus jobs de uno en uno, y dos jobs nunca
  escriben el mismo destino a la vez. Un cambio vale para los jobs que
  empiezan después. Cada job SFTP usa un channel SSH propio, y los
  servidores limitan los channels por conexión (OpenSSH `MaxSessions`,
  10 por defecto). Cada transfer FTP usa una control connection propia;
  los servidores suelen limitar las conexiones por usuario o dirección,
  y una conexión FTP cuyo servidor rechaza un segundo login sigue con
  sus jobs de uno en uno.

## Capa de funcionalidades del filesystem

Estas primitivas funcionan en **cualquier** backend, incluso aquellos
cuyo protocolo nativo no las soporta.

| Módulo | Qué proporciona |
|---|---|
| `core.atomic_io` | `atomic_write(backend, path, data)` — atómico-nativo en S3 / Azure / Dropbox / GDrive / OneDrive / IMAP / Rsync; tmp-then-rename en el resto. Un fichero guardado por SFTP conserva su propietario y su grupo; el fichero temporal los recibe antes del primer byte (un fichero local, su grupo). |
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
| `core.archive` | Extracción segura de zip / tar / 7z (`.zip .xpi .jar .war .apk .epub .docx .xlsx .odt .tar .tar.gz .tgz .tar.bz2 .tbz2 .tar.xz .txz .7z`). Guards contra zip-slip / bomba / metadata mentirosa; las entradas symlink y hardlink (tar, y symlinks de ZIP) se omiten - nunca se crean ni se siguen - y el resultado las nombra; `.7z` requiere el extra `[archive]`. Un archivo cuyos nombres de miembros llevan caracteres de control o cambios de dirección (un nombre que se vería como `invoiceexe.jpg` aunque termina en `.exe`) se rechaza. Un 7z cifrado y los miembros ZIP cifrados con ZipCrypto se abren con su contraseña: el panel y la vista del archivo la piden y la guardan en memoria solo mientras el archivo está abierto; una incorrecta se indica y se vuelve a pedir; un miembro ZIP cifrado con AES se nombra - ábrelo con 7-Zip. Los nombres ZIP guardados sin el flag UTF-8 se leen como los leen unzip y 7-Zip: UTF-8 si es válido, si no la página de códigos detectada en todos los nombres, si no cp437. Un 7z cuyas carpetas están guardadas como solo lectura o cerradas (0000) se extrae entero; uno con más miembros que el límite se rechaza antes de listarlo. *Cancel* detiene un 7z, un RAR o un único fichero comprimido también mientras se escriben sus datos. Con una contraseña dada, un 7z que no necesita ninguna o que está dañado antes de su parte cifrada lo dice en lugar de "wrong password". Una entrada de carpeta ZIP que termina en barra invertida es una carpeta; un tar que contiene un fichero más de una vez extrae la última copia, como hace tar. Los nombres que Windows no permite (CON, NUL, COM1.txt, a:b, un punto o un espacio al final) se rechazan en Windows y cuando el destino está en un recurso compartido de Windows o en un disco NTFS o FAT. |
| `core.packer` | Clic derecho → **Pack**: zip, tar.gz / .zst / .xz / .bz2, 7z (opcionalmente AES-256 con nombres de fichero cifrados) o un fichero como .gz / .zst / .xz / .bz2 — desde cualquier backend, sin sobrescribir nunca (`name (2).zip`) y sin dejar nunca un archivo a medio escribir. Mientras se escribe, el archivo es un fichero oculto `.tmp-….tmp` en la carpeta; el que deja un pack interrumpido lo quita la limpieza de la carpeta cuando tiene una hora. El archivo recibe el modo habitual de un fichero nuevo (0666 menos la umask); si contiene un fichero o una carpeta que el grupo u otros no pueden leer, también se les cierra a ellos. Un nombre dentro de una carpeta empaquetada que no puede ser miembro de un archivo (el `../x` de un servidor) se omite y se cuenta. Un origen local se lee tal como se listó: si entretanto se reemplazó por un enlace o por otro fichero, el pack falla. Un pack admite como mucho 200 000 ficheros y carpetas juntos. Un 7z conserva los permisos de un fichero sin setuid, setgid ni sticky, como ZIP y tar. |
| `core.elevated_io` | Lectura local con privilegios vía `pkexec` — axross nunca mantiene el privilegio. Entrada "Open as root…" en el menú contextual. |
| `core.fuse_mount` | Montaje FUSE de cualquier FileBackend. Solo lectura por defecto; `writeable=True` habilita create / write / unlink / mkdir / rename. Los ficheros y las carpetas muestran los permisos que informa la conexión (sin setuid ni setgid; sin bits de escritura en un montaje de solo lectura). En un montaje de lectura y escritura un fichero nuevo tiene desde su primer byte el modo con que se creó, y chmod funciona. Extra opcional `[fuse]`. |
| `core.mcp_server` | Servidor MCP JSON-RPC con framing stdio que expone el backend configurado como herramientas. `--mcp-write` añade herramientas mutadoras, capadas a un root a prueba de path-traversal. |

## Acciones del menú contextual

El menú contextual es una sola columna; **F10**, **Shift+F10** y la tecla de menú lo abren desde el teclado, en la fila actual. **Open** va primero (una carpeta se abre en el pane, un archivo en su visor, como con `Enter`), luego *Open With ▸* (como texto, hex, root, View Selected Media…, Preview Archive) y, para un archivo comprimido, *Extract…*; luego *Copy* (`Ctrl+C`), *Cut*, *Paste*, *Rename*; *Copy to Target Pane*, *Move to Target Pane*, *Pack ▸*; *Move to Trash* (`Del`) y *Delete Permanently* (`Shift+Del`); *New Folder*, *New File…*; *Properties…*, *Analyse ▸* (tipo de archivo, imagen de disco, checksum, versiones, tamaño, sift, Duplicate Finder, Find in This Folder) y *More ▸*: *Refresh*, modo de vista, View Media…, bookmark, Show Trash…, *Copy Path*, *Links ▸* (destino del enlace, nuevo symlink / hardlink / XLink), *Metadata ▸*, *Tags ▸*, terminales, FUSE, Permissions…, cifrar / descifrar, el agente y, al final, *Send to Workspace ▸* para el propio pane. El nivel superior sigue siendo una sola columna incluso en una pantalla de 1024x600. Más de tres entradas de extensiones van a *Extensions ▸*. La tabla nombra cada entrada por su etiqueta.

| Acción | Trigger | Qué hace |
|---|---|---|
| Disk Image… | Clic derecho (un fichero `.img .raw .dd .iso .qcow2 .vdi .vmdk .vhd(x) .e01 …`) | El contenedor (qcow2, VDI, VMDK, VHD/VHDX, E01), la tabla de particiones (MBR con particiones lógicas, GPT) y el filesystem y la etiqueta de cada volumen, leídos en Python puro a través de cualquier backend. Una imagen local monta un volumen mediante un loop device sobre exactamente sus bytes: primero `udisksctl` sin preguntar (donde polkit lo permite), luego `sudo`, luego `pkexec` y por último `udisksctl` dejando preguntar a polkit. La contraseña de sudo se pide una vez y se guarda en memoria mientras axross está abierto (nunca en disco, nunca en una línea de comandos); *Remember the sudo password* (*Edit → Settings… → Security*) lo desactiva y vuelve al orden `udisksctl` (polkit pregunta), `pkexec`, `sudo` preguntando cada vez. El Paranoid Security Mode nunca la recuerda. sudo, pkexec y udisksctl se ejecutan solo desde carpetas del sistema propiedad de root, nunca desde `$PATH`. **Read-only** salvo que *Allow writing* esté marcado y confirmado. La carpeta montada se abre en un panel nuevo; *Unmount* libera el loop device. Los montajes hechos por axross se recuerdan entre reinicios (`~/.config/axross/mounts.json`; solo vuelven los que siguen montados). *Identify File Type…* reconoce imágenes de disco también por su contenido (GPT, MBR, discos virtuales) y ofrece *Disk Image…* para esa fila, se llame como se llame. qcow2 / VDI dinámico / VMDK hay que convertirlos antes (`qemu-img convert -O raw`); un VDI fijo se monta directamente. |
| Tags ▸ | Clic derecho sobre una selección | Marca un tag de color (Important y Review later existen; New Tag… añade uno) en cada fichero seleccionado de cualquier backend; puntos en la columna Name, los tags en su tooltip; `tag:<nombre>` en el campo de filtro muestra solo esos ficheros; *View > Tagged Files…* lista los ficheros de cada tag; *Go to File* muestra el fichero seleccionado en un panel (una conexión cerrada se abre como un bookmark, en la carpeta del fichero). Guardado en `~/.config/axross/tags.json`. |
| New Folder | Click derecho | `backend.mkdir(path)` en cada backend con escritura. |
| New File… | Click derecho | Fichero de cero bytes vía `backend.open_write(path).write(b"")`; nunca sustituye un fichero de ese nombre (tampoco uno guardado entretanto). |
| New Symlink… | Click derecho | Dos prompts. Visible solo en backends con `supports_symlinks=True`. |
| New Hardlink… | Click derecho | Misma forma; cross-device → `OSError(EXDEV)`. |
| Find in Index | `Ctrl+Shift+F` | Búsqueda en el índice offline de metadata. |
| Find in This Folder… | Clic derecho (también en espacio vacío) | Find Files con esta carpeta (o la seleccionada) marcada — ver *Find Files*. |
| Calculate Size (N folders) | Clic derecho sobre carpetas | Tamaño total, número de ficheros y carpetas de cada carpeta elegida, recorridos en segundo plano a través de la conexión (*Cancel* en la línea de estado); la tabla de resultados ordena y los tamaños aparecen en la columna Size del panel hasta que la carpeta se recarga. **Los ficheros ocultos cuentan**: dotfiles, carpetas ocultas y entradas que el backend marca como ocultas se suman como cualquier otra — igual que `du` —, las muestre el panel o no. Un enlace cuenta con su propio tamaño y nunca se sigue; una carpeta que no se puede leer se nombra en el resultado y se salta, y una entrada cuyo tamaño no se puede leer hace del total un límite inferior (la nota dice cuántas). |
| Identify Files in This Folder… | Clic derecho (también en espacio libre); el botón de la ventana *Identify File Type* | Cada fichero directamente en la carpeta (una carpeta elegida, si no la mostrada; las subcarpetas se cuentan, no se recorren; ficheros ocultos incluidos) identificado por su contenido como en *Identify File Type…*, en segundo plano y a través de la conexión, así que también en paneles remotos. Acotado: como mucho 2000 ficheros, 64 KiB por fichero, 15 s de timeout por lectura, *Cancel*; no se pregunta a `file(1)`. Las columnas ordenan: nombre, tipo detectado, MIME type, el veredicto *mismatch*, tamaño, una nota — en una imagen de disco su contenedor, tabla de particiones y número de particiones (`Raw disk image, MBR, 2 partitions, 4.0 MiB`; como mucho 4 MiB leídos para ello) — y, para ficheros locales con el extra `sift` instalado, el tipo según sift. Una fila abre *Disk Image…* (imágenes de disco) o *Properties…*; un doble clic elige lo que corresponda. |
| Analyse with sift / Analyse Folder with sift | Clic derecho (la entrada de carpeta también en espacio libre), el menú Actions, *Tools → Analyse with sift* | Abre el dock *Analysis (sift)* (el icono del tamiz de sift, `Ctrl+Shift+I`) y explica el fichero allí sin modelo. Varios ficheros seleccionados, o una carpeta (la seleccionada, si no la mostrada), se ofrecen como un batch para el perfil LLM activo; *Tools → Analyse with sift* toma la selección, o la carpeta mostrada si no hay selección. El resumen de directorio propio de sift (`sift --dir-summary`, desde sift 0.1.96) no forma parte del dock: una carpeta se analiza fichero por fichero. Sin sift (axross-slim, o una instalación desde el código sin el extra `sift`) cada entrada dice que sift viene con axross-full o con el extra `axross[sift]` y enlaza *Help → Features…*. |
| Identify File Type… | Clic derecho (selección) | Una fila por entrada: el tipo real según el contenido (magic bytes vía la base MIME de Qt, puremagic, una tabla de firmas propia), el tipo MIME, lo que afirma la extensión y un *mismatch* resaltado cuando no coinciden, tamaño y, para texto, codificación y finales de línea. Lee como mucho 64 KiB por fichero a través del backend, fuera del hilo de la GUI, con 15 s de timeout por fichero — un remoto muerto da una fila «timed out». Los ficheros locales muestran también la descripción de `file(1)` si está instalado. Scripting: `axross.file_type(b, path)`. |
| Open Terminal Here | Clic derecho (también en espacio vacío) | Abre una shell en el dock de terminal en la carpeta: una carpeta seleccionada, si no la que se muestra. Los paneles locales obtienen una shell local que arranca en esa carpeta; los paneles SFTP / SCP una shell en la misma conexión SSH seguida de `cd -- '<carpeta>'` (entrecomillado con `shlex.quote`). Desactivado, con el motivo como tooltip, en protocolos sin shell. |
| Open External Terminal Here | Clic derecho (paneles locales) | Lanza `$TERMINAL`, si no el primero instalado de x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, alacritty, kitty, foot, wezterm, xterm — con la carpeta como directorio de trabajo, desacoplado, sin shell de por medio. |
| Duplicate Finder | Menú View, `Ctrl+Shift+D` | Agrupa los archivos indexados por hash de contenido y mueve las copias sobrantes a la papelera — ver *Duplicate Finder* en *Herramientas*. |
| View Media… / View Selected Media… | Click derecho, menú View | Imágenes, PDFs y vídeos de la carpeta (opcionalmente recursivo) o de la selección como grid overview, visor para ir pasando o slideshow — ver *Editores y visores*. |
| Show / Remove / Export Metadata… | Click derecho | EXIF / GPS / XMP / IPTC, propiedades de Office, info de PDF, tags de audio / vídeo de la selección — o de toda la carpeta si no hay nada seleccionado (subcarpetas opcionales) — ver *Metadata de ficheros*. |
| Copy / Cut / Paste | Click derecho (Paste también en el espacio vacío), `Ctrl+C` / `Ctrl+X` / `Ctrl+V` | Copy recuerda la selección para Paste y pone sus rutas como texto en el portapapeles para otros programas; Cut recuerda la selección y no elimina nada (las entradas se atenúan); Paste en cualquier panel copia las entradas copiadas, o mueve las cortadas, a su carpeta por la cola de transferencias - ver *Transferencias*. Un cut que nunca se pega lo deja todo en su sitio. *More ▸ Copy Path* pone solo las rutas en el portapapeles. |
| Move to Trash | Click derecho, `Del` | Papelera universal (una carpeta `.axross-trash` en el home de la conexión: funciona donde la conexión puede renombrar; los protocolos de solo lectura y los que no renombran - Gopher, LDAP, NNTP, PJL, POP3, SLP, SVN, TFTP, WMI - no tienen, y ahí `Del` pregunta por un borrado definitivo). Funciona como Delete Permanently: en segundo plano, con la misma segunda pregunta para las entradas ocultas. Un fichero en un disco RAM (`/run/user`, `/dev/shm`) no se mueve a un trash en otro disco; bórralo para siempre. En el disco de esta máquina y por SFTP el trash es una carpeta que solo tú puedes abrir (0700); en S3, SMB, WebDAV, FTP y los backends cloud es la carpeta `.axross-trash` arriba del recurso compartido, donde lo que se mueve tiene los permisos de esa carpeta - Move to Trash, Remove Metadata y el Duplicate Finder lo dicen antes de poner nada allí, y ofrecen *Delete Permanently* o copias limpias. |
| Delete Permanently | Click derecho, `Shift+Del` | Primero cuenta fuera del hilo de la GUI lo que se borrará (carpetas, archivos, tamaño, entradas ocultas) y luego pregunta - con **No** como botón por defecto, así que `Enter` conserva los archivos. Una carpeta seleccionada con entradas ocultas (dotfiles o el flag hidden del backend) - o una que la comprobación no pudo leer entera - necesita un segundo OK cuyo default es No. El borrado corre en segundo plano: la línea de estado muestra el progreso, Cancel para en la entrada siguiente - también dentro de una carpeta que se borra en local, por SMB, SFTP o FTP, y la línea de estado dice cuánto de esa carpeta ya se borró (lo borrado queda borrado; un servidor que borra una carpeta entera con un request, como WebDAV o S3, termina esa carpeta) - los fallos se listan por entrada y la carpeta se recarga al final. Una ruta que ya se está borrando se rechaza, también desde el otro pane. |
| Show Trash… | Click derecho | Diálogo restaurar / borrar permanentemente. |
| Show Versions… | Click derecho | Snapshot browser — Save Version As, Restore as Current. |
| Show Checksum… | Click derecho | Checksum nativo (S3 ETag, Drive md5, ssh sha256sum…) con fallback a stream-hash; un fichero local se calcula con progreso y *Cancel*, y si el checksum del servidor falla se ofrece SHA-256 leyendo el fichero. |
| Extract… | Click derecho sobre archivo soportado | Carpeta hermana del mismo nombre, cancelable, con los guards de `core.archive`. Solo backends locales. |
| Abrir un miembro | `Enter` / doble clic en la vista del archivo | Un miembro cuyo contenido es un fichero Office / OpenDocument, PDF, e-book, imagen, sonido o vídeo se abre en la aplicación del sistema; cualquier otro en la vista hex. *Open with the System Application…* pregunta antes; lanzadores y scripts nunca se entregan. |
| Extract Selected | Botón en la vista del archivo | Sobre una carpeta se lleva la carpeta con todo lo que contiene - también sus permisos guardados y sus subcarpetas vacías. |
| Encrypt / Decrypt con passphrase | Click derecho | AES-256-GCM. Decrypt escribe un fichero nuevo en claro que solo tú puedes leer (0600). |
| Open as root… | Click derecho | Solo local; routea a `pkexec`. Oculto si polkit/pkexec faltan. |
| Create XLink… | Click derecho | Fichero pointer cross-protocolo. |
| Mount as FUSE (read-only / read-write)… | Click derecho | Dos entradas para que el modo de mount sea visible al frente. Cambia a "Unmount FUSE" mientras está montado. Los ficheros y las carpetas muestran los permisos que informa la conexión (sin setuid ni setgid; sin bits de escritura en un montaje de solo lectura). En un montaje de lectura y escritura un fichero nuevo tiene desde su primer byte el modo con que se creó, y chmod funciona. |
| Batch Rename… | Click derecho (multi-selección) | Find/Replace o regex con preview en vivo + rename atómico. |
| Permissions… | Click derecho | Diálogo chmod con grid de checkboxes + input octal. setuid, setgid y sticky se muestran como en `ls -l` (`-rwsr-xr-x  (4755)`) en la columna Permissions, en *Properties…* y en *Permissions…*. |

## Find Files

**Edit → Find Files…** (`Alt+F7` o `Ctrl+Alt+F`; en el menú contextual de
un panel *Find in This Folder…*) busca en carpetas de todas las conexiones
abiertas a la vez — local, SFTP, SMB, S3, … — y, si se quiere, en el índice
offline. `Ctrl+F` sigue siendo el filtro en vivo del panel.

| Campo | Qué hace |
|---|---|
| Name | Un texto sin `*` ni `?` coincide en cualquier parte del nombre, corchetes incluidos (`report` encuentra `Q3-report.pdf`, `Song [Remix]` a sí mismo); un patrón (`*.jpg`, `IMG_????.*`, `IMG_[0-9]*`), con el nombre entero, donde `[0-9]` es un conjunto. No distingue mayúsculas ni la forma Unicode (`strasse` encuentra `Straße`, un `Ärger` escrito en un Mac se encuentra). Una búsqueda por nombre lista también las carpetas que coinciden (categoría *Folder*), salvo que Contains, Size o Types estén puestos. *Regex* toma una expresión regular. |
| Contains | Texto dentro del fichero, línea a línea, en los primeros 32 MiB de cada fichero - UTF-8, UTF-16 con marca de orden de bytes y, para texto simple (no *Regex*), también Latin-1 / Windows-1252; *Regex* y *Case-sensitive* como de costumbre. |
| Types | Cualquiera de las plantillas marcadas: imágenes, vídeos, audio, documentos, archivos comprimidos, imágenes de disco y de VM (dd / raw / img, ISO, qcow2, VDI, VMDK, VHD(X), E01 / AFF, DMG, LUKS…), carteras cripto (Bitcoin Core / Litecoin `wallet.dat`, Electrum, keystores Ethereum `UTC--…`, Exodus, Monero, MultiBit / Armory, Wasabi, Atomic, Ledger Live, carteras de navegador MetaMask / Phantom / …), claves y certificados (PEM / DER, `.p12` / `.pfx`, keystores Java, claves SSH y PuTTY, KeePass), código fuente, correo, bases de datos. Se decide por nombre y carpeta; para ficheros locales cuya extensión no dice nada (`blob`, `wallet.dat`, `UTC--…`) también por los primeros bytes y — con el extra `sift` (`axross[sift]`) — por sift. Types nombra *clases* de fichero: nada busca contraseñas o claves dentro de los ficheros. |
| Size / Modified | `10K`, `1.5M` (o `1,5M`), `2G`; un rango de fechas, ambos días incluidos. |
| Inside archives | Busca también dentro de zip, tar, tar.gz / .bz2 / .xz / .zst, ficheros .gz / .bz2 / .xz / .zst sueltos y archivos anidados en ellos (3 niveles); en 7z y rar por nombre de miembro. Un resultado se lee `archive.zip!/carpeta/fichero.txt`. Con límites: 10 000 miembros y 1 GiB descomprimido por archivo, 64 MiB por archivo anidado, la proporción 100:1 anti zip-bomb de la extracción para miembros de 64 MiB o más (los menores no se comprueban por proporción, así que un ZIP de una imagen de disco llena de ceros se extrae); un archivo remoto se copia antes (como mucho 256 MiB) a un fichero temporal privado. |
| Tag | Solo ficheros con la etiqueta elegida (menú contextual → *Tags*); un archivo etiquetado vale para sus miembros. Una Smart Folder conserva la etiqueta. Los resultados del índice offline también se filtran. |
| *Hidden files*, *Skip .git, node_modules, caches*, depth | Qué incluye el recorrido. Nunca se siguen carpetas enlazadas (symlinks). |
| Look in | La carpeta de cada panel abierto (la activa marcada), *Add Folder…* y *Also search the offline index* (nombres, tamaños, fechas; sin contenido). |

Los resultados llegan mientras la búsqueda corre; *Stop* o cerrar la
ventana la cancela. Las columnas se ordenan; doble clic o `Enter` muestra el
fichero seleccionado en un panel (un miembro de archivo abre la vista del
archivo), y el menú contextual tiene *Open*, *Reveal in Pane*, *Copy Path* y
*Send to Agent*. Si el filtro del panel o el ajuste de ficheros ocultos
escondería la entrada mostrada, Reveal vacía el filtro o muestra las
entradas ocultas en esa carpeta (hasta que el panel cambie a otra), y la
línea de estado lo dice.

En una carpeta local la búsqueda usa [`fd`](https://github.com/sharkdp/fd)
para listar ficheros y [`ripgrep`](https://github.com/BurntSushi/ripgrep)
(`rg`) para buscar en su contenido si están instalados (en el `PATH`,
`fdfind` en Debian / Ubuntu, o `bin/` junto a un build congelado); sin ellos
un recorrido propio da los mismos resultados, más despacio. Las carpetas
remotas se recorren a través de la conexión.

**Save as Smart Folder…** guarda la búsqueda entre los bookmarks (barra
lateral y menú Bookmarks, con icono de lupa); un clic la vuelve a ejecutar
en las carpetas cuya conexión está abierta. Se guarda en `bookmarks.json`
con los demás bookmarks.

**Edit → Index Active Folder…** registra nombres, tamaños y fechas bajo la
carpeta del panel activo en el índice offline — es la única forma de
llenarlo. *View → Find in Index…* (`Ctrl+Shift+F`) busca en él en una ventana
que sigue abierta junto a la ventana principal (Ctrl+Shift+F la trae de
nuevo al frente); la ventana muestra el fichero del índice.

### El índice offline

- **Qué guarda.** Un fichero SQLite con una fila por fichero y carpeta: la
  conexión, la ruta completa, nombre, tamaño, carpeta o no, extensión, hora
  de modificación y cuándo se indexó. Ni contenido ni checksums — esos están
  en el índice de duplicados (`cas.sqlite`, al lado).
- **Dónde.** `$AXROSS_METADATA_DB`; si no, `$XDG_DATA_HOME/axross/metadata.sqlite`
  cuando `XDG_DATA_HOME` es una ruta absoluta; si no,
  `~/.local/share/axross/metadata.sqlite`. Un índice en el sitio antiguo
  sigue en uso mientras no haya uno en el nuevo, así que fijar
  `XDG_DATA_HOME` no deja nada huérfano. `cas.sqlite` sigue las mismas
  reglas (`$AXROSS_CAS_DB`). *Edit → Settings… → Search* muestra ambas rutas.
- **Cómo se llena y se actualiza.** *Edit → Index Active Folder…* (o
  *Index Current Pane…* en *Find in Index*) recorre de forma recursiva la
  carpeta del panel activo a través de su conexión — cualquier backend,
  entradas ocultas incluidas, como mucho 50 niveles y 1 000 000 de entradas
  por pasada, escritas en lotes de 500, cancelable (lo indexado se
  conserva). Navegar nunca indexa. Indexar de nuevo la misma carpeta
  actualiza sus filas y quita las de ficheros borrados desde entonces — solo
  tras una pasada completa: una cancelada, o una que llegó al límite de
  entradas, no quita nada, y las filas bajo una carpeta que no se pudo listar
  se quedan. La herramienta MCP `build_index` solo añade; con `prune` además
  pregunta al backend por cada path indexado bajo la carpeta y quita las
  filas cuyo fichero ya no está.
- **Cómo se busca.** Subcadena del nombre (sin distinguir mayúsculas en
  ningún alfabeto: «ärger» encuentra `Ärger.txt`, «strasse» encuentra
  `Straße.pdf`, también en la herramienta MCP `search_index`), extensión, rango de
  tamaño, rango de fechas, una conexión. Extensión, tamaño y fecha usan
  índices SQLite; una subcadena del nombre (`LIKE '%…%'`) no puede usar
  ninguno y lee todas las filas. La búsqueda corre en segundo plano y la
  ventana muestra las primeras 5000 coincidencias (y avisa si hay más).
- **Qué tan rápido — medido** en la máquina de desarrollo con `/usr`
  (290 872 entradas, disco local, la máquina con otra carga): primera pasada
  125 s (unas 2 300 entradas/s), segunda pasada sobre el mismo árbol 53 s,
  fichero del índice 98 MiB; una búsqueda por nombre 0,4–1,2 s (se leen
  todas las filas; muchos resultados tardan más), una por extensión 37 ms.
  Bueno para «¿dónde estaba ese fichero?» en conexiones que ahora están
  offline; no es una búsqueda de contenido (esa es *Find Files → Contains*,
  en vivo).

### Find Files y sift

sift (el extra opcional `sift`) es un *analizador* de ficheros, no un
buscador: no construye índice ni tiene búsqueda — su línea de comandos y su
API resumen ficheros, y lo único que guarda es una caché de resúmenes por el
hash del contenido. Buscar en carpetas, por tipo y dentro de archivos, es el
propio Find Files de axross (`core.file_search`, `core.file_categories`,
`core.archive`).

- **Para qué usa Find Files a sift.** Con el extra instalado, el filtro
  *Types* pregunta a `sift.detect` por ficheros locales cuyo nombre no dice
  nada (ninguna extensión que reclame una plantilla) y asigna la clase
  detectada — imagen, PDF, DOCX, archivo, SQLite, correo, código fuente, … —
  a una plantilla. Los ficheros remotos y los miembros de archivos se
  clasifican solo por nombre y carpeta. No hay interruptor: Find Files usa
  sift si está.
- **Dentro de archivos.** sift lista los miembros de un archivo en su
  resumen (el dock Analysis), pero no busca en ellos. *Find Files → Inside
  archives* sí: zip, tar.*, compresores de un solo fichero y archivos
  anidados en ellos (3 niveles), 7z y rar por nombre de miembro.
- **Dónde están las opciones y funciones de sift.** *View → Panels → Analysis (sift)*
  (`Ctrl+Shift+I`; menú contextual → *Analyse with sift*) explica el
  fichero seleccionado: sin modelo automáticamente, con el perfil LLM activo
  mediante *Analyse with LLM*. El botón *LLM…* del dock abre *Edit →
  Settings… → LLM Profiles*, donde se configuran los servidores de modelos;
  *Edit → Settings… → Analysis (sift)* tiene las opciones propias de sift
  (análisis automático, límite de lectura, presupuesto de tiempo, visión,
  contexto, etiquetas, categorías, la caché) y el perfil que usa el
  análisis. *Help → Features…* muestra si el extra sift está instalado y
  ofrece instalarlo (`pip install axross[sift]`; un build congelado ofrece
  en su lugar la descarga de axross-full). *Identify Files in This Folder…*
  muestra la clase que sift da a los ficheros locales en una columna propia.

## Path bar

- **Auto-refresh ◉** suscribe el panel a `core.watch`; refresh
  debounced en cambios del backend.
- **Filtro en vivo** escribe en la path bar para filtrar el listado
  en tiempo real. **Ctrl+F** salta al campo del filtro; **Esc** allí
  borra el filtro y vuelve a la lista. Esc en la lista detiene primero
  un load en curso, luego borra un filtro activo, luego la selección y
  luego un cut pendiente de ese panel.
- **Ctrl+L** salta al campo de la ruta - también desde el campo del
  filtro, y Ctrl+F desde allí vuelve al filtro; **Esc** en el campo de la
  ruta descarta lo escrito, muestra de nuevo la carpeta actual y vuelve a
  la lista.
  En un panel local `~` es la carpeta personal y una ruta relativa está
  debajo de la carpeta mostrada; una carpeta que no se puede abrir deja la
  barra en la carpeta mostrada (una ruta escrita se queda mientras la barra
  tiene el foco). Una ruta con un control bidi o un carácter invisible se
  queda tal cual en la barra, con una bandera naranja al final; su tooltip
  nombra la ruta como la muestra la lista (ese carácter como �).
- **Marcadores** como dock izquierdo; F8 marca el path actual, F12
  alterna el dock. Las carpetas arrastradas desde un pane al dock
  (espacio libre, un grupo o entre dos entradas) se convierten allí en
  marcadores, las remotas con su connection profile. Los ficheros y
  carpetas soltados *sobre* un marcador se mueven a su carpeta (Ctrl
  copia), con la misma comprobación de nombres existentes que F5 / F6;
  una carpeta que falta o un remoto que no responde se notifica y no se
  encola nada, y un marcador remoto sin conexión abierta conecta
  primero y luego transfiere. Los grupos de marcadores se anidan hasta 16
  niveles; un grupo más profundo se rechaza. Un marcador creado por un
  axross más nuevo cuyo tipo esta versión no conoce se abre como carpeta y
  se guarda tal cual, con cada campo que esta versión no conoce. Las
  entradas que no se pueden leer se guardan en
  `bookmarks.json.unreadable-<hora>-<id>` antes del siguiente guardado.
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

Cada visor, editor, diálogo y ventana adicional tiene su propia barra de
título: su icono y nombre, luego `_` (ponerla en la barra de docks), el
botón de maximizar y [x]. El gestor de ventanas no dibuja la suya (la
ventana no tiene marco): arrastrar la barra de título mueve la ventana, un
doble clic la maximiza o la restaura y los bordes finos cambian su tamaño.
*Settings > Appearance > axross's own title bars* vuelve a la barra de
título y los botones del gestor de ventanas, también en las ventanas
abiertas. [x] la cierra, el de su izquierda lo maximiza a toda la pantalla y
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
  es una pestaña de una ventana de editor (F4 o *Open With ▸ Open as Text* en un panel,
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
  abre la ventana sin fichero. El resaltado se hace en un proceso aparte:
  un fichero que no se puede colorear en 60 segundos queda como texto
  plano hasta que se elige otro lenguaje u otro fichero, y la ventana
  nunca lo espera más de un segundo. Guardar conserva el
  final de cada línea no tocada, un BOM y los espacios duros, escribe de
  forma atómica y pregunta si el fichero cambió desde que se abrió; el
  panel con la carpeta se refresca. Cerrar con cambios sin guardar
  pregunta Save / Discard / Cancel; cerrar la última pestaña cierra la
  ventana, y la barra de menús lleva los botones maximize y [x]. Se abren ficheros hasta el límite de
  apertura (32 MB por defecto, *Edit → Settings… → Files & Panes*).
  Una línea de más de 200 000 caracteres se abre con ajuste de línea;
  por encima de 1 000 000 el fichero se abre además de solo lectura, con
  una nota y *Edit Anyway*. Una línea sin sitio donde partir se parte en
  cualquier punto; abierto sin la ventana principal, el fichero se lee en
  segundo plano ("Loading…").
- **Editor hex** — útil para triage en ficheros remotos.
- **Visor de Markdown** — F3 / doble-click en un archivo `.md`,
  `.markdown`, `.mdown` o `.mkd`, local o remoto (F4 lo sigue
  editando): el Markdown de GitHub (tablas, listas de tareas, tachado,
  autolinks, notas al pie) con los encabezados como índice al lado, que
  sigue el lugar que se lee, código resaltado, zoom (Ctrl +/-/0),
  búsqueda (Ctrl+F marca cada coincidencia y dice cuál de cuántas; Enter
  o F3 la siguiente, Shift+Enter o Shift+F3 la anterior), Recargar (F5) y
  Editar (F4). Ctrl+rueda, Ctrl++ (o Ctrl+=) y Ctrl+- hacen zoom del texto
  entre 25 % y 400 %; el botón muestra el nivel, y si haces clic en él (o
  pulsas Ctrl+0) vuelve al tamaño original.
  Un archivo local se muestra de nuevo cuando cambia en el
  disco, y el lugar que se leía se mantiene. *Export* guarda la página
  como HTML (con sus imágenes dentro, nada que pudiera cargar de otro
  sitio) o PDF, o la imprime (Ctrl+P) - la página entera, con progreso y
  *Cancel*, mientras la ventana sigue usable. En un PDF (y en papel) un
  recuadro que cruza un salto de página (una alerta, un bloque de código)
  se dibuja entre los márgenes en ambas páginas. Un archivo largo muestra su comienzo
  enseguida y se compone por partes mientras se lee («Rendering… 40 %»).
  Un texto largo con notas al pie en línea (`^[...]`) se muestra por
  partes, como otros textos largos (salvo que una nota pase de una línea
  a otra o contenga código). Un
  salto va directo a su lugar - soltar la barra de desplazamiento, Buscar
  (desde arriba de lo que se ve; su cuenta dice «12+» hasta que la página
  está completa), un enlace a un encabezado, Ctrl+Fin, recargar - y las
  partes intermedias aparecen al desplazarse hacia ellas, sin mover lo que
  se lee. Seleccionar todo, Export e imprimir toman la página entera. Una
  coincidencia o un enlace `#…` dentro de un `<details>` plegado lo abre;
  Buscar cuenta y alcanza esas coincidencias en el orden de la página. Una
  tabla demasiado ancha para el texto crece más allá y la página se
  desplaza de lado en vez de partir sus palabras.
  Recargar (también cuando el archivo cambia), plegar, el zoom y otro
  tamaño de ventana mantienen el lugar que se lee, y recargar muestra la
  página anterior hasta que la nueva está lista; Buscar sigue el orden de
  la página y vuelve al principio; Seleccionar todo y Copiar actúan enseguida, también en una página larga,
  y copian exactamente lo que muestra la página (las fórmulas
  como su TeX: `$$…$$` en una línea propia, `$…$` en el texto - arrastrar y el
  portapapeles de selección dan lo mismo, un elemento de lista con su número o
  viñeta, una fila de tabla con sus celdas separadas por tabuladores); el índice
  lista cada encabezado desde el principio. Por debajo de 700 px el índice se oculta (*Outline* lo
  devuelve); la ventana llega hasta 440 px. Con el botón derecho, un
  encabezado del índice ofrece *Copy Link to Heading* y un bloque de código *Copy
  Code Block*.
  Los enlaces se abren en la misma ventana - otro archivo Markdown en el
  encabezado que nombra su `#…`, el README de una carpeta, un archivo de
  texto como texto, una imagen a su propio tamaño - y Atrás / Adelante
  (Alt+Izquierda / Alt+Derecha, los botones del ratón) recorren los
  visitados. Un enlace por encima de la carpeta del documento solo se abre
  tras una pregunta (No por defecto); un archivo secreto, nunca. Un enlace web se abre en el navegador (un enlace `mailto:` en el
  programa de correo) solo tras una pregunta
  que muestra su dirección real (en el modo de seguridad `paranoid`,
  nunca) - un host que imita a otro (letras cirílicas, mezcladas o latinas de
  apariencia engañosa) se
  muestra y enlaza en punycode (`xn--…`), también como texto de un enlace `www.…`
  o de correo y en la pregunta del correo; lo demás (`file:`, una ruta absoluta, un archivo secreto) se
  nombra en la línea de estado, sin abrirlo.
  Lo que contiene el archivo se muestra, nunca se ejecuta: del HTML solo
  queda una lista corta de etiquetas inofensivas (`<p align>`, `<img>`,
  `<br>`, `<details>`/`<summary>` (plegado salvo con `open`; un clic en el
  resumen lo abre o pliega), `<kbd>`, `<sub>`/`<sup>` y similares;
  scripts, estilos y marcos desaparecen con su contenido, otras etiquetas
  desaparecen y su texto queda), nada se carga de la red (una imagen
  o insignia remota es un pequeño recuadro «▣ texto alternativo» (en la terminal «🖼 texto
  alternativo»), con su
  dirección en el tooltip; una imagen incrustada como `data:` se muestra), las imágenes se leen solo de
  la carpeta del archivo y de las que están debajo (ninguna carpeta
  superior, sin ruta absoluta, sin `file:`), solo archivos regulares,
  nunca un archivo secreto, como máximo 8 MiB y 40 millones de píxeles
  cada una y 200 por archivo. En el editor, *View → Markdown Preview*
  (Ctrl+Shift+M) muestra el texto renderizado al lado y sigue lo que
  escribes (tras una pausa): la vista previa del editor mantiene a la vista
  la línea en la que escribes, también en textos largos y en textos sin
  encabezados.
  Con markdown-it-py instalado (axross-markdown lo trae), el visor muestra
  el conjunto completo - notas al pie (numeradas como en GitHub: una referencia
  a una nota que no existe queda como está escrita, cada cita tiene su propio
  regreso), listas de definiciones, front matter (un `key: value`
  sencillo como tabla, como en GitHub; otro YAML en un recuadro con
  etiqueta),
  tablas alineadas, las alertas de GitHub (`> [!NOTE]` …), matemáticas
  compuestas como KaTeX (`$x^2$`: variables en cursiva, nombres de función
  rectos, sumas e integrales grandes con sus límites, fracciones y
  binomiales apiladas, paréntesis que crecen, matrices y casos como
  cuadrículas, números de `\tag` a la derecha; sin una fuente matemática instalada, una
  fuente con serifa, y una fórmula demasiado anidada o larga se muestra como
  texto en su línea), atajos de emoji (`:tada:`), direcciones `https://…`, `www.…` y de
  correo sueltas como enlaces, código con los colores de GitHub - para temas
  claros y oscuros; sin él usa el Markdown de Qt, con el mismo HTML
  permitido, alertas, emoji, enlaces de referencia y matemáticas (también en bloques de código del lenguaje `math`),
  pero `<details>` siempre abierto. Los bloques enormes (un log de 100 000
  líneas en un bloque de código, miles de fórmulas) nunca congelan la ventana, tampoco dentro
  de un elemento de lista, una cita, una alerta, una definición o una nota, ni las tablas y
  listas HTML: un bloque así se queda donde está y se compone por partes al desplazarse. Un
  encabezado, una fila de tabla o un término con más de 100 fórmulas muestra el resto como
  TeX, con una nota. El texto de un encabezado o de una celda de tabla de
  más de 2000 caracteres se corta con «…» en la ventana (el aviso lo dice);
  el editor muestra la línea entera. Una nota al pie citada muchas veces
  muestra sus primeros 20 regresos, seguidos de «and N more». El código de más de 500
  líneas o 40 000 caracteres se muestra sobre su fondo gris sin recuadro. Los
  bloques de código se colorean en un proceso aparte; uno que tarda más de
  5 segundos se muestra sin colores. Las listas
  anidadas a más de 16 niveles y las citas a más de 8 se muestran más planas, con una nota,
  en todas las vistas. Una copia larga se hace por partes ("Copiando… 40 %"); recargar
  mientras tanto la cancela y lo dice. Las anclas
  `<a id>` / `<a name>` pueden llevar dígitos y puntos (`#26.8.0`), las etiquetas de notas
  al pie coinciden sin importar mayúsculas, y el `` $`…`$ `` de GitHub también es una
  fórmula, igual que `$$ … $$` con espacios dentro. `$$…$$` en líneas
  propias es una fórmula destacada, también justo después de una línea de
  texto o de la línea `[!NOTE]` de una alerta, como en GitHub. Las matemáticas cubren los símbolos
  comunes de KaTeX, argumentos de un solo carácter (`\frac12`, `\sqrt5`), `\choose`,
  `\bigcup`, `\lbrace`, `\ket`, `\mathscr`, `\operatorname*` y los índices anidados;
  `\cfrac`, `\overset`, `\underset` y `\stackrel` se apilan solo en fórmulas destacadas (en el
  texto y en la terminal van al lado), y un comando desconocido se muestra tal como está
  escrito. Un archivo que no es UTF-8 se lee como Windows-1252 / Latin-1.
  Un texto que el parser no puede leer (o que tarda demasiado) se muestra
  tal como está escrito, con un aviso del motivo - nunca una página en
  blanco ni un bloqueo. Un archivo que no se puede leer muestra el motivo
  en la página. Una fórmula anidada más de 64 grupos se muestra
  como su TeX con la nota "(nested more than 64 deep: shown as written)".
  Una imagen cuya dirección no se permite (`file:`, o una dirección
  `data:` que no es una imagen) es un recuadro que la nombra, de un
  archivo que no es texto se dice que no lo es, y un shortcode de emoji
  que ninguna fuente instalada puede dibujar queda tal como está escrito;
  Export HTML conserva los enlaces relativos como `notes.md`. En una terminal,
  `axross-mdcat ARCHIVO.md` (axross-markdown) muestra lo mismo en color,
  con enlaces e imágenes donde la terminal puede mostrarlos; `--watch` lo
  muestra de nuevo cuando cambia (si el archivo no existe, lo dice y espera
  hasta que aparezca), `--toc` lista sus encabezados; un archivo largo se escribe a medida que se
  compone; una lista numerada de tareas conserva sus números (`1. ☐ a`). El `axross-markdown [ARCHIVO…]` independiente abre el visor; `--term` (la salida
  de terminal, con las opciones de mdcat), `--html ARCHIVO|-` (una página HTML), `--help` y
  `--version` no inician Qt, y una opción desconocida es un error.
  En Windows, `axross-markdown.exe` no abre ninguna ventana de consola;
  la vista de terminal es `axross-mdcat.exe` (o `axross-markdown --term`
  desde una consola), y su salida a una tubería o a un archivo es UTF-8.
  Si falta una biblioteca del sistema que la ventana necesita (libEGL en un
  Linux mínimo), nombra la biblioteca y el paquete que la trae y remite a
  `--term` / `--html`. Con *View → Theme* (Alt+V) del visor coloreas la
  página (fondo, texto, títulos, enlaces, código, citas, tablas, avisos y
  fórmulas) con uno de doce temas: Light, Dark, Sepia, Solar Light, Solar
  Dark, Arctic, Retro, Night Violet, Slate, Paper, High Contrast Light y
  High Contrast Dark. Todos mantienen el texto y los enlaces con el
  contraste WCAG AA, y los dos de alto contraste con AAA. *Automatic (as
  axross)*, el predeterminado, sigue el tema de axross, claro u oscuro. Tu
  elección vale para cada visor abierto y para la vista previa del
  editor, y axross la guarda en sus ajustes. Un cambio de tema es un
  único cambio, sin destellos: la página conserva sus colores antiguos
  hasta que está compuesta con los nuevos. El axross-markdown
  independiente tiene el mismo menú y guarda tu elección en
  `~/.config/axross-markdown/settings.json`. Allí eliges los colores de la
  propia ventana en *View → Window Theme*; si no eliges ninguno, siguen el
  esquema claro u oscuro del escritorio. Sus programas de un solo archivo
  se actualizan desde versiones firmadas (*Help → Updates*: apagado,
  avisar o instalar automáticamente; `--check-update`, `--update`). Con
  `axross-mdcat --theme NAME` usas los mismos temas en la terminal, y
  `--list-themes` los muestra. En la terminal un enlace de
  más de 2083 caracteres se muestra como su texto, una tabla de más de 500
  filas se dibuja sobre la marcha, y una de más de 64 columnas se muestra
  tal como está escrita (el final de la salida lo dice). axross-mdcat se
  detiene en cuanto termina el programa en el que escribe (`… | head`); si
  no puede escribir su salida (un disco lleno), lo dice y sale con el
  estado 1. Como la ventana, dibuja como máximo 200 imágenes de un texto;
  después dice que el resto no se dibuja.
- **Visor de imágenes** — F3 / doble-click, allow-list MIME,
  caps de tamaño. Ctrl + / Ctrl - (o `+` / `-`, Ctrl + rueda) hacen zoom,
  Cada imagen se abre ajustada a la ventana y sigue ajustada al
  cambiar su tamaño, hasta que haces zoom; Ctrl+0 (o `0`) muestra 100 %, `F` vuelve a ajustar.
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
  páginas de un PDF abierto solo; mantener pulsada una flecha pasa como
  mucho tres imágenes o páginas por segundo). Un PDF se abre y se dibuja
  en un proceso aparte: una página que tarda más de 15 segundos o lo hace
  fallar muestra el motivo, y las demás páginas se dibujan igual; una
  página que no se pudo dibujar se intenta una vez más cuando vuelves a
  ella. Las imágenes también se decodifican en un proceso aparte (unos
  pocos siguen en marcha para las siguientes): una imagen que tarda más de
  30 segundos o hace fallar el decodificador muestra el motivo. El visor
  de imágenes y la vista de miniaturas del panel decodifican igual. Antes
  de reproducir un vídeo, ffprobe (si está instalado) lo abre en un
  proceso aparte: un vídeo cuya comprobación falla o no termina en 10
  segundos no se reproduce, y se muestra el motivo. Un PDF de más de una página muestra un control de páginas
  `← n / m →` en la barra de botones; Arriba / Abajo pasan sus páginas.
  Home / End, F11 fullscreen, Ctrl+M maximize / restore (la ventana
  recuerda tamaño, posición y estado maximize para la próxima
  apertura), rueda (en un PDF Ctrl + rueda), Ctrl + / Ctrl - o `+` / `-`
  zoom (en un PDF ajustado, desde el tamaño mostrado), Ctrl+0 100 %, `F` fit, `1`
  100 %, `R` rotar, `S` slideshow (intervalo en segundos; la
  slideshow da la vuelta, un vídeo se reproduce hasta el final), Esc
  vuelve a la overview, otro Esc cierra. **Supr** (Delete) mueve el
  fichero mostrado (o el tile seleccionado) al trash tras una pregunta,
  donde su conexión tiene uno (en un recurso compartido cuyo trash está
  arriba lo dice, como el panel); **Shift+Supr** lo borra para siempre tras
  su propia pregunta (por defecto *No*);
  arrastrar la imagen o un tile a un pane lo mueve allí, con Ctrl se
  copia - igual que un arrastre desde el pane del que salió el visor
  (una imagen ampliada se desplaza en su lugar). El visor de imágenes
  hace ambas cosas también. Funciona en cualquier
  backend: los ficheros remotos se copian a un directorio temporal
  privado hasta el *Open Size Limit* y se borran después; un
  elemento demasiado grande, cifrado o roto muestra el motivo. El SVG
  solo se renderiza sin DOCTYPE/entidades, scripts ni referencias
  fuera del fichero, en un proceso aparte que se detiene a los 10
  segundos, también un SVG con nombre de imagen (`x.png`); la vista de
  miniaturas del panel dibuja los SVG igual, y la primera página de un
  PDF; sus miniaturas se guardan en `~/.cache/axross/thumbnails`, legibles
  solo por ti, como mucho 20 000 (las usadas hace más tiempo se borran
  primero). En un fichero Markdown una imagen SVG pasa por las mismas
  comprobaciones y el mismo proceso (30 segundos para todos los SVG de un
  documento juntos), y una "imagen" que en realidad es un PDF o PostScript
  no se muestra, tampoco en el terminal. El modo `paranoid` bloquea el visor.
  `I` (o el botón *Info*) muestra la metadata del elemento actual en
  un panel lateral, con *Remove metadata* — también en el visor de
  imágenes.
- **Media Player** (extensión incluida; su botón de la barra de
  herramientas o *Extensions → Media Player* ofrece activarla) — un dock que reproduce MP3, WAV, Ogg Vorbis, FLAC,
  Opus, AAC y más - y radio por internet: *URL…* añade un stream por su
  dirección http / https (la playlist .m3u de una emisora también los
  nombra; un stream no tiene posición a la que saltar). Las pistas se añaden con click derecho → *Play in
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
  no se puede reproducir se marca y se salta - también una que hace
  fallar o colgarse a ffprobe (si está instalado) cuando comprueba antes
  la pista; una pista así no se carga cuando el reproductor vuelve a
  arrancar. *M3U* → *Load Playlist…* / *Save Playlist…* leen
  y escriben playlists M3U / M3U8 (UTF-8, rutas relativas para pistas
  bajo la carpeta de la playlist, títulos y duraciones `#EXTINF`; los streams http / https se
  conservan, otras URLs y entradas ausentes o que no son audio se omiten, archivos de más
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
  mute, + / - volumen; los botones junto a Play saltan 15 s atrás y
  adelante (pasado el final, la pista termina como siempre). Con numpy: ecualizador de 10 bandas con presets
  (la flecha a la izquierda de *Equalizer* pliega los sliders de las
  bandas y deja el sitio a la playlist; es el único ecualizador de axross
  - la voz del Agent también pasa por él, se guarda en `audio.json` y
  vuelve en el siguiente inicio). El botón **…** a la derecha del volumen:
  *Output* reproduce el Media Player en su propio dispositivo (*Same as
  the output*, o p. ej. el headset mientras la voz sigue en los altavoces
  - su canal del Audio Mixer), *Sleep Timer* pausa tras 15 a 90 minutos
  con 8 segundos de fundido o al final de la pista (el tiempo restante
  aparece junto al volumen) y *Audio Mixer…* abre el mezclador. Además,
  una visualización animada:
  espectro, espectro reflejado, espectro radial, osciloscopio, VU meter
  estéreo, espectro en línea (eje de frecuencia logarítmico), waterfall
  (espectrograma), espectro polar, stereo scope (goniómetro: L contra
  R), un starfield que acelera con el bajo, un ecualizador LED (bloques
  con un bloque de pico que cae), columnas de partículas (puntos de los
  que suben chispas con el ritmo), un wave ribbon que gira con el ritmo,
  ridgelines (el historial del espectro en profundidad bajo un sol a
  rayas), un terreno del espectro (el historial como paisaje wireframe),
  un anillo 3D de barras, un caleidoscopio (pétalos reflejados del bajo,
  los medios y los agudos) o curvas de campana (una por banda) - un clic
  en ella pasa a la siguiente. Cada visualización es segura para personas
  fotosensibles: haga lo que haga el sonido (un synth con puerta, estática
  de radio), ninguna zona de la imagen destella más de tres veces por
  segundo y ninguna destella en rojo saturado (WCAG 2.3.1 / 2.3.2). Vale a
  cualquier tamaño y velocidad de imagen y con cualquier música - un synth
  con puerta, ruido distinto a izquierda y derecha, ráfagas cortas: las
  barras cambian juntas como mucho cinco veces por segundo y si no se
  quedan donde estaban, el osciloscopio mantiene sus puntos a 3 px, el
  stereo scope dibuja puntos, y una ventana pequeña muestra menos curvas de
  campana, más anchas, y menos filas de terreno. Su menú del click derecho lista cada
  visualización y cada
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
- **Chat** (extensiones incluidas IRC, Matrix y XMPP: se activan en
  *Extensions → Manage Extensions…* y luego el menú Extensions muestra y
  oculta el panel de cada una; Matrix y XMPP necesitan el extra `chat`,
  que ofrece *Help → Features…*) — el editor de cuentas ofrece servidores públicos conocidos
  en una lista editable (siempre se puede escribir uno propio): una copia
  viene con axross, *Refresh list* descarga los directorios públicos (la
  lista de redes de irssi, joinmatrix.org, la lista XMPP Providers) a través
  del proxy y los guarda. Conectado, *Channel List* / *Room Directory* /
  *Group Chats* abre a la derecha los canales públicos del servidor -
  filtro, orden, doble clic para entrar (IRC LIST por partes, como mucho
  100 000 canales). Un candado junto a cada cuenta y conversación muestra la
  protección: TLS hasta el servidor, cifrado de extremo a extremo (todas las
  claves verificadas o no) o texto claro.
- **Bluetooth** (extensión incluida; *Tools → Bluetooth* ofrece
  activarla) — un panel para conectar altavoces, auriculares y otros
  dispositivos Bluetooth a través de BlueZ (`bluetoothd`) en el D-Bus del
  sistema; no se inicia ningún programa. Muestra el adaptador (si hay
  varios: elige uno) con el interruptor *Powered*, y *Scan* lista lo que
  está al alcance: nombre, dirección, tipo (altavoz, headset, teléfono,
  teclado, reloj, rastreador, sensor …), radio (Classic, BLE o ambas),
  intensidad de señal en dBm durante el escaneo, el fabricante que
  anuncia un dispositivo BLE, batería si el dispositivo la informa,
  cuándo se oyó por última vez (*now*, *12 s ago*) y Connected / Paired /
  Trusted. **Add Device…** añade un dispositivo nuevo de una vez: enciende
  el adaptador si se lo pides, escanea mientras está abierto, lista los
  dispositivos nuevos cercanos (los que tienen nombre primero, la señal más
  fuerte arriba, *Show unnamed* para balizas) y *Add* empareja, marca como
  de confianza y conecta el elegido y - para un altavoz o headset con *Use
  as audio output* marcado - lo convierte en la salida de axross, cada paso
  marcado o fallando con su motivo; *Cancel* detiene un emparejamiento y al
  cerrar se detiene el escaneo que inició. Junto a *Scan* eliges qué busca
  un escaneo - *Classic + BLE*,
  *Classic only* (altavoces, teléfonos, teclados) o *BLE only* (relojes,
  rastreadores, sensores) - y la señal más débil que lista (*-70 dBm or
  stronger* se queda con los dispositivos cercanos); un escaneo en marcha
  conserva su elección. La fila de abajo filtra la lista sin escanear de
  nuevo: palabras contra nombre, dirección, tipo, fabricante y servicios,
  *All radios* / *Classic* / *BLE* y *Named only* (oculta las balizas y
  rastreadores sin nombre que un escaneo BLE encuentra por docenas). El
  tooltip de un dispositivo nombra sus servicios. *Details…* (o un doble
  clic) muestra todo lo que BlueZ sabe de un dispositivo - dirección y su
  tipo, clase de dispositivo, radio, fabricante, clase y apariencia,
  señal y potencia de transmisión, batería, cuándo se oyó por última vez,
  su estado y los datos de anuncio en bruto - y, en *Services*, los
  servicios y perfiles que ofrece. Para un dispositivo BLE conectado
  (*Connect* está ahí mismo) mapea los servicios GATT que BlueZ resolvió
  con sus características: *Read* o *Read All* obtiene sus valores,
  *Watch* muestra cada nuevo valor de una que notifica (pulso, sensor)
  hasta *Stop Watching* o hasta cerrar el diálogo. Los valores conocidos
  se decodifican (nombre, nivel de batería, apariencia, pulso,
  temperatura, humedad, presión), los demás como texto o hex. La pestaña
  *Map* junto a *List* dibuja los dispositivos cercanos alrededor de este
  ordenador a su distancia estimada - a partir de la señal y, si el
  dispositivo la anuncia, su potencia de transmisión, suavizada sobre las
  últimas lecturas; los anillos marcan 1, 3, 10 y 30 m. Bluetooth no
  indica dirección, así que el ángulo de un dispositivo es solo su lugar
  fijo en el mapa. El color es la radio (Classic, BLE, ambas), un punto
  relleno un dispositivo emparejado, un anillo uno conectado; los más
  cercanos con nombre llevan etiqueta, pasar el ratón muestra la señal y
  la distancia de cualquiera, un clic lo selecciona en la lista y un
  doble clic abre sus detalles (cuyo *Signal history* muestra las
  últimas lecturas). La fila de filtros también se aplica al mapa. Una
  distancia es una estimación aproximada - paredes y cuerpos la reducen
  a la mitad o la duplican con facilidad. *Test…* (o la pestaña
  *Connection* de los detalles) reúne las opciones y pruebas de conexión:
  conectar o desconectar un solo perfil (*Audio playback (A2DP)*,
  *Headset with microphone (HFP)*, *Media controls*, HID, PAN, puerto
  serie - los que ofrece el dispositivo); *Reconnect automatically when
  the connection drops* (axross lo vuelve a conectar tras 2, 5, 15, 30 y
  60 s mientras se ejecuta; una desconexión que pides no es una caída; se
  guarda en `~/.config/axross/bluetooth.json`); *Test Connection* -
  conecta si hace falta e informa, con tiempos: la conexión, la
  resolución de los servicios, la ida y vuelta de unas lecturas GATT (BLE)
  y, para un altavoz o headset, la aparición de su salida de audio; para
  altavoces y headsets *Play Test Sound* (dos tonos cortos en la salida
  propia del dispositivo, sea cual sea la salida de axross) y *Test
  Microphone* (un medidor de nivel durante 5 s - el micrófono de un
  headset solo existe en su perfil de headset, el panel dice cuál
  conectar). Un escaneo
  se detiene solo a los 2 minutos. Para el dispositivo elegido: *Pair*
  (*Cancel Pairing* mientras dura), *Trust* / *Untrust* (un dispositivo de
  confianza puede volver a conectarse solo), *Connect*, *Disconnect*,
  *Remove* (tras una confirmación). Altavoces y auriculares suelen
  emparejarse sin preguntar; cuando un dispositivo pide confirmar un
  passkey, un PIN o un passkey, un diálogo te pregunta - nada se acepta
  sin tu respuesta, y cerrar el diálogo es un no. *Use as Audio Output*
  conecta un altavoz o headset si hace falta, espera hasta 20 s a que su
  salida aparezca en el servidor de sonido y la convierte en la salida de
  *Edit → Settings… → Audio*, que el Media Player y los demás
  reproductores siguen al instante; si no aparece ninguna salida (el
  perfil A2DP no está disponible, p. ej. falta el soporte Bluetooth de
  PipeWire o PulseAudio) el panel lo dice y ofrece *Audio Settings…*. Los
  errores de BlueZ se convierten en frases (adaptador apagado, bloqueado
  por rfkill, PIN incorrecto, dispositivo fuera de alcance, perfil no
  disponible). Sin el D-Bus del sistema, sin `bluetoothd` en marcha o sin
  adaptador el panel lo dice y no ofrece nada más; se da cuenta cuando el
  servicio arranca o se conecta un adaptador. Solo Linux.
- **Audio Mixer** (extensión incluida, **Tools → Audio Mixer** ofrece
  activarla) — todos los ajustes de sonido en un panel. *axross*: el
  volumen maestro con su mute y su dispositivo de salida, y un canal por
  fuente — Media Player, Agent voice, Media preview — con su propio
  volumen, mute y salida (*Same as the output* o un dispositivo propio: la
  voz en el headset, la música en los altavoces). *Equalizer*: el único
  ecualizador de 10 bandas de axross con presets (la fila de ecualizador
  del Media Player muestra el mismo ajuste, la voz del Agent pasa por él;
  se oye con numpy). *System*: el servidor de sonido mediante `pactl`
  (PipeWire o PulseAudio) — salidas y entradas con volumen (hasta 150 %),
  mute y *Default*, los programas que reproducen o graban con su volumen
  y su dispositivo (elegir otro los mueve; los streams propios de axross
  van marcados) y el perfil de cada tarjeta (un headset Bluetooth: A2DP
  para música, el perfil de headset para su micrófono). Sin `pactl` o sin
  servidor de sonido la pestaña dice por qué y ofrece *Try Again*. Todo se
  guarda en `audio.json` como en **Edit → Settings… → Audio** (que conserva
  el backend, el dispositivo de entrada y las pruebas) y los reproductores
  en marcha lo siguen al instante.
- **System Information** (extensión incluida) — ver *System Information*
  en *Extensiones incluidas*.
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
Los ficheros y carpetas ocultos se incluyen. Lo que una ejecución deja
fuera lo nombra la línea de estado, con las rutas en su tooltip: carpetas
que no se pudieron leer, carpetas a más de 8 niveles, subcarpetas
mientras *Include subfolders* está desactivado, el límite de 5000
ficheros, enlaces a carpetas y ficheros de tipos cuya metadata axross no
puede limpiar (HEIC, AVIF, RAW como DNG / CR2 / NEF, SVG, PSD, `.doc` /
`.xls` / `.ppt`, EPUB …) - esos se quedan como están.
Leer y eliminar corren en segundo plano con progreso y *Cancel*. En los
visores de imágenes y de media, `I` abre la misma información como panel
lateral.

| Tipo | Lectura | Se elimina | Se conserva |
|---|---|---|---|
| JPEG, PNG, WebP, GIF | incluido | EXIF (GPS, cámara, números de serie, fechas, autor, software), thumbnails embebidos, XMP, IPTC, comentarios, chunks de texto PNG, datos tras la imagen | orientación EXIF, perfil de color ICC; los píxeles nunca se recodifican y se comprueba que son idénticos |
| TIFF | incluido | lo mismo, con un guardado sin pérdida | orientación, perfil ICC; un TIFF con compresión JPEG se rechaza |
| docx / xlsx / pptx, odt / ods / odp | incluido | `docProps/core.xml`, `app.xml`, `custom.xml` (encontrados por sus relaciones, en mayúsculas o minúsculas, también Strict OOXML), cada `meta.xml` de ODF, también el `Object N/meta.xml` de un objeto embebido, el comentario del zip, los comentarios y campos extra de las entradas (ids de usuario, fechas) | todas las demás partes, que descomprimen a los mismos bytes; las fechas de las entradas |
| PDF | pypdf, si no QtPdf | diccionario Info, XMP y PieceInfo dondequiera que estén (catálogo, páginas, imágenes, formularios), revisiones anteriores y objetos que nada usa (reescritura completa) | — necesita el extra `[metadata]` (`pip install 'axross[metadata]'`) |
| Audio / vídeo | `ffprobe` | todos los tags y capítulos, data streams (pistas GPS de cámaras), la carátula de los ficheros de audio (`ffmpeg -c copy`, sin recodificar) | los streams |

**No se elimina** (es contenido, no metadata, o no se puede quitar sin
cambiarlo): en ficheros Office los comentarios y sus autores, el control
de cambios, `people.xml`, la ruta de la plantilla, las partes de XML
personalizado, `absPath`, las imágenes dentro con su propio EXIF / GPS,
el thumbnail, las propiedades de documentos embebidos, los nombres de
impresora y de host de ODF y las fechas de las entradas del zip; en PDFs
las anotaciones y sus autores, los adjuntos, el `/ID` del trailer y el
EXIF / GPS dentro de JPEGs embebidos; en imágenes el perfil ICC (con el
nombre de un perfil PNG); en vídeos la carátula y los adjuntos MKV. Un
fichero local con otros hard links se limpia en el propio fichero, así
que cada nombre tiene el contenido limpio; la papelera guarda una copia
propia del original. La copia limpia se hace en una carpeta privada
junto al fichero, no en la carpeta temporal del sistema.

**Cómo se escribe** — *Edit → Settings… → Metadata* (*Tools → Metadata
Settings…* la abre):

- **In place** (por defecto): el fichero se reemplaza de forma atómica
  y el original queda en el trash de axross. Una ejecución — un fichero
  o una carpeta entera — es una entrada para *Edit → Undo Last
  Operation* (`Ctrl+Z`), que devuelve cada original byte a byte, pero
  solo mientras el fichero contenga exactamente lo que escribió la
  eliminación; `Ctrl+Z` salta un Remove Metadata que ya no puede
  deshacer (el fichero editado desde entonces, el trash vaciado) y dice
  por qué. El original se queda en el trash de axross - en conexiones
  locales y SFTP una carpeta que solo tú puedes abrir (0700), la copia con
  los permisos del original - hasta que se vacía el trash; bórralo allí
  (*Show Trash…*)
  cuando el original no deba conservarse en absoluto.
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

## Herramientas

Ventanas de los menús *View* y *Tools* que no son un panel. **F1** en
cada una abre su parte de esta sección.

### Duplicate Finder

*View → Duplicate Finder…* (`Ctrl+Shift+D`; en un panel, clic derecho →
*Analyse → Duplicate Finder…*) trabaja con el índice de duplicados
(`cas.sqlite`, ver *El índice offline*).
Agrupa los archivos indexados por hash de contenido, primero el mayor desperdicio: cada grupo muestra el espacio que liberaría y la línea de estado el total. Los archivos vacíos y los grupos que solo son enlaces duros de un archivo quedan ocultos salvo que se marque *Empty files* / *Hard links*. *Filter* (texto o patrones como `*.jpg *.png`; `Ctrl+F`), *At least* (un tamaño) y *Sort* (espacio a liberar, tamaño, copias, nombre, carpeta) acotan la lista; las copias de un grupo siguen en orden de superviviente (la primera se conserva). *Rebuild from Active Pane…* calcula los hashes de la carpeta en segundo plano con recuentos, bytes y *Cancel*: los archivos sin cambios no se vuelven a leer, los que desaparecieron desde el último escaneo salen del índice, y el informe nombra los archivos que no se pudieron leer, las carpetas que no se pudieron listar y los FIFOs, sockets o dispositivos omitidos (nunca se leen: podría colgarse). Un backend sin checksum de contenido propio (SMB, FTP simple, WebDAV solo con ETags) hace leer sus archivos en su lugar — solo los que comparten tamaño con otro archivo, y solo mientras coincidan sus primeros 64 KiB; un ETag nunca cuenta como hash. *Mark All Duplicates (keep first)* conserva la copia más antigua; *Mark, Keeping…* (también en el menú contextual) conserva la copia más reciente, la ruta más corta o una copia dentro de una carpeta, o marca las copias dentro de una carpeta; un enlace duro de una copia conservada nunca se marca, y los enlaces duros no cuentan como espacio a liberar. *Move Selected to Trash…* (`Del`) mueve las copias marcadas a la papelera de axross tras comprobar en vivo que queda otra copia real. `Enter` abre la carpeta contenedora, la línea bajo la lista muestra la fila actual completa (tamaño exacto, hash, enlaces duros), y se pueden copiar URLs `ax-cas://…`. Miles de grupos aparecen por partes mientras la ventana sigue usable.

*View → Duplicate Index & History…* muestra el índice por sí solo: cada
reconstrucción queda registrada como un escaneo, listado con su carpeta,
backend, inicio y fin, los archivos indexados, los que siguen en el
índice, los grupos de duplicados y su estado. *Show Duplicates* abre el
Duplicate Finder sobre los grupos de ese escaneo, *Re-scan* recorre otra
vez la misma carpeta en el mismo backend en segundo plano (con *Cancel*;
se registra un escaneo nuevo), *Remove from Index…* olvida las filas de
ese escaneo y *Clear Whole Index…* todas las filas - los archivos se
quedan donde están. Las filas indexadas antes de que se registraran los
escaneos forman una entrada *earlier*: se puede mostrar y quitar, no
volver a escanear (su carpeta es desconocida).

### Disk Usage

*View → Disk Usage…* es una tabla con la capacidad de cada conexión
abierta (cada conexión una vez, la muestren cuantos paneles la muestren):
backend, protocolo, total, usado, libre y una barra de la parte usada.
Las consultas corren fuera del hilo de la GUI, cada una con su timeout.
Una conexión que no informa capacidad (IMAP, LDAP, la mayoría de los
object stores en la nube) o que no respondió a tiempo muestra *not
supported* y ninguna barra - no se midió nada, y eso no es 0 %; la línea
de abajo las cuenta. *Refresh* mide de nuevo.

### Scheduled Jobs

*View → Scheduled Jobs…* ejecuta un script guardado (el dock *Scripts*)
a intervalos: dale al job un nombre, el nombre del script y un intervalo
(5 minutos, 15 minutos, 1 hora, 6 horas, 1 día o uno propio de al menos
300 s) y *Add*. La tabla muestra de cada job el script, el intervalo, la
última ejecución, el estado, la próxima ejecución y el detalle de la
última; *Enable / disable* y *Remove* actúan sobre el job seleccionado.
*Run Now* registra el inicio de la ejecución como la última ejecución del
job.
Los jobs solo corren mientras axross está abierto (comprueba una vez por
minuto), cada uno en un proceso hijo como una ejecución desde el dock
Scripts, no interactivo (una pregunta se rechaza en lugar de esperar),
como mucho 24 horas y 1 000 000 caracteres en stdout y otros tantos en
stderr por ejecución. Un job que sigue corriendo no se vuelve a iniciar -
tampoco desde un segundo axross ni tras un fallo mientras su script sigue
corriendo (un lease en `~/.local/state/axross/jobs.leases/`); las citas perdidas con
axross cerrado dan una ejecución, no una cola; tras 10 fallos seguidos un
job se desactiva solo y dice por qué (*Enable / disable* lo vuelve a
activar); el detalle de un fallo es el final de la última línea de error
del script, como mucho 500 caracteres. Una última ejecución registrada más
de un intervalo en el futuro (el reloj se atrasó) hace el job pendiente al
momento. El modo de seguridad paranoid no inicia ningún job y no cuenta
ninguno como fallido. Los
scripts que ejecuta un job llevan `[scheduled]` en el dock Scripts. Los
jobs se guardan en `~/.local/state/axross/jobs.json`, junto al diario de
operaciones (`AXROSS_OPERATION_JOURNAL` mueve ambos). Una fila de job que
no se puede leer se guarda en `jobs.json.unreadable-<hora>-<id>` antes del
siguiente guardado.

### Diagnóstico y Recovery Scan

- **Tools → Run Active Pane Diagnostics…** comprueba la conexión del
  panel activo: su carpeta home, un listado y un stat de la carpeta
  mostrada y - tras una pregunta, nunca en el modo de seguridad
  paranoid - una prueba que escribe, renombra y borra allí un pequeño
  fichero `.axross-diagnostic-*`. El informe da cada comprobación como
  `[OK]` o `[FAIL]` con su detalle, sin contraseñas ni tokens; corre
  fuera del hilo de la GUI.
- **Tools → Recovery Scan…** lista lo que se puede recuperar en la
  carpeta del panel activo: ficheros temporales que dejó una escritura
  atómica interrumpida (`.tmp-*.tmp`, también los antiguos
  `.axross-atomic-*.tmp`) y las entradas de la papelera de axross de esa
  conexión con su ruta original y tamaño. No borra nada: *Show Trash…*
  restaura, y los restos de más de una hora los quita un panel al abrir
  su carpeta.

## Extensiones incluidas

axross trae extensiones en `resources/extensions/`; todas empiezan
desactivadas, y *Extensions → Manage Extensions…* las activa y
desactiva. Un botón de la barra de herramientas (Media Player, Folder
Treemap, Drives Overview) y las entradas *Tools → Audio Mixer*, *Tools →
Bluetooth* y *Tools → System Information…* ofrecen activar su extensión
cuando está desactivada. Media Player, Chat, Bluetooth y Audio Mixer se
describen en *Editores y visores*, Agent Stats en *Dock Agent*. Las demás:
Drives Overview y Markdown Preview son paneles; Checksum Manifest
(*Create SHA256SUMS*), Forensic Tools (imágenes de disco: hashes,
qemu-img, The Sleuth Kit, TestDisk, PhotoRec) y VirtualBox añaden
entradas al menú contextual. Cómo se confía en las extensiones, cómo se
pausan y se escriben - y la `api` que reciben - está en
[EXTENSIONS.md](EXTENSIONS.md) (en inglés). Una extensión que llama a
`sys.exit()` se muestra como fallida; nunca cierra axross.

### Arcade

*Extensions → Arcade…* abre una ventana con los cuatro pequeños juegos
propios de axross: **Byte Chase** (recoge cada bit de un laberinto
mientras cuatro daemons te persiguen; una root key los da la vuelta un
rato), **Tilt Maze** (100 niveles en 10 mundos sobre un tablero
isométrico, Espacio salta sobre los daemons y los pozos), **Rockfall**
(40 cuevas en 5 mundos: excava en busca de cristales bajo rocas que caen
y llega a tiempo a la salida) y **Trail Runner** (los corredores dejan
muros tras de sí; 1-3 corredores del ordenador o dos jugadores en un
teclado, Espacio acelera). Los juegos nunca destellan en rojo: cuando
atrapan a Byte la pantalla se oscurece, y nada parpadea más de tres
veces por segundo. En el selector las flechas o W A S D eligen y
Enter o un clic empieza; un juego ofrece *Start at level 1*, *Continue at
level n* y un *world code* que abre un mundo ya alcanzado. En el juego:
flechas o W A S D dirigen, `P` pausa, `M` silencia, `R` empieza de nuevo
al terminar, Esc vuelve al selector y, desde allí, cierra la ventana.
Cada nivel se genera, la música y los sonidos se sintetizan y siguen la
salida del Audio Mixer; los récords y el progreso se guardan en
`~/.config/axross/arcade.json` y `arcade-progress.json`.

### Folder Treemap

Un panel (el botón *Folder Treemap* de la barra de herramientas o
*Extensions → Folder Treemap*) que dibuja la carpeta del panel activo como
cajas cuya área es el tamaño: archivos y subcarpetas, las subcarpetas
sumadas en segundo plano a través de la conexión - como mucho 20 000
entradas y 12 niveles, sin seguir enlaces a carpetas. Una suma que se
detuvo ahí lleva *(at least)* en el tooltip, que nombra la caja y su
tamaño. Un doble clic en una caja de carpeta la abre en el panel; salir
de una carpeta antes de que termine su recorrido lo detiene. El botón de
pausa de la barra de título del panel deja de seguir al panel de
archivos.

### Entropy Heatmap

Clic derecho en un fichero → *Entropy Heatmap…*: la entropía de Shannon
de cada bloque de 4 KiB de sus primeros 16 MiB como franja de color -
azul para texto, tablas y relleno, rojo para datos comprimidos o
cifrados - con la media y el valor más alto en bits por byte y un
veredicto (*looks compressed or encrypted throughout*, la parte de tales
bloques, *low entropy* o *mixed content*). El fichero se lee en segundo
plano a través de su conexión, así que los ficheros remotos también
funcionan.

### Backup Repositories

Clic derecho en una carpeta (o en nada, para la carpeta mostrada) →
*Backup Repository Info…* dice qué contiene un repositorio **restic**,
**Borg** o **duplicity**, sin contraseña y en cualquier backend, solo por
su estructura: de restic el número de snapshots, claves, índices y
carpetas de packs; de Borg el `config` en claro (versión, id, ajustes de
segmentos, append-only, repokey o keyfile) y el número de segmentos; de
duplicity cada cadena de backups con sus backups completos e
incrementales, sus horas, volúmenes, tamaño y cifrado. *Unlock…* pide la
contraseña (y un fichero de clave de Borg cuando el repositorio lo usa) y
lista los snapshots o archivos con la propia herramienta (`restic
snapshots`, `borg list`, `duplicity collection-status`) - solo
repositorios locales. La contraseña va al entorno de la herramienta o a
la entrada de gpg, nunca a una línea de comandos, y no se guarda; en el
repositorio no se escribe nada.

### Image Batch

Selecciona imágenes (`.png .jpg .jpeg .webp .bmp .gif .tif .tiff`), clic
derecho → *Resize / Convert Images…*: el lado más largo en píxeles (0
mantiene el tamaño; nunca se amplía) y el formato (PNG, JPEG o WebP). Las
copias van a una subcarpeta `resized`, como `name (2).jpg` si el nombre ya
existe - nada se sobrescribe y los originales quedan intactos. Las fotos
se enderezan primero según su orientación EXIF; un JPEG recibe las partes
transparentes sobre blanco. Las imágenes de más de 64 MiB y los ficheros
que no son imagen se omiten y se cuentan. Funciona en cualquier backend;
el panel se recarga al terminar el lote.

### System Information

**System Information** (extensión incluida, **Tools → System
Information…** ofrece activarla; después también *Extensions → System
Information…*) — una ventana con todo sobre el ordenador en el que
corre axross. *Overview*: el nombre, fabricante, modelo y sistema del
ordenador con sus cifras clave (hilos de CPU, memoria, almacenamiento,
pantallas), y tarjetas con anillos para la carga de CPU, la memoria, el
swap, el sistema de archivos raíz y la batería (carga y salud), las
temperaturas más altas en una escala de color (verde hasta 60 °C,
ámbar, naranja desde 80 °C o la marca alta del propio sensor, rojo
desde 90 °C o crítica), la gráfica con las pantallas conectadas y las
interfaces de red con su caudal en vivo; CPU y memoria tienen una
sparkline de los dos últimos minutos. Un clic en una tarjeta abre su
página. La lista de la izquierda tiene una página para *CPU* (uso por
CPU lógica, núcleos P y E, frecuencias, cachés, las características del
juego de instrucciones como chips, la vista del kernel sobre las
vulnerabilidades de la CPU), *Memory* (en uso, caché y libre en una
barra, swap), *Storage* (una barra por disco con sus particiones,
puntos de montaje y uso; discos y sistemas de archivos como tablas),
*Graphics & Displays* (adaptadores, salidas con el nombre, la
resolución, la frecuencia y el tamaño del monitor según su EDID, un
esquema de las pantallas), *Network* (interfaces con tipo, estado,
velocidad o señal Wi-Fi, driver y tráfico; adaptadores Bluetooth;
interruptores de radio), *Audio* (tarjetas de sonido, códecs,
dispositivos PCM), *USB & Peripherals* (el árbol USB y los dispositivos
de entrada), *PCI* (el árbol PCI, nombres de `pci.ids`), *Battery &
Power*, *Sensors* (temperaturas, ventiladores, voltajes), *System & OS*
(fabricante, modelo, firmware, Secure Boot, kernel, escritorio,
versiones) y *Virtualisation* (máquina física, máquina virtual o
contenedor, con los indicios). Todo se lee de `/proc` y `/sys` sin root
y sin arrancar ningún programa (en Windows y macOS menos: lo que dicen
Python y el psutil opcional); cada fuente tiene un plazo, y una sección
que no se puede leer dice por qué - las demás no esperan. El campo de
búsqueda (`/`) filtra todas las páginas a la vez y la lista cuenta los
resultados por página. *Copy Section*, *Copy All* y *Save Report…*
(texto o JSON) exportan lo recogido; *JSON Export* guarda todo como
archivo JSON o copia todo / la página mostrada como JSON (cada valor,
tabla y lectura en bruto). Los números de serie, las
direcciones MAC e IP y los UUID quedan ocultos en pantalla y en cada
copia hasta marcar *Show identifiers* - estos informes se suelen pegar
en público. Los valores en vivo se leen una vez por segundo mientras la
ventana está a la vista, nunca oculta; *Refresh* lo recoge todo de
nuevo. La ventana conserva su tamaño.

## Dock de Transferencias / Terminal / Log

- La franja inferior tiene tres pestañas: **Transfers**, **Terminal**,
  **Log**. Cada una parpadea ámbar cuando algo pasa fuera de pantalla
  (cambio de estado de transferencia, salida de shell, línea de log).
  Click la levanta y limpia el indicador.
- Click derecho en una transferencia para **Cancel** (este job),
  **Retry** (un job fallido o cancelado) y **Open destination folder**
  (el panel de su conexión muestra la carpeta, con el archivo
  seleccionado).
- El dock de Log filtra por nivel y por área: *Areas* junto al nivel es
  una lista de las áreas de logging para marcar (un área incluye sus
  sub-áreas; *Other* es todo lo de fuera, *All Areas* el valor por
  defecto). Ambos filtros vuelven a mostrar las líneas recibidas. Qué se
  registra se ajusta en *Edit → Settings… → Logging* (ver
  [Logging](#logging)).
- El terminal (dock y pane de terminal) es una pantalla VT100 / xterm:
  retorno de carro, movimientos del cursor, borrado, regiones de
  scroll y la pantalla alternativa funcionan, así que los prompts de
  zsh, la edición de línea, `less`, `top` y los editores dibujan donde
  deben. El tamaño de terminal de la shell es el del área del terminal
  y sigue cada cambio de tamaño (`stty size` lo muestra). Los colores
  no se muestran. Las imágenes de programas y otras cadenas de control
  largas (imgcat, sixel, una copia OSC 52 grande) se descartan y nunca
  aparecen como texto; escribir sobre la mitad de un carácter ancho lo
  borra entero, como en xterm.
- Las teclas pulsadas en el terminal van a la shell: Ctrl+letra (en
  macOS la tecla Control), teclas de función, flechas y teclas de
  edición; así Ctrl+W, Ctrl+Q o F6 no cierran un pane, no salen de
  axross ni mueven ficheros. Alt+tecla actúa como Meta (Alt+B, Alt+F,
  Alt+. llegan a la shell, salvo donde axross tiene un atajo con Alt como
  Alt+Izquierda / Derecha), y Shift+Tab y Ctrl / Shift con las flechas
  también llegan. Pegar con Ctrl+Shift+V (macOS: Command+V),
  clic central o el menú contextual; el texto va a la shell, y una shell
  que pide bracketed paste (bash 5.1+, zsh, fish) lo recibe como una sola
  edición en vez de ejecutarlo línea a línea. Pegar mucho en una shell
  ocupada - local, SSH o en Windows - espera en una cola (hasta 16 MiB) y
  sale a medida que la shell lee; la ventana nunca se congela. Los atajos
  con Command en macOS y las teclas de zoom siguen siendo de axross.
- Mientras se arrastra un fichero sobre un pane, la fila donde caerá
  queda enmarcada y una nota junto al cursor nombra la carpeta:
  *Move to …* o, con Ctrl, *Copy to …*. La fila `..` es la carpeta de
  arriba.

## Scripting y REPL embebida

axross trae una superficie Python curada (``axross.*``) con 122
nombres públicos (111 funciones + 11 clases: los tipos de resultado
de los helpers de red, grep y archivos, NonInteractiveError). Tres
puertas al mismo surface:

- **Dock Console** (menú View) — REPL con entrada multilínea,
  historial, tab-completion, panel lateral con cada función y su
  docstring. Tab completa allí, así que **Esc** devuelve el foco al
  panel de archivos. Un bloque pegado de varias sentencias se ejecuta
  sentencia a sentencia, como en el prompt; el primer error detiene el
  resto. El historial guarda ese bloque como una entrada, y Arriba lo trae
  entero tras reiniciar.
- **Headless** — ``axross --script myscript.py`` corre tu Python
  en el mismo namespace; ideal para cron/CI/lotes.
  Las palabras tras el fichero son el ``sys.argv[1:]`` del script
  (``axross --script mirror.py /srv/data``); el security mode
  paranoid, también si se eligió en *Settings*, lo rechaza.
- **MCP** — si ``--mcp-allow-scripts`` está activo, el surface
  también es alcanzable vía herramientas MCP.
- **Help → Scripting Guide** — la guía de scripting dentro de axross
  (SCRIPTING_es.md, en el idioma de la interfaz cuando hay versión) y,
  en su segunda pestaña, la referencia de la API (el texto de
  `axross.docs()`), con índice y un campo de búsqueda (Return busca la
  siguiente coincidencia).

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

### Explorar la API

- ``axross.help()`` — chuleta agrupada por categoría.
- ``axross.docs("backend")`` / ``axross.docs("scripts")`` /
  ``axross.docs("slash")`` — referencia Markdown por tema.
- Autocompletado con ``axross.<TAB>`` en la REPL.
- ``docs/SCRIPTING_REFERENCE.md`` — cada verbo y cada clase de resultado
  con su firma completa y docstring.

### Slash-commands de la REPL

| Comando | Efecto |
|---|---|
| ``.help`` | Listar los slash-commands |
| ``.scripts`` | Scripts guardados en ``~/.config/axross/scripts/`` |
| ``.save <name>`` | Guardar el código enviado en ESTA sesión; nunca reemplaza un script existente con ese nombre (``.delete`` primero), ni uno cuyo nombre solo difiere en mayúsculas |
| ``.load <name>`` | Mostrar el código de un script guardado |
| ``.run <name>`` | Ejecutar un script guardado en el namespace en vivo |
| ``.delete <name>`` | Borrar un script guardado |
| ``.open`` | Mostrar la ruta de la carpeta de scripts |

### Proxy en scripts

``axross.open(profile_name)`` y ``axross.open_url(url, **kw)`` pasan la
configuración de proxy por la misma lógica de ConnectionManager que la GUI.
``open()`` la lee del perfil guardado; ``open_url()`` la acepta como
argumentos con nombre:

```python
b = axross.open_url(
    "sftp://alice@gateway.example.com/",
    password="hunter2",
    proxy_type="socks5",          # "socks5" / "socks4" / "http" / "https" (+ "+ntlm" ...)
    proxy_host="proxy.example.com",
    proxy_port=1080,
    proxy_username="puser",       # opcional
    proxy_password="ppass",       # opcional
)
```

Si `proxy_type` no es `"none"`, `proxy_host` y un `proxy_port` distinto de 0
son obligatorios. Un proxy configurado a medias falla en lugar de conectar
directamente. Sin ningún argumento `proxy_*`, `open_url` usa el proxy por
defecto de *Tools → Network & Proxy…* (con su lista de exclusiones y su
script PAC); un script PAC que no se puede evaluar lanza
`ProxyResolutionError` en lugar de conectar directamente. Qué backends
admiten el proxy y cuáles no (UDP, transportes de kernel/USB, backends
locales) está en **[USAGE.md](USAGE.md)** (EN) y
**[PROXY_SUPPORT.md](PROXY_SUPPORT.md)**.

### Categorías (cada nombre público: `axross.api_schema()`)

| Grupo | Verbos |
|---|---|
| Conectar / backend | ``open``, ``open_url``, ``localfs``, ``ramfs``, ``list_backends``, ``available_backends`` |
| Perfiles | ``list_profiles``, ``get_profile``, ``save_profile``, ``delete_profile`` |
| E/S de ficheros | ``copy``, ``move``, ``checksum``, ``read_bytes`` / ``write_bytes`` / ``read_text`` / ``write_text``, ``hash_bytes`` / ``hash_file`` |
| Cripto / archivos | ``encrypt``, ``decrypt``, ``extract_archive``, ``is_archive``, ``archive_inspect`` |
| Bookmarks | ``list_bookmarks``, ``add_bookmark``, ``remove_bookmark`` |
| Scripts | ``script_dir``, ``list_scripts``, ``save_script``, ``load_script``, ``delete_script``, ``run_script`` |
| Por protocolo | ``find_tftp_files``, ``slp_discover``, ``nntp_post``, ``git_push``, ``exec``, ``interactive_shell``, ``query``, ``tables``, ``imap_search`` / ``imap_move`` / ``imap_set_flags``, ``share``, ``ldap_search`` |
| DNS / red | ``dns_resolve`` / ``dns_records`` / ``dns_reverse``, ``port_open``, ``port_scan``, ``subnet_hosts`` |
| Utilidades de red | ``ping`` / ``PingResult``, ``mac_lookup`` / ``OuiInfo``, ``whois`` / ``WhoisInfo``, ``time_skew`` / ``TimeSkew``, ``tcp_banner``, ``tls_cert`` / ``TlsCert``, ``ssh_hostkey`` / ``SshHostKey``, ``http_probe`` / ``HttpProbe`` |
| SNMP | ``snmp_get``, ``snmp_walk``, ``snmp_set``, ``SnmpVar`` |
| Búsqueda entre backends | ``find_files``, ``grep`` / ``GrepHit``, ``diff_files`` |
| Metadata de ficheros | ``metadata``, ``remove_metadata``, ``export_metadata`` |
| UI helpers | ``message``, ``confirm``, ``toast`` (modal + toast con iconos SVG de estado; sin GUI, stdout/stdin), ``is_interactive``, ``NonInteractiveError`` |

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
Scripts dock, un ``run_script`` de MCP o ``AXROSS_NONINTERACTIVE=1`` —
lanza ``axross.NonInteractiveError`` en vez de usar el valor por
defecto; ``assume_yes=True`` responde que sí sin preguntar.

Una ejecución del dock Scripts termina con axross también cuando axross se
mata con kill o se cae, junto con lo que haya iniciado (Linux, macOS).

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
plug-in Secret-Service de KeePassXC). axross sondea un backend
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

axross puede correr como servidor Model Context Protocol de modo que
un cliente LLM (Claude Desktop, Cline, un agente propio) pueda manejar
cualquier backend configurado a través de una superficie de
herramientas JSON-RPC.

```bash
axross --mcp-server                                  # solo lectura, stdio
axross --mcp-server --mcp-write --mcp-root ~/data    # añade tools de escritura (capada a ese root)
axross --mcp-server --mcp-http 127.0.0.1:7331        # HTTP, loopback
```

Las herramientas de ficheros de solo lectura (`list_directory`, `get_path_info`,
`read_file`, `compute_file_checksum`, `search_index`, `walk_tree`, `search_content`, …), las de escritura
con `--mcp-write`, los grupos de capacidades de `--mcp-tools`
(`axross --mcp-list-tools` imprime cada herramienta que sirve un
conjunto de flags), endpoints `resources/*`, log forwarding por
`notifications/message`, timeouts por herramienta, rate limits
token-bucket por sesión, sesiones HTTP con streaming SSE de
progreso, multi-backend routing opcional.

Referencia completa: **[docs/MCP_es.md](MCP_es.md)** (ES) · [MCP.md](MCP.md) (EN) · [MCP_de.md](MCP_de.md) (DE).
Para clientes LLM: [LLM_GUIDE.md](LLM_GUIDE.md) (en inglés).

## Dock Agent — un LLM local trabaja con axross

View > Panels > Agent (Ask the Agent: Ctrl+Shift+K; Ctrl+Shift+A en una
lista de archivos invierte la selección) abre un chat con un perfil LLM
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
a "+") abre una conversación nueva directamente como panel. **Send to
Workspace** en el mismo menú del tab lo hace en un paso: la conversación
se separa y se coloca en el workspace elegido, o con **New Workspace**
sola en uno nuevo, donde es la vista principal - clic derecho en el tab
de ese workspace → **Detach to Window** le da una ventana propia. Se
mueve la
misma conversación: una tarea en curso sigue, sus preguntas siguen
llegando, nada se reinicia. Un panel así se coloca como un panel de
extensión: en **All Workspaces** (el área de docks de la ventana) o -
con el botón ⇄ o un clic derecho en su barra de título (*Send to
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

**El agente nunca cambia**, sea cual sea su raíz y su acceso: los
ajustes y datos de axross (`~/.config/axross`, `~/.local/share/axross`,
`~/.local/state/axross` - sus permisos, sus servidores MCP), los ficheros
de inicio del shell (`~/.bashrc`, `~/.profile`, `~/.zshrc`, …),
`~/.config/autostart`, `~/.config/systemd`, `~/.ssh` y `~/.gnupg`, los
comandos del PATH (`~/.local/bin`) y los hooks de inicio de Python
(`~/.local/lib`), los ajustes de Git, pip y npm, los ficheros de inicio de
editores y gestores de ventanas, y los ajustes y servidores MCP de otros
clientes LLM (`~/.claude`, Claude Desktop, Cursor, VS Code), en su sitio
por defecto y en el de XDG: cambiado, cada uno ejecutaría código o
ampliaría los permisos del agente sin preguntar. Una carpeta que contiene
uno de ellos tampoco se borra ni se mueve, y un enlace simbólico no lleva
a ellos por otro camino. En el sandbox se montan de solo lectura los que
existen y las carpetas que faltan. El agente tampoco lee los tokens de
axross ni las claves privadas SSH y GnuPG (`--mcp-allow-secret-reads` lo
permite para el servidor MCP).

**Los archivos ocultos son de solo lectura para el agente y MCP.** Además
de esa lista, ninguna herramienta del agente o de MCP escribe, borra ni
mueve una entrada oculta de la carpeta personal (`~/.pdbrc`,
`~/.wezterm.lua`, `~/.aliases`, `~/.jupyter`, …) ni nada en `~/.config`,
`~/.local/share` y `~/.local/state` (también donde XDG los mueve,
`~/Library` en macOS, `%APPDATA%` en Windows): demasiados programas
ejecutan código desde ahí. Para que el agente cambie una de esas carpetas,
concede esa carpeta en concreto - como raíz del agente (o del servidor
MCP) o como carpeta adicional (`~/.config/myapp`); los sitios de la lista
siguen protegidos dentro, y conceder toda la carpeta personal no levanta
nada. Los ficheros de zsh en `$ZDOTDIR` (leído de `~/.zshenv`) cuentan como
ficheros de inicio, y los ficheros de Git que ejecutan código (`.git/config`,
`.git/hooks`, `.git/info`, `.git/commondir` - dirige Git a la configuración y
los hooks de otra carpeta -, `gitdir`, `.gitmodules`, una entrada `.git`) se
rechazan en cualquier sitio, también en un repositorio bare (`x.git/hooks`) y
en cualquier carpeta que Git tome por un repositorio (`HEAD`, `objects/` y
`refs/`; el último de los tres no se crea en una carpeta que aún no lo es -
un fichero `objects` o `refs` cuenta tanto como una carpeta, y una entrada de
archivo llamada `HEAD` no se extrae); igual `.hg/hgrc` y
`.hg/hgrc-not-shared` de Mercurial, `.sl/config` de Sapling, `.jj/repo` de
Jujutsu, `_darcs/prefs/defaults` de darcs y `.bzr/branch/branch.conf` de
Breezy (y las carpetas `.hg`, `.sl`, `_darcs`, `.bzr` mismas). Estos nombres
cuentan sin distinguir mayúsculas (`head`, `.GIT`): en una memoria FAT o
exFAT, un recurso SMB o una carpeta casefold Git recibe `head` al abrir
`HEAD`. Los archivos de proyecto desde los que otros programas ejecutan
código se rechazan también a cualquier profundidad: las carpetas `.claude`,
`.vscode`, `.cursor`, `.idea`, `.zed`, `.devcontainer`, `.husky`, `.fleet`,
`.gemini`, `.codex`, `.windsurf`, `.roo`, `.kiro`, `.amazonq`, `.continue`,
`.theia` (hooks, tareas al abrir la carpeta, servidores MCP, órdenes de
arranque y de dev container) y los archivos `.mcp.json`,
`.devcontainer.json`, `*.code-workspace`, `.pre-commit-config.yaml`,
`lefthook.yml` (y sus variantes) y `.overcommit.yml`; igual la carpeta que
nombra `core.hooksPath` de un repositorio (`.githooks`, `.husky/_` de husky;
también desde `~/.gitconfig`, `/etc/gitconfig` o `GIT_CONFIG_*`) y un
archivo que su configuración incluye (`include.path = ../.gitconfig`): el
siguiente `git commit` los ejecuta. Para que el agente cambie una de esas
carpetas (`.vscode` de un proyecto), concede esa carpeta misma como raíz o
carpeta adicional: solo cuentan los nombres por debajo de una carpeta
concedida. Cuenta cada nombre de
una ruta: tal como se escribe, tras cada symlink del camino y resuelto - y el
destino de un symlink en esos sitios (GNU stow: `~/.config/kitty ->
~/dotfiles/kitty`) se protege como el sitio mismo, salvo que concedas ese
destino. Un archivo con otros hard links no se escribe (los otros nombres
cambiarían también; escribe una copia con otro nombre). En el sandbox las
entradas ocultas de una carpeta personal con escritura se montan de solo
lectura y no se puede crear ninguna nueva, los destinos de esos symlinks son
de solo lectura; la configuración, los hooks, `info` y `commondir` de Git de
la carpeta del agente y de los repositorios una carpeta más abajo también,
igual que los ajustes de proyecto y las carpetas de hooks de arriba que
existan ahí, y
un `.git/commondir` que el agente cree ahí se aparta al terminar su tarea
(renombrado a `commondir.set-aside-by-axross-<hora>`), igual que un
`.git/config.worktree` y el `commondir` y `config.worktree` de las carpetas
Git de submódulos y worktrees (`.git/modules/<nombre>`,
`.git/worktrees/<nombre>`) creados durante la tarea. Un repositorio nuevo que
el agente cree en su carpeta no está cubierto (el límite documentado de un
worker comprometido). El `set_permissions` de MCP no pone los bits setuid, setgid ni
sticky, no da escritura al grupo o a todos y no cambia un archivo con otros
hard links (su modo vale para todos sus nombres).

**Secretos que el agente no lee**, además de los de axross: las
credenciales de herramientas comunes (`~/.aws`, `~/.kube`,
`~/.docker/config.json`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`,
`~/.pypirc`, `~/.npmrc`, cargo, rclone, Vault, Terraform, las credenciales
de Claude Code, `pass`), los perfiles de navegadores y correo (Firefox,
Chrome, Chromium, Brave, Edge, Thunderbird; los llaveros de macOS) y, bajo
una carpeta oculta de la carpeta personal, todo archivo cuyo nombre diga
credential, token, secret, key (`*.pem`, `*.key`, `id_*`, `*key*.json`), una
base de contraseñas (`*.kdbx`), cookies o history. Sus nombres se pueden
listar; el sandbox los muestra vacíos. La papelera de axross
(`~/.axross-trash`) también es secreta y de solo lectura para toda
herramienta. Un symlink a un secreto (`~/.ssh/id_ed25519 ->
~/keys/id_ed25519`) hace secreto su destino, y un hard link a un archivo
secreto tampoco se lee. El agente no cambia el código del axross que se
ejecuta (sus paquetes, recursos y scripts de una carpeta de fuentes, y
ningún código Python - `.py`, `.pyc` o un módulo compilado - en ninguna
parte bajo esa carpeta; en el sandbox no se crea nada nuevo en su nivel
superior; el binario de un build de un solo fichero, los ajustes y
programas del venv),
y un symlink que crea con `..` en su destino apunta al sitio comprobado
mismo, así nada redirigido después lo lleva a otra parte. En cualquier sitio - también en una carpeta de
proyecto - el agente no lee una clave privada ni una base de contraseñas
reconocida por su contenido (`-----BEGIN … PRIVATE KEY-----` en el primer
MiB, también tras los certificados de un bundle, una clave OpenSSH o PuTTY,
una base de KeePass) ni archivos que por su nombre guardan credenciales
(`.env`, `.env.*` salvo `.env.example`/`.sample`/`.template`, `*.env`,
`.envrc`, `.netrc`, `.git-credentials`, `.pgpass`, `.npmrc`, `.pypirc`,
`.htpasswd`, `*.tfstate`, `*.kdbx`, `id_rsa`/`id_ed25519`/`id_ecdsa` y sus
copias (`id_rsa.bak`), `*.ppk`, `*.p12`, `*.pfx`, `kubeconfig`,
`credentials.json`, `client_secret*.json`, `secrets.yaml`, `secrets.json`,
`.aws/credentials`, `.docker/config.json`, `.kube/config`). Una carpeta
cuyo nombre hace secretos sus ficheros (`.aws`, `.docker`, `.kube`; en un
remoto también `.ssh` y `.gnupg`) no se renombra ni se mueve entera, y las
copias de seguridad como `.aws/credentials.bak` o `config~` también son
secretas. Con una raíz
que contiene `/proc` (`--mcp-root /`) tampoco se leen el entorno, la línea
de órdenes, la memoria, los maps y los ficheros abiertos de un proceso
(`/proc/<pid>/environ`, …, `/proc/self`) ni `/run/secrets`. El sandbox solo
oculta los secretos de la carpeta personal; los archivos del proyecto
siguen visibles para las órdenes. La papelera firma cada entrada: una entrada cuyos datos o
registro han cambiado no se restaura - salvo un fichero enviado a la
papelera con otros nombres (enlaces duros) y editado a través de uno de
ellos: es el mismo fichero y vuelve (a un sitio protegido solo tras tu
confirmación). El mensaje dice si cambió el registro o los datos. Una
entrada que vuelve a un sitio protegido (un fichero de inicio, una
entrada de autostart) solo se restaura desde la ventana de la papelera y
tras tu confirmación. Cuando axross ya tiene su clave, un
registro sin firma cuenta como cambiado y no se restaura; solo los
registros más antiguos que la clave cuentan como antiguos.

**Las carpetas ocultas no se leen sin concederlas.** Las herramientas del
agente y del servidor MCP no entregan el contenido de una entrada oculta de
tu carpeta personal (`~/.config/<app>`, `~/.mozilla`,
`~/.local/share/TelegramDesktop`, …) ni de `~/snap` (ahí guardan los
paquetes snap sus perfiles de Firefox y Chromium; también `~/Library` y
`%APPDATA%`): demasiados programas guardan ahí sesiones, tokens y claves
para listarlos todos. Los nombres se pueden listar y tus demás archivos se
leen como antes. Si una tarea necesita uno de esos archivos, concede esa
carpeta - como raíz del agente o del servidor MCP o como carpeta adicional
(basta de solo lectura), p. ej. `~/.config/myapp`; los secretos dentro
siguen sin leerse. Conceder toda la carpeta personal no levanta nada;
`--mcp-allow-secret-reads` lo levanta para el servidor MCP junto con los
secretos.

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

*lax* con bubblewrap llega a internet por un espacio de nombres de red
propio cuando `pasta` (passt) está instalado; sin él, el sandbox comparte
la red del host - también sus sockets abstractos (el servidor X, D-Bus) -
y el log lo dice. Un servidor MCP del `.mcp.json` de un proyecto (o de
los ajustes de otro cliente) que ejecuta un programa pregunta antes de
activarse, con el comando completo y el fichero del que viene.

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
sandbox; uno sin él dice *runs on this machine, not in a container*.
**Contenido por defecto:** sin perfil de sandbox solo arranca un
lanzador puro: un intérprete que ejecuta un script o un módulo que ya
está en disco (`node server.js`, `python3 -u server.py`, `python -m
módulo`, `java -jar x.jar`, `dotnet x.dll`, `bash x.sh`,
`ruby`/`perl`/`php` con un script). Cualquier otro programa (un binario,
una herramienta de build como `bazel run`, `make`, `mix run`, `swift run`
…, un gestor de paquetes) dice *not started: needs a sandbox profile or
Trusted* y se rechaza al arrancar hasta que se ejecute en un perfil de
sandbox o marques *Trusted: runs on this machine as it is* (entonces se
ejecuta con tus derechos; se guarda como `"trusted": true`). Trusted
nunca deja entrar en esta máquina un comando que descarga código. El
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
  catálogo incluido (funciona sin conexión: los servidores de
  referencia de MCP fetch, filesystem, git, memory, sequentialthinking,
  time y everything; los servidores propios de los fabricantes para
  GitHub - solo lectura, repositorios, issues y pull requests -,
  Playwright, MarkItDown y Brave Search; búsqueda con DuckDuckGo; tres
  servidores de seguridad, vuln-nist, shodan y rea. Las imágenes van
  fijadas por digest y solo vienen del namespace curado `mcp/*` de Docker
  y de la imagen propia de GitHub `ghcr.io/github/github-mcp-server`; los
  paquetes npm y PyPI van fijados a una versión exacta), el namespace
  `mcp` de Docker Hub, el MCP Registry oficial
  (`registry.modelcontextprotocol.io`) y ficheros de catálogo o URLs
  `https://` propios. *Check* lee uno y dice qué contiene o por qué se
  rechaza (esquema incorrecto, más de 1 MiB, no es JSON, una entrada
  sin digest fijado …). Lo que dice una fuente se muestra como texto
  plano.
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
  una imagen fijada `node:24-slim` / `python:3.13-slim` (`npm
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
  demás no tienen ruta - el `fetch` propio de Node solo con
  `NODE_USE_ENV_PROXY=1`, que pone la entrada de Brave Search); **Full**
  cualquier host. Carpetas solo como se elijan, de solo lectura salvo
  que se marque *Writable*. Los valores de entorno y los secretos (en el
  keyring) llegan al contenedor por un pipe, nunca en la línea de
  comandos ni en un fichero.
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
`--mcp-tools agent` (`run_llm_agent`); ese modelo solo puede leer
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

## Docks de correo y proyectos de correo

**Tools → Mail Docks…** configura agentes que vigilan cada uno un buzón (un perfil IMAP,
POP3 o Exchange guardado y una carpeta). Cada dock tiene su panel: qué vigila, cuándo se
ejecuta, su registro (con cada llamada a herramienta de su agente), *Run Now*, *Stop*
(termina la ejecución en curso; un correo que espera su respuesta no se envía), *Pause*
(se conserva para el próximo inicio, como desmarcar *Run on its timer* en sus ajustes),
*Settings…* y *Open Drafts Folder* (los borradores POP3, en un panel). Un dock cerrado
vuelve con **View → Panels**; la ventana Mail Docks añade, edita, muestra y elimina docks.
Un dock necesita un buzón. Ajustes: el intervalo, las
**instrucciones** que sigue en cada ejecución, el perfil LLM, el perfil de **sandbox** (el
modelo y el agente corren dentro; las credenciales del buzón nunca) y la **política de
envío** con el servidor SMTP.

- *Never send - drafts only*: las respuestas quedan en Borradores (IMAP APPEND con
  \Draft; POP3: en la carpeta de borradores del dock).
- *Ask me before each mail*: un correo espera en el panel *Send* / *Don't Send* (sin
  respuesta en 30 minutos no se envía).
- *Answer the sender without asking*: la respuesta al remitente del correo contestado (y
  a los *destinatarios permitidos*, direcciones o `@dominio`) sale enseguida; cualquier
  otro espera tu sí. El remitente es la dirección *From* del correo: un *Reply-To*
  que nombre el correo es otra persona y también espera tu sí. Solo
  cuenta el remitente de un correo listado como nuevo en esa ejecución, y
  una respuesta que contiene el texto de otro correo (sus códigos,
  enlaces, direcciones, 8 o más palabras seguidas o citas más allá del
  correo contestado) espera tu sí también entonces. El asunto y los
  nombres de los destinatarios se comprueban como el texto. Todo lo que
  una herramienta mostró de otro correo cuenta como su texto: su asunto en
  la lista, su nombre de fichero, los enlaces de su parte HTML. Un código
  cuenta por sus dígitos se escriba como se escriba - con espacios,
  agrupado, en otras cifras, como palabras, al revés o codificado - y entre
  los correos enviados sin preguntar en esta ejecución y en las del dock de
  los últimos 7 días; un código alfanumérico o el token de un enlace cuenta
  con o sin sus separadores. Lo que el propio dock envió sin preguntar a
  varias personas - su firma citada en un hilo - y su propia dirección no
  cuentan como texto de otro correo, y en la comprobación sobre varios
  correos solo cuenta lo que añade el correo nuevo. Cada correo listado como nuevo recibe como
  mucho una respuesta sin preguntar. Las notas de otros docks cuentan como
  texto de otro correo, y un dock no se informa a sí mismo. Un correo que
  espera *Send* se ajusta a la línea; una serie larga de espacios se
  muestra como *[N espacios]*.

El agente de un dock solo tiene las herramientas de correo (`mail_list_new`, `mail_list`,
`mail_read`, `mail_analyse`, `mail_draft`, `mail_send`, `dock_report`) y no escribe
ficheros. El contenido de un correo se marca como no fiable en cada resultado; un correo
no puede añadir destinatarios ni cambiar la política. `dock_report` deja una nota a otro
dock, que la lee en su siguiente ejecución. Un correo cuenta como atendido cuando el
agente lo ha leído, analizado o contestado; uno que solo vio en `mail_list_new`, o uno de
una ejecución que falló o se detuvo, vuelve a ser nuevo en la siguiente. SMTP: STARTTLS o TLS con el certificado
comprobado, sin cifrar solo a esta máquina; la contraseña queda en el llavero.

**Tools → Mail Project…** importa ficheros `.eml` y `.msg` de Outlook, ficheros de datos de
Outlook (`.pst`, `.ost`, también los de Outlook 2013; cada mensaje como `.eml` con sus
cabeceras de transporte originales), mbox, Maildir,
carpetas enteras o la carpeta de un perfil de buzón en una carpeta de proyecto y analiza
cada mensaje sin conexión: la cadena Received, SPF/DKIM/DMARC tal como se registraron,
remitentes y dominios que no coinciden, enlaces cuyo texto muestra otro destino y
adjuntos peligrosos (programas, macros, dobles extensiones, contenido que no es lo que
dice el nombre). La lista se ordena por sospecha; la pestaña *Message* muestra el correo con
el HTML desactivado (sin scripts, estilos, marcos ni formularios, nada se carga, cada enlace
con su destino real al lado, se abre solo tras preguntar). *Check SPF / DKIM / DMARC in DNS*
(desactivado por defecto: las consultas revelan qué dominios miras) comprueba SPF, cada
firma DKIM contra la clave publicada y la política DMARC. *Ask the Agent…* abre una pestaña del
Agent sobre la carpeta, solo lectura, con un prompt de analista.

## Settings

**Edit → Settings…** (**Ctrl+,**; en macOS en el menú de la aplicación)
reúne todos los ajustes de axross en una ventana: a la izquierda las
categorías, a la derecha la página de la elegida y encima un campo que
encuentra un ajuste por su nombre (escribe *sudo*, *proxy* o *zoom*).

| Categoría | Ajustes |
|---|---|
| General | Idioma (al siguiente arranque), restaurar el layout de la última sesión al arrancar, cuándo un panel se vuelve activo (con clic o tras 0,5–3 s con el ratón dentro), ofrecer el tour Getting started en el siguiente arranque (ver [Manual y tours](#manual-y-tours)) |
| Appearance | Theme, compact mode, monochrome icons, icon colours (Theme default; Own colours in every theme - también en Hacker y Amber, que dibujan cada icono en un color; One colour a elegir), tamaño de letra (zoom), resaltar hidden files y su color (un color difícil de leer en el theme solo tras preguntar) |
| Toolbar | Agrupar los botones por categoría, mostrar el color de cada categoría detrás de sus botones, el color de cada categoría (Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions), *Reset to Defaults* |
| Files & Panes | Mostrar hidden files, open size limit, parallel transfers, workspaces en RAM (sí / no, límite de tamaño, memoria que queda libre) y ficheros temporales en RAM (al siguiente arranque) |
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
| Logging | El nivel general (DEBUG, INFO, WARNING, ERROR), un nivel por área (Inherit, un nivel u Off; las librerías third-party en WARNING), el tamaño y la rotación del log file, *Log to terminal (stderr)*, agrupar mensajes repetidos, *Reset to Defaults* (ver [Logging](#logging)) |

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

### Logging

Los caracteres de control, secuencias de escape y marcas bidi en lo que
se registra (nombres de ficheros remotos, respuestas de servidores) se
escriben escapados - en el fichero de log, el terminal, el dock Log y el
log de auditoría MCP -, así un nombre no puede falsear líneas ni colores
del log; los nombres remotos con CR, LF o caracteres C1 se rechazan.

La página **Logging** decide qué entra en el log - sin llenarlo de ruido.
Cada parte de axross pertenece a un área: Application, Protocols (una
entrada por familia: SFTP / SSH / SCP / rsync, SMB / DFS, FTP / TFTP,
WebDAV, cloud storage, NFS / iSCSI, correo y news, WinRM / WMI, bases de
datos, Git / SVN, devices, protocolos legacy, conexiones y proxy), Local
Files, Transfers, Indexing / Search, Analysis, Agent / LLM, MCP (client y
server), Scripting, Media / Audio / Voice, Update, Security, Terminal,
Extensions, User Interface y Third-Party Libraries (paramiko, smbprotocol,
urllib3 y requests, los SDK de cloud, Pillow, asyncio, ...). Un área está
en *Inherit* (el nivel del área de arriba, arriba del todo el nivel
general), DEBUG, INFO, WARNING, ERROR u *Off*. El nivel general es INFO;
las librerías third-party están en WARNING, así que DEBUG para SMB muestra
los pasos SMB de axross, no cada paquete de la librería. Un área en DEBUG
sigue un problema allí mientras el resto queda en INFO - sus líneas de
debug ni se generan mientras el área está más baja.

El log file es `~/.local/state/axross/logs/axross.log` (solo tú lo puedes
leer); rota a los 5 MiB y guarda 3 ficheros rotados - ambos se ajustan en
la página (1-100 MiB, 1-20 ficheros). *Log to terminal (stderr)* escribe
las mismas líneas en el terminal desde el que se arrancó axross.
*Collapse repeated messages* (activado, 10 s): un mensaje idéntico a uno
escrito hace menos que la ventana (misma área, nivel, texto y error) se
cuenta en vez de escribirse, y la cuenta sigue en una línea,
`Last message repeated 999 more times in 10.0 s: ...` - un timer que falla
cada 10 ms da dos líneas por ventana, no cien por segundo. *Reset to Defaults* muestra
los valores por defecto; OK o Apply los guardan. Cada cambio surte efecto
al momento y se guarda en `~/.config/axross/logging.json`.

`--debug` en la línea de comandos registra cada área de axross en DEBUG
durante esa ejecución y escribe en el terminal; `--verbose` sube cada área
a INFO como mínimo, también con terminal. Las librerías third-party
mantienen su nivel, y la página lo indica mientras rige un flag así.

*Tools → Network & Proxy…, LLM Profiles…, Agent Settings…, MCP Servers…, Metadata
Settings…* y *Extensions → Manage Extensions…* abren la ventana Settings en
su página. *View → Show Hidden Files* (**Ctrl+H**), *View → Theme* y *View
→ Zoom* siguen siendo interruptores rápidos; se guardan al momento, como la
página.

## Updates

**axross-base y packs.** `axross-base` contiene solo el núcleo; cada extra de pip, cada
extensión incluida y los grupos de funciones son *unidades* que añade desde su propia
release: *Help → Features… → Packs…* las lista con su tamaño; *Add* descarga los wheels
(de la release o el mismo fichero de PyPI) y comprueba la firma, el manifiesto y el
SHA-256 de cada wheel antes de descomprimir nada; *Remove* borra lo que ninguna otra
unidad necesita. Una unidad de wheels solo de Python puro se puede usar en el acto; una
con un wheel nativo, y quitar una, se aplican en el siguiente arranque. Una actualización
del binario trae antes las unidades instaladas de la nueva release; si el manifiesto de
packs de la release se volvió a emitir (misma versión, un pack corregido), *Help →
Features…* ofrece *Update packs*, comprobado igual.

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
  respuesta, también cuando axross está al día. Si `settings.json` no se
  puede escribir, la comprobación muestra igualmente su resultado y la
  escritura fallida va al log.
- **La ventana de update** muestra esta versión y la nueva, las release
  notes (mostradas como Markdown; nunca se cargan imágenes ni otros
  recursos de ellas, el HTML se muestra como texto y solo se abren los
  enlaces http y https, en el navegador) y un enlace a la página del
  release, y ofrece **Download and
  Install**, **Skip This Version** (ningún aviso más para esa versión;
  preguntando a mano se sigue ofreciendo) y **Remind Me Later** (ningún
  aviso hasta el siguiente arranque).
- **Download and Install** descarga el binario de este build (axross-full
  recibe axross-full, un build slim su binario slim), comprueba su SHA-256
  contra el `SHA256SUMS` del mismo release (y contra el digest propio de
  GitHub del archivo) y rechaza todo lo que no coincida: entonces no se
  sustituye nada y el archivo parcial se borra. Antes, el propio
  `SHA256SUMS` debe llevar una firma válida: `SHA256SUMS.sig` es una firma
  Ed25519 hecha con la release key de axross, cuya clave pública va
  integrada en axross. Un release sin ella, o con una que no verifica, se
  rechaza ("The update is refused: release X.Y.Z is not signed with the
  axross release key"): quien pudiera cambiar el release podría cambiar
  sus checksums, pero no crear esa firma. Un archivo verificado
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
`release-assets.githubusercontent.com` y `objects.githubusercontent.com`,
por https; cada redirect se
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
  una versión saltada, el último check), si el siguiente arranque ofrece el
  tour Getting started (`offer_tour_at_start`).
- `~/.config/axross/proxy.json`, `llm.json`, `extensions.json` — el proxy
  por defecto, los perfiles LLM, las extensions activadas (secretos en el
  keyring).
- `~/.config/axross/agent/voice.json` — los ajustes de Voice (`0o600`).
- `~/.config/axross/audio.json` — los ajustes de Audio: backend,
  dispositivo de salida y de entrada, volúmenes (`0o600`).
- `~/.config/axross/column_prefs.json` — orden, anchos y columnas
  ocultas, un solo archivo para todos los panels; un panel guarda solo lo
  que cambiaste en él, así que el cambio de otro panel se queda.
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
- Un fichero de configuración que no es JSON válido (una edición a mano
  fallida) nunca se sobrescribe: axross lo guarda como
  `NOMBRE.unreadable-<hora>-<id>` a su lado y empieza el fichero de nuevo;
  uno que no puede leer en absoluto (permisos) no se escribe.
- `~/.config/axross/logging.json` — los ajustes de Logging: nivel general, nivel por
  área, tamaño y rotación del log file, terminal, agrupar mensajes repetidos (`0o600`).
- `~/.local/state/axross/logs/axross.log` — log rotativo (5 MiB, 3 ficheros rotados
  salvo que *Edit → Settings… → Logging* diga otra cosa; `0o600`).

## A dónde ir después

- **¿Solo conectar?** [OAUTH_SETUP.md](../OAUTH_SETUP.md) recorre los
  registros de app de almacenamiento en la nube.
- **¿Operando en redes hostiles?** [OPSEC.md](OPSEC.md) lista cada
  fingerprint cliente-a-servidor que axross emite y cómo suprimirlo.
- **¿Manejar axross desde un LLM?** [MCP_es.md](MCP_es.md) es la
  referencia canónica del protocolo.
- **¿Escribir o activar extensiones?** [EXTENSIONS.md](EXTENSIONS.md)
  explica la confianza, la pausa y la `api` de las extensiones (en inglés).
- **¿Construir o contribuir?** [DEVELOPMENT.md](DEVELOPMENT.md) tiene
  la suite de tests, el compose del lab, y la matriz de cobertura.
- **¿Manual en alemán?** [USAGE_de.md](USAGE_de.md).
