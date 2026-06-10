# Pruebas de credenciales — fuerza bruta, password spray, enumeración de usuarios

[English](CRED_ATTACK.md) · [Deutsch](CRED_ATTACK_de.md) · [Español](CRED_ATTACK_es.md)

Axross expone una superficie pequeña de pruebas de credenciales
(`core.cred_attack`, accesible como `axross.bruteforce`,
`axross.spray` y `axross.enumerate_users`) para evaluaciones
**autorizadas** — pentests con permiso por escrito, autopruebas en
laboratorio y entornos CTF. Todo el módulo se niega a ejecutar a
menos que el llamador pase explícitamente `authorized=True`; esta
puerta es un rechazo duro, no una sugerencia educada, y no hay
override por variable de entorno.

> **Léeme antes de ejecutar.** Las pruebas de credenciales son
> intrusivas, ruidosas en la línea y fáciles de utilizar mal. Los
> defaults de abajo son conservadores por una razón. Si los aflojas,
> escribe en las notas del engagement *por qué* — el tú futuro querrá
> el comprobante.

---

## Qué hace la API

| Función | Patrón | Caso de uso |
|---|---|---|
| `axross.bruteforce(profile, users=…, passwords=…)` | itera `user × password` (user-major) | Un usuario objetivo, muchas contraseñas candidatas. O muchos usuarios cuando aceptas el riesgo de bloqueo per-user. |
| `axross.spray(profile, users=…, password=…)` | itera `password × user` (password-major) | Una contraseña contra un pool de usuarios — el patrón estándar contra AD / Microsoft 365 donde el bloqueo cuenta intentos por usuario y ventana. |
| `axross.enumerate_users(profile, candidates, method=…)` | oráculo por protocolo o timing estadístico | Probar qué candidatos existen en el objetivo *antes* de lanzar un spray. |

Las tres aceptan una instancia `ConnectionProfile` o el nombre de un
perfil guardado. Los ajustes de red (host, puerto, proxy, TLS) se
toman de la plantilla; el usuario y la contraseña se sobreescriben
por intento.

---

## Defaults OPSEC — qué obtienes out of the box

Los defaults están afinados para producir **la señal más pequeña
que aún cumple el trabajo**. Puedes sobreescribir cada uno por
llamada; el punto es que «no hacer nada» es el camino seguro.

| Default | Valor | Por qué |
|---|---|---|
| Puerta de autorización | `authorized=True` requerido | Rechazo de una línea contra el mal uso casual. Sin skip por env-var, sin «sí» recordado. |
| Rate-limit | 30 intentos / minuto | Un intento cada dos segundos se mezcla con reintentos de login por error humano. Más rápido viola reglas IDS basadas en honor en la mayoría de objetivos bien gestionados. |
| Presupuesto de timeout por intento | 10 s | Los intentos que vuelven después del presupuesto se marcan `ERROR`; el bloqueo duro sigue limitado por el timeout socket/connect de cada backend. |
| Abort por bloqueo | El primer `LOCKOUT` detiene el run | Una señal basta — las próximas dos serían violaciones de política. Aflójalo explícitamente si tu engagement letter lo permite. |
| Stop tras primer éxito por usuario | True | No sigas adivinando una vez que el usuario está dentro. |
| Manejo de contraseñas en logs | sólo prefijo SHA-256 | Las contraseñas en claro nunca llegan al logger estructurado. Las credenciales exitosas vuelven al llamador en claro — para eso vino. |
| Estado de resume | archivo JSON opt-in | Si necesitas sobrevivir a Ctrl-C pasa `state_file=…`; el archivo se reescribe atómicamente tras cada intento. Trátalo como sensible — lleva pares user+hash y la identidad del objetivo. |
| Modo de seguridad paranoid | rechaza todo el módulo | `AXROSS_SECURITY_MODE=paranoid` bloquea las pruebas de credenciales hasta que vuelvas a cambiar. |

---

## Brute-force vs. spray — elige uno

Comparten motor; sólo cambia el orden de iteración. Ese orden es la
diferencia entre un engagement silencioso y un ticket de helpdesk
por cuenta bloqueada.

* **Brute-force** (`axross.bruteforce`): prueba cada contraseña para
  el usuario 1, luego usuario 2, etc. Atraviesa la ventana de
  bloqueo de un usuario *rápido*. Adecuado cuando tienes un único
  usuario y una lista candidata larga, o cuando el objetivo no tiene
  política de bloqueo (volcado offline de KDC, workstation de lab).

* **Spray** (`axross.spray`): prueba una contraseña contra cada
  usuario, luego la siguiente. Cada usuario ve un intento por pasada;
  las ventanas de bloqueo rara vez se llenan. Adecuado para AD /
  Entra ID / OWA / IMAP en MTA real / WebDAV en Nextcloud / SMB en
  domain-member.

Si no tienes una razón fuerte para brute-force: **spray**.

Para objetivos SSH/SCP sigue aplicando la política de host-key. Si la
clave del host aún no es de confianza, pasa un callback explícito
`on_unknown_host=` con la regla de confianza del engagement; la
superficie de pruebas de credenciales no confía hosts SSH
automáticamente.

El módulo falla cerrado para protocolos/perfiles donde las contraseñas
candidatas no se consumen durante el connect (por ejemplo TFTP/NFS/RamFS,
cloud drives sólo OAuth, o perfiles Azure que ya llevan connection
string/SAS token). Así evitamos falsos «success» en transportes que no
autentican realmente el secreto candidato.

---

## Clasificación de bloqueo — la heurística

`core.cred_attack.classify_error()` inspecciona el texto de la
excepción de cada intento fallido y decide:

* `LOCKOUT` — strings como `account locked`,
  `STATUS_ACCOUNT_LOCKED_OUT`, `too many login attempts`,
  `rate limit`, `throttle`, `try again later`, fraseo de IIS / Postfix /
  Dovecot / OpenLDAP / sshd-PAM / Cisco IOS, …
* `FAILED` — `authentication failed`, `permission denied`,
  `no such user`, `STATUS_LOGON_FAILURE`, `incorrect password`, …
* `ERROR` — connection refused, timeout, fallo DNS, broken pipe, …
* default → `ERROR` (un fraseo desconocido puede ser crash de backend,
  problema TLS, fallo de proxy o bug de parser; no se cuenta en silencio
  como contraseña incorrecta).

La heurística es heurística a propósito. La lista de marcadores está
en `core/cred_attack.py`; con un objetivo que use texto a medida la
extiendes en runtime:

```python
from core.cred_attack import register_marker

# Un appliance custom que dice "ACCOUNT FROZEN" al bloquear
# y "BAD CREDS" al fallo de auth normal.
register_marker("account frozen", kind="lockout")
register_marker("bad creds", kind="auth_fail")
```

El orden importa: los marcadores de bloqueo se chequean primero, así
que «too many failed login attempts — account locked out» se
clasifica como LOCKOUT (contiene `failed`, pero machea LOCKOUT
primero).

---

## Enumeración de usuarios

Dos métodos ortogonales:

### Oráculo (`method="oracle"` o `"auto"` con oráculo registrado)

El protocolo filtra existencia de usuario a través de una diferencia
en el comportamiento de error entre usernames conocidos y
desconocidos. Oráculos integrados:

| Protocolo | Mecanismo | Confianza |
|---|---|---|
| `pop3` | fraseo de respuesta `USER` / `PASS` — `no such user` vs `auth failed` | 0.7–0.9 |
| `ftp` / `ftps` | `USER` devuelve `331 Password required` (conocido) vs `530 user cannot log in` (desconocido) | 0.7–0.8 |

Añade los tuyos en runtime con `register_oracle(protocol, callable)`.
Firma del callable: `(profile, candidates: list[str], timeout_s: float, *, rate_limiter=None, jitter_s=0.0) -> list[EnumResult]`.
Los oráculos custom antiguos de tres argumentos siguen funcionando,
pero axross registra un warning porque esos callables deben aplicar su
propio pacing.

### Timing (`method="timing"` o fallback de `"auto"`)

Genérico. Funciona contra cualquier backend alcanzable por
`ConnectionManager`. Para cada candidato el loop dispara
`timing_samples` (default 5) intentos de login con contraseña basura
y registra el tiempo de pared. Por candidato toma la **mediana**
(robusta frente a outliers); entre candidatos calcula la mediana
global + desviación absoluta mediana (MAD), y marca candidatos cuya
mediana excede `global + 3·MAD` como «probable existe» (el servidor
realmente comparó hash) y los que están bajo `global − 3·MAD` como
«probable no existe» (cortocircuito). Candidatos dentro del piso de
ruido reciben `confidence=0`.

Tanto los probes de oráculo como los intentos de timing usan el mismo
default `rate_per_min` que `spray`/`bruteforce` (30/min). Timing consume
un token por intento de login, así que `timing_samples=5` implica al
menos cinco probes pausados por candidato.

Caveats:

* Los resultados de timing tienen tasa real de falsos positivos.
  Trátalos como pista, no como prueba. Valida los hits fuertes con un
  único pase de spray sobre sólo esos usernames.
* Rate-limiting del lado del servidor aplana las diferencias. Si el
  objetivo está detrás de un WAF que inyecta delay sintético, timing
  está muerto — usa la vía de oráculo o salta la enumeración.
* Si puedes evitar enumerar, no enumeres. Usa una lista que ya tengas
  de OSINT / pretexto de phishing. La enumeración crea líneas extra
  de log en el objetivo.

---

## Resume tras Ctrl-C

Pasa `state_file="/ruta/a/run.json"` a `bruteforce` o `spray`. El
runner:

1. Carga el estado previo al inicio. Si el archivo apunta a otro
   host/puerto/protocolo se ignora (warning en log) y se inicia un
   run nuevo.
2. Tras cada intento reescribe el archivo atómicamente con el
   conjunto running de pares `[username, password_hash]` ya
   intentados y el conjunto running de éxitos.
3. En un run posterior, se saltan los pares `(user, hash)` ya
   probados y se emite outcome `SKIPPED` para ellos.

Como el archivo de estado guarda hashes, no contraseñas en claro, es
seguro mover entre cajas de operador — pero el archivo lleva
identidad del objetivo (host/puerto/protocolo) y todos los usernames;
trátalo como dato sensible del engagement.

---

## Callbacks de progreso

`progress=callable` se dispara con cada `AttemptOutcome` (o
`EnumResult`). Útil para UIs en vivo, ruteo de logs estructurados o
dashboards externos:

```python
from core.cred_attack import AttemptOutcome, AttemptResult

def show(outcome: AttemptOutcome) -> None:
    if outcome.result is AttemptResult.SUCCESS:
        print(f"  ✓ {outcome.username}")
    elif outcome.result is AttemptResult.LOCKOUT:
        print(f"  ✗ LOCKOUT user={outcome.username}")

axross.spray(
    profile, users=[…], password="Spring2026!",
    progress=show, authorized=True,
)
```

Excepciones en el callback se logean como `WARNING` y se tragan; el
run no aborta.

---

## Ejemplos

Scripts ejecutables bajo [`examples/`](../examples/):

* [`examples/spray_pop3.py`](../examples/spray_pop3.py) — spray de una contraseña contra un pool POP3.
* [`examples/bruteforce_ssh.py`](../examples/bruteforce_ssh.py) — brute-force contra una cuenta SSH con lista candidata y archivo de resume.
* [`examples/enum_pop3.py`](../examples/enum_pop3.py) — oráculo de user-enum POP3, luego spray sólo contra los hits.
* [`examples/dry_run.py`](../examples/dry_run.py) — generar plan de run sin disparar paquetes.

Todos los ejemplos sólo asignan `authorized=True` tras un prompt
literal de confirmación — cópialos como punto de partida, pero
mantén el prompt.

---

## Reglas duras

No son sugerencias:

1. **Autorización por escrito.** El «adelante» verbal de un cliente
   pagador no es un documento de scope. Ten el engagement letter en
   mano antes de llamar a estas funciones contra un objetivo de
   tercero.
2. **Sin objetivos terceros en tests.** La suite de tests propia del
   módulo nunca se conecta a internet abierta — usa stubs in-process.
   No la cambies.
3. **No bucles sobre `ERROR`.** Un fallo de red no es prueba; el
   runner ya NO lo cuenta contra el budget de bloqueo, pero si los
   outcomes `ERROR` empiezan a dominar, **detén el run** e
   investiga. Un proxy mal configurado, una VPN caída o el WAF
   anti-bot del objetivo pueden hacer parecer cada intento transitorio
   mientras el objetivo realmente rate-limita tu IP origen.
4. **No corras con `abort_on_lockout=False` «por velocidad».** Esa
   flag existe para el engagement donde el cliente dice explícitamente
   «puedes agotar la política de bloqueo como parte del test»; no es
   un bypass del throttle.
5. **Trata la lista de éxitos como material comprometido.** Las
   contraseñas en claro vuelven al llamador — escríbelas
   inmediatamente a un archivo sellado, nunca a una shell history o
   a un proceso invocado vía `subprocess.run([…, password])`.

---

## Ver también

* [`docs/OPSEC.md`](OPSEC.md) — qué revela el cliente axross al servidor.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — referencia completa de la API `axross.*`.
* [`docs/RED_TEAM_NOTES.md`](RED_TEAM_NOTES.md) — revisión adversaria de cada backend.
* [`SECURITY.md`](../SECURITY.md) — política de divulgación de vulnerabilidades.
