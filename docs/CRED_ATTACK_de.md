# Credential-Tests — Brute-Force, Spray, User-Enumeration

[English](CRED_ATTACK.md) · [Deutsch](CRED_ATTACK_de.md) · [Español](CRED_ATTACK_es.md)

Axross liefert eine kleine Credential-Test-Oberfläche
(`core.cred_attack`, exponiert als `axross.bruteforce`,
`axross.spray` und `axross.enumerate_users`) für **autorisierte**
Assessments — Pentests mit schriftlicher Einwilligung, Lab-Selbsttests
und CTF-Umgebungen. Das gesamte Modul verweigert die Ausführung,
solange der Aufrufer nicht explizit `authorized=True` übergibt; dieser
Gate ist eine harte Verweigerung, kein höflicher Hinweis, und es gibt
**keinen** Override über Umgebungsvariablen.

> **Vor dem Lauf lesen.** Credential-Tests sind invasiv, laut auf der
> Leitung und leicht zu missbrauchen. Die unten beschriebenen Defaults
> sind aus gutem Grund konservativ. Wenn du sie lockerst, schreib in
> die Engagement-Notizen *warum* — dein zukünftiges Ich will den Beleg.

---

## Was die API tut

| Funktion | Muster | Anwendung |
|---|---|---|
| `axross.bruteforce(profile, users=…, passwords=…)` | iteriert `user × password` (user-major) | Ein Zielbenutzer, viele Passwortkandidaten. Oder viele Benutzer, wenn du das Per-User-Lockout-Risiko akzeptierst. |
| `axross.spray(profile, users=…, password=…)` | iteriert `password × user` (password-major) | Ein Passwort gegen einen User-Pool — das Standardmuster gegen AD / Microsoft 365, wo Lockout per-User-pro-Zeitfenster zählt. |
| `axross.enumerate_users(profile, candidates, method=…)` | protokollspezifisches Oracle oder statistisches Timing | Vorab prüfen, welche Kandidaten am Ziel existieren, *bevor* du einen Spray fährst. |

Alle drei akzeptieren entweder eine `ConnectionProfile`-Instanz oder
den Namen eines gespeicherten Profils. Netzwerk-Einstellungen (Host,
Port, Proxy, TLS) werden aus der Vorlage übernommen; Username und
Passwort werden pro Versuch überschrieben.

---

## OPSEC-Defaults — was du out of the box bekommst

Die Defaults zielen auf **das kleinstmögliche Signal, das den Job
erledigt**. Jede Einstellung ist pro Aufruf überschreibbar; der Punkt
ist, dass „nichts ändern" der sichere Weg ist.

| Default | Wert | Warum |
|---|---|---|
| Autorisierungs-Gate | `authorized=True` Pflicht | Einzeiler-Verweigerung gegen Zufallsmissbrauch. Kein Env-Var-Skip, kein gespeichertes „ja". |
| Rate-Limit | 30 Versuche / Minute | Ein Versuch alle zwei Sekunden geht in normalem User-Tippfehler-Login auf. Schneller verletzt Honor-System-IDS-Regeln auf den meisten gut gepflegten Zielen. |
| Per-Versuch-Timeout-Budget | 10 s | Versuche, die erst nach dem Budget zurückkommen, werden `ERROR`; hartes Blockieren hängt weiterhin am Socket-/Connect-Timeout des jeweiligen Backends. |
| Lockout-Abort | Erstes `LOCKOUT` stoppt den Lauf | Ein Signal reicht — die nächsten zwei wären Policy-Verletzungen. Lockern darfst du explizit, wenn dein Engagement-Letter es deckt. |
| Stop bei erstem Erfolg pro User | True | Nicht weiterraten, wenn ein User drin ist. |
| Passwort-Handling im Log | nur SHA-256-Prefix | Klartext-Passwörter erreichen den strukturierten Logger nie. Erfolgreiche Credentials kommen im Klartext zurück an den Aufrufer — dafür ist er hier. |
| Resume-State | opt-in JSON-Datei | Wenn du Ctrl-C überleben musst, übergib `state_file=…`; die Datei wird nach jedem Versuch atomar neu geschrieben. Sensibel behandeln — sie trägt User+Passwort-Hash-Paare und Zielidentität. |
| Paranoid-Security-Mode | verweigert das ganze Modul | `AXROSS_SECURITY_MODE=paranoid` blockiert Credential-Tests, bis du wieder umstellst. |

---

## Brute-Force vs. Spray — wähle eines

Beide teilen sich die Engine; nur die Iterationsreihenfolge ändert
sich. Diese Reihenfolge ist der Unterschied zwischen einem leisen
Engagement und einem account-locked Helpdesk-Ticket.

* **Brute-Force** (`axross.bruteforce`): probiere alle Passwörter für
  User 1, dann User 2 usw. Geht *schnell* durch das Lockout-Fenster
  eines Users. Richtig, wenn du einen einzelnen User hast und eine
  lange Kandidatenliste — oder wenn das Ziel keine Lockout-Policy hat
  (Offline-KDC-Dump, Lab-Workstation).

* **Spray** (`axross.spray`): probiere ein Passwort gegen jeden User,
  dann das nächste Passwort. Jeder User sieht einen Versuch pro
  Durchlauf; Lockout-Fenster füllen sich selten. Richtig für
  AD / Entra ID / OWA / IMAP-on-real-MTA / WebDAV-on-Nextcloud /
  SMB-on-domain-member.

Wenn du keinen starken Grund für Brute-Force hast: **Spray**.

Für SSH/SCP-Ziele gilt weiterhin die Host-Key-Policy. Wenn der Host-Key
noch nicht vertraut ist, übergib einen expliziten `on_unknown_host=`-
Callback mit der Trust-Regel deines Engagements; Credential-Tests
vertrauen SSH-Hosts nicht automatisch.

Das Modul failt geschlossen für Protokolle/Profile, bei denen
Kandidatenpasswörter beim Connect gar nicht verbraucht werden (z. B.
TFTP/NFS/RamFS, OAuth-only Cloud-Drives oder Azure-Profile mit bereits
gesetztem Connection-String/SAS-Token). So vermeiden wir
False-Positive-„Success" auf Transporten, die das Kandidaten-Secret
nicht wirklich authentisieren.

---

## Lockout-Klassifikator — die Heuristik

`core.cred_attack.classify_error()` inspiziert den Exception-Text
jedes fehlgeschlagenen Versuchs und entscheidet:

* `LOCKOUT` — Strings wie `account locked`, `STATUS_ACCOUNT_LOCKED_OUT`,
  `too many login attempts`, `rate limit`, `throttle`, `try again later`,
  Wording von IIS / Postfix / Dovecot / OpenLDAP / sshd-PAM / Cisco IOS, …
* `FAILED` — `authentication failed`, `permission denied`, `no such user`,
  `STATUS_LOGON_FAILURE`, `incorrect password`, …
* `ERROR` — connection refused, timeout, DNS-Fehler, broken pipe, …
* default → `ERROR` (unbekanntes Wording kann Backend-Crash, TLS-Thema,
  Proxy-Fehler oder Parser-Bug sein; das zählt nicht still als falsches
  Passwort).

Die Heuristik ist absichtlich heuristisch. Die Marker-Liste steht in
`core/cred_attack.py`; bei einem Ziel mit eigenem Wording erweiterst
du sie zur Laufzeit:

```python
from core.cred_attack import register_marker

# Eine Custom-Appliance, die "ACCOUNT FROZEN" beim Lockout
# und "BAD CREDS" beim normalen Auth-Fail meldet.
register_marker("account frozen", kind="lockout")
register_marker("bad creds", kind="auth_fail")
```

Reihenfolge zählt: Lockout-Marker werden zuerst geprüft, sodass
„too many failed login attempts — account locked out" als LOCKOUT
klassifiziert wird (enthält zwar `failed`, matcht aber zuerst LOCKOUT).

---

## User-Enumeration

Zwei orthogonale Methoden:

### Oracle (`method="oracle"` oder `"auto"` mit registriertem Oracle)

Das Protokoll leakt User-Existenz über unterschiedliches
Fehlerverhalten zwischen bekannten und unbekannten Usernames.
Eingebaute Oracles:

| Protokoll | Mechanismus | Konfidenz |
|---|---|---|
| `pop3` | `USER` / `PASS` Antwort-Wording — `no such user` vs. `auth failed` | 0.7–0.9 |
| `ftp` / `ftps` | `USER` liefert `331 Password required` (bekannt) vs. `530 user cannot log in` (unbekannt) | 0.7–0.8 |

Eigene Oracles registrierst du zur Laufzeit über
`register_oracle(protocol, callable)`. Signatur des Callables:
`(profile, candidates: list[str], timeout_s: float, *, rate_limiter=None, jitter_s=0.0) -> list[EnumResult]`.
Ältere Drei-Argument-Custom-Oracles laufen weiter, aber axross loggt
eine Warnung, weil diese Callables ihr Pacing selbst übernehmen müssen.

### Timing (`method="timing"` oder `"auto"`-Fallback)

Generisch. Funktioniert mit jedem über `ConnectionManager`
erreichbaren Backend. Pro Kandidat feuert die Schleife
`timing_samples` (Default 5) Login-Versuche mit Junk-Passwort und
misst die Wall-Clock-Zeit. Pro Kandidat wird der **Median** genommen
(robust gegen Ausreißer); über alle Kandidaten werden globaler Median
+ Median-Absolute-Deviation (MAD) berechnet, und Kandidaten mit
Median > `global + 3·MAD` gelten als „existiert wahrscheinlich"
(Server hat tatsächlich Hash verglichen), Kandidaten unter
`global − 3·MAD` als „existiert wahrscheinlich nicht" (Short-Circuit).
Kandidaten im Rauschband bekommen `confidence=0`.

Oracle-Probes und Timing-Versuche laufen beide über denselben
`rate_per_min`-Default wie `spray`/`bruteforce` (30/min). Timing zieht
einen Token pro Login-Versuch, also bedeutet `timing_samples=5`
mindestens fünf gedrosselte Probes pro Kandidat.

Caveats:

* Timing-Resultate haben eine echte Falsch-Positiv-Rate. Behandle sie
  als Hinweis, nicht als Beweis. Validiere starke Hits mit einem
  einzelnen Spray-Pass auf nur diese Usernames.
* Server-seitiges Rate-Limiting nivelliert Timing-Unterschiede. Wenn
  ein WAF synthetische Verzögerungen einfügt, ist Timing tot — nimm
  den Oracle-Pfad oder lass die Enumeration weg.
* Wenn du nicht enumerieren *musst*, lass es. Verwende lieber eine
  Liste aus OSINT / Phishing-Pretext-Recon. Enumeration erzeugt extra
  Logzeilen am Ziel.

---

## Resume nach Ctrl-C

Übergib `state_file="/pfad/zum/run.json"` an `bruteforce` oder
`spray`. Der Runner:

1. Lädt einen vorhandenen State zu Beginn. Wenn die Datei ein anderes
   Host/Port/Protokoll referenziert, wird sie ignoriert (Warnung im
   Log) und ein frischer Lauf gestartet.
2. Schreibt nach jedem Versuch die Datei atomar neu mit der laufenden
   Menge der `[username, password_hash]`-Paare und der Erfolgsmenge.
3. Beim nächsten Lauf werden bereits versuchte `(user, hash)`-Paare
   übersprungen und als `SKIPPED` markiert.

Da die State-Datei nur Hashes hält, ist sie zwischen Operator-Boxen
verschiebbar — die Datei trägt aber Zielidentität (Host/Port/Protokoll)
und alle Usernames; behandle sie als sensible Engagement-Daten.

---

## Progress-Callbacks

`progress=callable` wird mit jedem `AttemptOutcome` (bzw.
`EnumResult`) aufgerufen — nützlich für Live-UIs, strukturiertes
Log-Routing oder externe Dashboards:

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

Exceptions im Callback werden als `WARNING` geloggt und geschluckt;
der Lauf bricht nicht ab.

---

## Beispiele

Lauffähige Skripte unter [`examples/`](../examples/):

* [`examples/spray_pop3.py`](../examples/spray_pop3.py) — Single-Password-Spray gegen einen POP3-Mailbox-Pool.
* [`examples/bruteforce_ssh.py`](../examples/bruteforce_ssh.py) — Brute-Force gegen einen SSH-Account mit Kandidatenliste und Resume-Datei.
* [`examples/enum_pop3.py`](../examples/enum_pop3.py) — POP3-User-Enum-Oracle, dann Spray nur gegen die Hits.
* [`examples/dry_run.py`](../examples/dry_run.py) — Run-Plan erzeugen ohne Pakete zu feuern.

Alle Beispiele setzen `authorized=True` erst nach einem expliziten
Bestätigungs-Prompt — kopier sie als Startpunkt, aber behalte den
Prompt.

---

## Harte Regeln

Das hier sind keine Vorschläge:

1. **Autorisierung schriftlich.** Das mündliche „mach mal" eines
   zahlenden Kunden ist kein Scope-Dokument. Halte den
   Engagement-Letter in der Hand, bevor du diese Funktionen gegen ein
   Drittziel aufrufst.
2. **Keine Drittziele in Tests.** Die eigene Test-Suite des Moduls
   verbindet sich nie ins offene Netz — sie nutzt In-Process-Stubs.
   Bitte nicht ändern.
3. **Nicht auf `ERROR` loopen.** Ein Netzwerkfehler ist nicht
   beweiskräftig; der Runner zählt ihn nicht aufs Lockout-Budget,
   aber wenn `ERROR`-Outcomes dominieren, **stoppe den Lauf** und
   untersuche. Ein falsch konfigurierter Proxy, ein abgerissenes VPN
   oder das Anti-Bot-WAF des Ziels lassen jeden Versuch transient
   aussehen, während das Ziel deine Quell-IP rate-limitet.
4. **Nicht mit `abort_on_lockout=False` „für Speed".** Dieses Flag
   existiert für das Engagement, in dem der Kunde explizit „du darfst
   die Lockout-Policy als Teil des Tests ausschöpfen" sagt; es ist
   kein Throttle-Bypass.
5. **Erfolgs-Liste als kompromittiertes Material behandeln.**
   Klartext-Passwörter werden zurückgegeben — direkt in eine
   verschlossene Datei schreiben, nie in Shell-History oder über
   `subprocess.run([…, password])`.

---

## Siehe auch

* [`docs/OPSEC.md`](OPSEC.md) — was der axross-Client dem Server verrät.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — vollständige `axross.*`-API-Referenz.
* [`docs/RED_TEAM_NOTES.md`](RED_TEAM_NOTES.md) — adversariale Review jedes Backends.
* [`SECURITY.md`](../SECURITY.md) — Vulnerability-Disclosure-Policy.
