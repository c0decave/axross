# `examples/` — runnable axross scripts

Small, self-contained Python scripts that exercise specific axross
features. Copy any of them as a starting point for your own work.
The focused API examples under [`scripting_api/`](scripting_api/) are
imported and executed by the test suite; the credential-testing
examples remain operator-driven because they ask for live
authorisation before sending attempts.

Each script targets a configurable host (`TARGET_HOST = "..."` near the
top), takes a literal confirmation prompt before doing anything
intrusive, and is opinionated about safe defaults so you can read
through it once and trust what it will fire on the wire.

| Script | What it does |
|---|---|
| [`spray_pop3.py`](spray_pop3.py) | Single-password spray against a POP3 mailbox pool. The default rate (30/min) and one-attempt-per-user-per-pass pattern is the conservative AD/M365-style safe default. |
| [`bruteforce_ssh.py`](bruteforce_ssh.py) | Brute-force one SSH account with a candidate-list and a resume file. Stops on the first lockout signal. |
| [`enum_pop3.py`](enum_pop3.py) | POP3 user-enumeration via the `USER`/`PASS` oracle, then sprays only the high-confidence hits. |
| [`dry_run.py`](dry_run.py) | Generates a credential-test plan and prints what *would* be tried, without firing any packets. Useful to sanity-check wordlists. |
| [`scripting_api/`](scripting_api/) | Runnable examples for the public `axross.*` scripting API, including local tests and Docker-lab protocol smokes. |

## Running

The scripts are plain Python and import the in-repo `axross` package.
Run them from the source checkout, with the same virtualenv you use
for `axross`:

```bash
cd /path/to/axross
python examples/spray_pop3.py
```

They emit progress to stdout and write the structured outcome via the
standard `core.cred_attack` logger; raise the log level if you want
the per-attempt classification:

```bash
AXROSS_LOGLEVEL=INFO python examples/spray_pop3.py
```

(Or configure `logging.basicConfig(level=logging.INFO)` inline — these
are example scripts, not framework code.)

## Authorisation

Every example sets `authorized=True` only after a literal y/N prompt
that names the target host. **Do not delete that prompt** when copying
the script for your own engagement — see
[`docs/CRED_ATTACK.md`](../docs/CRED_ATTACK.md) for why the gate is a
hard refusal and not a polite hint.

## Wordlists

The scripts ship with **tiny inline lists** (3–5 candidate users,
3–5 candidate passwords) so you can run them against a lab target and
see the full pipeline without leaking expectations about real
operations. For a real engagement, replace the inline lists with paths
to your own files — axross does not ship a wordlist source and never
fetches one from the network.
