# Contributing to Axross

Thanks for considering a contribution. Axross is an Apache-2.0 licensed
multi-protocol file manager; the ground rules below keep the project
sustainable and predictable for everyone.

## Licensing of contributions

By submitting a pull request, you agree that your contribution is provided
under the terms of the Apache License 2.0 (see [LICENSE](LICENSE)) and that
you have the right to submit it. Per Apache-2.0 §5, every contribution is
automatically licensed under the same terms as the project — no separate CLA
is required for normal contributions.

If your contribution includes code you did not author (vendored snippets,
translated code, etc.), flag it in the PR description with the original
source and its license so we can verify compatibility with Apache-2.0 before
merge.

## What's in scope

- Fixes for any backend listed in the protocol table.
- New backends that follow the `FileBackend` protocol in `core/backend.py`.
- UI / UX improvements (keyboard shortcuts, dialog ergonomics, accessibility).
- MCP tool additions that compose cleanly with the existing surface.
- Hardening tests (`tests/test_hardening_regressions.py`) that cover a real
  attack class; generic "it doesn't crash" tests are lower priority.
- Translation updates for README and user-facing messages.

## What's out of scope

- Features that require bundling additional heavy SDKs by default. Put them
  behind a new optional extra in `pyproject.toml` and keep the base install
  slim.
- Changes that degrade the safe-extraction guards in `core/archive.py`,
  the MCP root-traversal guard, or the profile-field keyring routing
  without explicit justification.
- Telemetry / phone-home / auto-update code of any kind.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
pip install -r dev-requirements.txt
```

For the protocol lab:

```bash
cd tests/docker && docker compose up -d --build
```

See [INSTALL.md](INSTALL.md) for the canonical install flow.

## Running tests

Host suite (no Docker required):

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q \
    tests/test_hardening_regressions.py tests/test_regressions.py \
    tests/test_new_features.py tests/test_backend_regressions.py \
    tests/test_pane_layout_regressions.py tests/test_e2e.py
```

Protocol lab (needs `docker compose up -d --build` first):

```bash
.venv/bin/pytest tests/test_protocols.py tests/test_network.py
```

PRs must pass the host suite. Lab tests are best-effort because not every
reviewer has the lab stood up — your PR description should state which
lab sections you ran locally.

## Code style

- Python: `ruff` is the only style gate. `ruff check .` must pass.
- Line length 100 (configured in `pyproject.toml`).
- Keep dependencies minimal. New runtime deps need a justification; new
  optional extras are preferred over base-install additions.
- Tests: mirror the module layout, one test file per module where
  reasonable. Use `QT_QPA_PLATFORM=offscreen` for any UI test.

## Commits and PRs

- One commit per logical feature. Rebase before opening the PR.
- Subject line: imperative, under 72 chars. Body wraps at 72.
- Reference the issue number in the body if applicable (`closes #123`).
- PR description states: what changed, why, how it was tested, and any
  follow-up items you deliberately deferred.

## Security issues

Do not open a public issue for anything with exploit potential — email
[SECURITY.md](SECURITY.md) has the disclosure contact and timeline.
