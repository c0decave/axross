"""lab_smoke.py — touch every available backend's root.

For every protocol that's actually installed (``axross.available_backends()``),
attempt the cheapest possible operation against it and report whether it
worked. A "lab is up" smoke test: useful as the first thing the CI
pipeline runs.

Doesn't try to authenticate — it walks profiles and connects only
where ``axross.open(<name>)`` is configured. Probes that need a live
remote (SFTP, S3, …) are surfaced with a one-line failure note.

Usage::

    report = smoke()
    for line in report:
        print(line)
"""
from __future__ import annotations


def smoke() -> list[str]:
    out: list[str] = []
    out.append(f"available backends: {axross.available_backends()}")
    out.append("")
    for name in axross.list_profiles():
        try:
            sess = axross.open(name)
        except (KeyError, OSError, ImportError) as exc:
            out.append(f"  ✗ {name}: {exc}")
            continue
        try:
            home = sess.home()
            sess.list_dir(home)
            out.append(f"  ✓ {name} listed {home}")
        except OSError as exc:
            out.append(f"  ✗ {name}: list_dir failed: {exc}")
        finally:
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
    return out
