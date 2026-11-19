#!/usr/bin/env python3
"""The screenshots of axross-markdown's README, made offscreen.

    QT_QPA_PLATFORM=offscreen python scripts/markdown_screenshots.py [FOLDER]

opens two documents (field notes with an alert, a table, a task list, code,
a definition and a footnote; a page of formulas) in the program's own
windows (ui.markdown_app: Open…, View, Export) in its Modern Light and Modern
Dark themes, and saves viewer-light.png, viewer-dark.png and viewer-math.png
into FOLDER (default: scripts/standalone_repo/axross-markdown/docs/screenshots,
whose README shows them). mdcat.png, the terminal's, is not made here.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

FIELD_NOTES = '''# Field notes: the backup server

The nightly job copies **every project** to the NAS and keeps *seven* generations.
Restore steps are in [RESTORE.md](RESTORE.md); the logs live in `/var/log/backup`.

> [!TIP]
> Run `backup --dry-run` first - it lists what would change and writes nothing.

## Schedule

| Job | When | Target | Kept |
|:--|:-:|:--|--:|
| Projects | 02:00 | `nas:/backup/projects` | 7 |
| Mail | 03:30 | `nas:/backup/mail` | 14 |
| Photos | Sunday | `s3://photos-archive` | 52 |

## Checklist

- [x] SSH key for the NAS in the agent
- [x] Snapshot before the upgrade
- [ ] Test a restore of `projects/website`

## The script

```python
def rotate(folder: Path, keep: int = 7) -> list[Path]:
    """Remove all but the newest *keep* generations."""
    old = sorted(folder.iterdir(), key=lambda p: p.stat().st_mtime)
    for path in old[:-keep]:
        shutil.rmtree(path)  # never follows a symlink
    return old[-keep:]
```

Term
:   A definition list explains a word.[^1]

[^1]: Footnotes are collected at the end of the page.
'''

MATH = r'''# Signals and series

A periodic signal is a sum of sines: the Fourier series of $f$ with period $2\pi$ is
$f(x) = a_0/2 + \sum_{n=1}^{\infty} (a_n \cos nx + b_n \sin nx)$.

$$
a_n = \frac{1}{\pi} \int_{-\pi}^{\pi} f(x) \cos(nx)\, dx
$$

## Energy

By Parseval's theorem the energy is the same in both domains:

$$
\int_{-\infty}^{\infty} |x(t)|^2 \, dt = \int_{-\infty}^{\infty} |X(f)|^2 \, df
$$

## A piecewise function

$$
f(x) = \begin{cases} x^2 & x \ge 0 \\ -x & x < 0 \end{cases}
$$

## A matrix

The rotation by $\theta$ in the plane:

$$
R(\theta) = \begin{pmatrix} \cos\theta & -\sin\theta \\ \sin\theta & \cos\theta \end{pmatrix}
$$
'''

#: (file, its text, theme, window size, the heading shown at the top - "" the page's start)
SHOTS = (
    ("viewer-light.png", "field-notes.md", FIELD_NOTES, "modern-light", (1180, 760), ""),
    ("viewer-dark.png", "field-notes.md", FIELD_NOTES, "modern-dark", (1180, 760), "the-script"),
    ("viewer-math.png", "math.md", MATH, "modern-light", (1180, 820), ""),
)


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else ROOT / "scripts/standalone_repo/axross-markdown/docs/screenshots"
    out.mkdir(parents=True, exist_ok=True)
    home = tempfile.mkdtemp(prefix="axross-md-shots-")
    os.environ["HOME"] = home  # (no settings of the user's: the theme is the shot's)
    os.environ["XDG_CONFIG_HOME"] = os.path.join(home, ".config")
    from PyQt6.QtWidgets import QApplication

    app = QApplication([sys.argv[0]])
    app.setApplicationName("axross-markdown")
    from ui import standalone_app
    from ui.markdown_app import MarkdownApp

    folder = Path(home) / "notes"
    folder.mkdir()
    for shot, name, text, theme, size, anchor in SHOTS:
        (folder / name).write_text(text, encoding="utf-8")
        standalone_app.apply_theme(app, theme, "axross-markdown")
        viewer = MarkdownApp().open_paths([str(folder / name)])[0]
        viewer.resize(*size)
        viewer.show()
        _wait(app, lambda: viewer.view._readable and viewer.view.markdown)
        if anchor:
            viewer.view.go_to_anchor(anchor, remember=False)
        _wait(app, lambda: False, 0.8)
        viewer.grab().save(str(out / shot))
        print("written", out / shot)
        viewer.close()
        viewer.deleteLater()
        _wait(app, lambda: False, 0.2)
    return 0


def _wait(app, done, seconds: float = 30.0) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end and not done():
        app.processEvents()
        time.sleep(0.01)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
