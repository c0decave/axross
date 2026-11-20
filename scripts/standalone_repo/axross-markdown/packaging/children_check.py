"""The release's smoke test of the children the program starts as itself: a
YAML and a Python block lexed by --lex-worker (their colours asserted), a
PNG decoded by --image-worker. Run inside the binary:
AXROSS_BUNDLE_SMOKE=1 axross-markdown --script packaging/children_check.py
(packaging/svg_check.py checks --svg-worker)."""

import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:  # (the program's own modules: axross-markdown's - axross's when it is run in axross)
    from axross_markdown._ax.core import lex_worker, previews
    from axross_markdown._ax.core.local_fs import LocalFS
except ImportError:
    from core import lex_worker, previews
    from core.local_fs import LocalFS

if not getattr(sys, "frozen", False):
    print("not a frozen build: the children's frozen path is not the one tested", file=sys.stderr)

from pygments.token import Keyword, Name

yaml = lex_worker.lex("YAML", "name: build\non:\n  push: [main]\nretries: 3\n", "default")
assert any(ttype in Name.Tag or ttype in Keyword for _at, ttype, _n in yaml), yaml
python = lex_worker.lex("Python", "def f(x):\n    return x\n", "default")
assert any(ttype in Keyword for _at, ttype, _n in python) and any(ttype in Name.Function for _at, ttype, _n in python)
print("lexed:", len(yaml), "yaml tokens,", len(python), "python tokens")

from PyQt6.QtGui import QColor, QImage

folder = tempfile.mkdtemp(prefix="axross-children-")
path = os.path.join(folder, "check.png")
picture = QImage(40, 20, QImage.Format.Format_RGB32)
picture.fill(QColor("#3b5bdb"))
assert picture.save(path, "PNG")
image = previews.decode_image(LocalFS(), path)
assert not image.isNull() and (image.width(), image.height()) == (40, 20), (image.width(), image.height())
print("image decoded:", image.width(), "x", image.height())
lex_worker.close_pool()
print("children checked")
