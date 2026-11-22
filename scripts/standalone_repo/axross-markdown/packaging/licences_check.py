"""The release's check that a binary carries its licences: THIRD_PARTY_LICENSES.txt (what it contains,
PyQt6's GPL-3.0 and Qt's LGPL-3.0, where the source code is) as Help > About reads it, and the
interpreter's LICENSE.txt (packaging/axross-markdown.spec). Run inside the binary:
AXROSS_BUNDLE_SMOKE=1 axross-markdown --script packaging/licences_check.py"""

import os
import sys

try:  # (the program's own modules: axross-markdown's - axross's when it is run in axross)
    from axross_markdown._ax.ui import markdown_about
except ImportError:
    from ui import markdown_about

path = markdown_about.licences_path()
assert path is not None and path.name == "THIRD_PARTY_LICENSES.txt", path
text = markdown_about.licences_text()
for needle in ("GNU GENERAL PUBLIC LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE", "Source code",
               "Apache License"):
    assert needle in text, needle
if getattr(sys, "frozen", False):
    python = os.path.join(sys._MEIPASS, "licenses", "python", "LICENSE.txt")  # noqa: SLF001
    assert os.path.isfile(python), python
    if sys.platform.startswith("linux"):  # (the build machine's libraries in it: each with its licence and source)
        system = os.path.join(sys._MEIPASS, "licenses", "system")  # noqa: SLF001
        index = open(os.path.join(system, "INDEX.txt"), encoding="utf-8").read()
        bundled = [name for name in os.listdir(sys._MEIPASS) if ".so" in name]  # noqa: SLF001
        assert not any(name.startswith("libcups.so") for name in bundled), "libcups.so.2 is bundled"
        for line in index.splitlines():
            if "licences: licenses/system/" in line:
                text = line.rsplit("licenses/system/", 1)[1].strip()
                assert os.path.isfile(os.path.join(system, text)), text
        print("system libraries noted:", index.count("    source  "))
else:
    print("not a frozen build: the binary's own files are not the ones tested", file=sys.stderr)
print("licences carried:", len(text), "characters")
