"""The release's smoke test of an SVG: drawn as the window draws one - in a
child the one-file program starts as itself with --svg-worker
(core.svg_worker), its bootloader between the two. Run inside the binary:
AXROSS_BUNDLE_SMOKE=1 axross-markdown --script packaging/svg_check.py"""

import sys

try:  # (the program's own modules: axross-markdown's - axross's when it is run in axross)
    from axross_markdown._ax.core.svg_worker import render_png
except ImportError:
    from core.svg_worker import render_png

SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20">'
       b'<rect width="40" height="20" fill="#3b5bdb"/></svg>')

if not getattr(sys, "frozen", False):
    print("not a frozen build: the --svg-worker path is not the one tested", file=sys.stderr)
png = render_png(SVG, 64)
assert png[:8] == b"\x89PNG\r\n\x1a\n", png[:16]
print("svg drawn:", len(png), "bytes")
