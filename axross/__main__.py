"""Allow ``python -m axross`` to behave like the console script."""

from __future__ import annotations

from axross.cli import main

raise SystemExit(main())
