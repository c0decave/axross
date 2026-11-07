"""Regenerate core/bluetooth_companies.py from an installed Bumble.

    pip install bumble && python scripts/gen_bt_companies.py
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

from bumble.company_ids import COMPANY_IDENTIFIERS

HEADER = '''# Bluetooth SIG company identifiers -> company names.
#
# Taken from Bumble {version} (bumble/company_ids.py), Copyright 2021-2022 Google LLC,
# licensed under the Apache License, Version 2.0
# (https://www.apache.org/licenses/LICENSE-2.0). Bumble generates the list
# from the Bluetooth SIG's assigned numbers. Not edited by hand: regenerate
# with scripts/gen_bt_companies.py.
"""The company of a BLE advertisement's manufacturer data (its 16-bit key)."""

COMPANY_IDENTIFIERS = {{'''


def main() -> None:
    lines = [HEADER.format(version=importlib.metadata.version("bumble"))]
    lines += [f"    0x{key:04X}: {COMPANY_IDENTIFIERS[key]!r}," for key in sorted(COMPANY_IDENTIFIERS)]
    lines.append("}")
    out = Path(__file__).resolve().parents[1] / "core" / "bluetooth_companies.py"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
