"""The settings matrix of Edit > Settings > Agent > Profiles (an agent profile's own settings). The
rows are defined in tests/test_settings_matrix_agent.py with every helper and effect; this file
runs them, so that the rows of the Agent page run side by side."""

from __future__ import annotations

import pytest

from tests import test_settings_matrix as SMX
from tests import test_settings_matrix_agent as A
from tests.test_settings_matrix import ctx  # noqa: F401 - the fixture of the matrix
from tests.test_settings_matrix_agent import _current_ctx  # noqa: F401 - autouse fixture


@pytest.mark.parametrize("row", A.params([r for r in A.PROFILE_ROWS if not A.is_profile_access(r)]))
def test_set_store_reload_effect(ctx, row) -> None:  # noqa: F811
    SMX.check_set_store_reload_effect(ctx, row)


@pytest.mark.parametrize("row", A.params([r for r in A.PROFILE_ROWS if not A.is_profile_access(r)]))
def test_hand_edited_value_falls_back(ctx, row) -> None:  # noqa: F811
    SMX.check_hand_edited_value_falls_back(ctx, row)
