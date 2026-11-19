"""SCP stat: a folder and a link are known whatever language the server
speaks.

Protocol review (round 1): GNU ``stat %F`` is translated - on a German
server a folder is "Verzeichnis", a link "symbolische Verknüpfung" -
and the type was read from that word: ``is_dir`` and ``is_link`` were
both False there. A missing path raised a plain OSError, not
FileNotFoundError, because the error is typed by its English wording,
and SCP's ``export LC_ALL=...`` at connect never reached a command (each
exec is a new shell). The type comes from the mode (``%f``) now, and
stat and mkdir run under LC_ALL=C.
"""

from __future__ import annotations

from types import SimpleNamespace

from core.scp_client import SCPSession
from core.telnet_client import _parse_stat_gnu


def test_sad_translated_type_words_still_give_folder_and_link():
    folder = _parse_stat_gnu("/srv/data|4096|1700000000|41ed|root|root|Verzeichnis")
    link = _parse_stat_gnu("/srv/l|6|1700000000|a1ff|root|root|symbolische Verknüpfung")
    plain = _parse_stat_gnu("/srv/f|6|1700000000|81a4|root|root|reguläre Datei")
    assert (folder.is_dir, folder.is_link) == (True, False)
    assert (link.is_dir, link.is_link) == (False, True)
    assert (plain.is_dir, plain.is_link) == (False, False)
    assert folder.permissions == 0o755


def _scp(answers):
    s = object.__new__(SCPSession)
    s._caps = SimpleNamespace(has_stat_gnu=True, has_env_prefix=True)
    sent = []

    def run(cmd, timeout=None, **kw):
        sent.append(cmd)
        return answers.pop(0)

    s._exec_raw = run
    return s, sent


def test_edge_stat_and_mkdir_run_in_the_c_locale():
    s, sent = _scp([("/x|1|1700000000|81a4|u|g|regular file", 0), ("", 0)])
    s._stat("/x")
    s.mkdir("/d")
    assert all(cmd.startswith("LC_ALL=C ") for cmd in sent), sent
