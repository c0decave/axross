"""SSH config import as OpenSSH reads it (review round 2).

* ``Include`` was skipped: every host of an included file (OrbStack,
  Colima, Teleport and many dotfile setups put theirs there) was missing
  from the import without a word. Included files are read in place,
  relative to ~/.ssh, globs sorted, nested at most 16 deep.
* OpenSSH takes the FIRST value of a setting: a second ``Host prod``
  block (or a later line) replaced HostName, User and Port, and the same
  alias was imported twice.
* ``HostName %h.example.org`` kept the literal "%h".
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ssh_config import parse_ssh_config  # noqa: E402


def _hosts(path):
    return {h.alias: h for h in parse_ssh_config(path)}


def test_sad_include_is_read(tmp_path) -> None:
    ssh = tmp_path / ".ssh"
    (ssh / "conf.d").mkdir(parents=True)
    (ssh / "conf.d" / "b.conf").write_text("Host beta\n  HostName b.example\n")
    (ssh / "conf.d" / "a.conf").write_text("Host alpha\n  HostName a.example\n")
    (tmp_path / "abs.conf").write_text("Host gamma\n  HostName g.example\n")
    (ssh / "config").write_text(
        "Include conf.d/*.conf\n"
        f"Include {tmp_path / 'abs.conf'}\n"
        "Host main\n  HostName m.example\n"
    )
    hosts = parse_ssh_config(ssh / "config")
    assert [h.alias for h in hosts] == ["alpha", "beta", "gamma", "main"]
    assert hosts[0].hostname == "a.example"


def test_sad_include_inside_a_host_block_applies_to_it(tmp_path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "user.conf").write_text("User deploy\n")
    (ssh / "config").write_text("Host web\n  Include user.conf\n  HostName w.example\n")
    web = _hosts(ssh / "config")["web"]
    assert (web.user, web.hostname) == ("deploy", "w.example")


def test_edge_include_loop_ends(tmp_path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "config").write_text("Include config\nHost x\n  HostName x.example\n")
    assert list(_hosts(ssh / "config")) == ["x"]


def test_sad_first_value_wins(tmp_path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text(
        "Host prod\n  HostName first.example\n  User deploy\n  Port 2200\n  User other\n"
        "Host prod\n  HostName second.example\n  Port 22\n"
    )
    hosts = parse_ssh_config(cfg)
    assert [h.alias for h in hosts] == ["prod"]
    assert (hosts[0].hostname, hosts[0].user, hosts[0].port) == ("first.example", "deploy", 2200)


def test_sad_hostname_percent_h(tmp_path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text("Host db1 db2\n  HostName %h.internal.example\n")
    hosts = _hosts(cfg)
    assert hosts["db1"].hostname == "db1.internal.example"
    assert hosts["db2"].hostname == "db2.internal.example"
