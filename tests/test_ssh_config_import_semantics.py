"""SSH config import: what OpenSSH would do with the same file.

Protocol review (round 1):

* a ``Match`` block's settings were applied to the ``Host`` block above
  it - ``Match host *.internal`` with ``ProxyCommand nc relay 22`` and
  ``User root`` gave the unrelated host ``prod`` that relay and that user;
* ``ProxyJump`` was dropped: the imported host connected directly,
  past the jump host the config routes it through;
* a negated pattern (``Host a !b``) became a host named ``!b``;
* ``Port=2222`` (the ``=`` form without spaces) was ignored;
* a ProxyCommand's alias resolution put another profile's host name as
  it was into ``ssh``'s argument list - a host ``-oProxyCommand=...``
  (an imported profile) became an option that runs a command here.
"""

from __future__ import annotations

import shlex

import pytest

from core.ssh_config import expand_proxy_command, parse_ssh_config


def _parse(tmp_path, text):
    path = tmp_path / "config"
    path.write_text(text)
    return {h.alias: h for h in parse_ssh_config(path)}


def test_happy_plain_host_block(tmp_path):
    hosts = _parse(tmp_path, "Host web\n  HostName web.example\n  User alice\n  Port 2200\n")
    assert hosts["web"].hostname == "web.example"
    assert hosts["web"].user == "alice"
    assert hosts["web"].port == 2200


def test_sad_match_block_does_not_leak_into_the_host_above(tmp_path):
    hosts = _parse(tmp_path, (
        "Host prod\n  HostName prod.example\n"
        "Match host *.internal\n  ProxyCommand nc relay 22\n  User root\n"
    ))
    assert hosts["prod"].proxy_command == ""
    assert hosts["prod"].user == ""


def test_sad_negated_pattern_is_no_host(tmp_path):
    hosts = _parse(tmp_path, "Host a !b\n  HostName a.example\n")
    assert set(hosts) == {"a"}


def test_edge_equals_form_without_spaces(tmp_path):
    hosts = _parse(tmp_path, "Host=eq\nHostName=eq.example\nPort=2222\nUser=bob\n")
    assert hosts["eq"].hostname == "eq.example"
    assert hosts["eq"].port == 2222
    assert hosts["eq"].user == "bob"


def test_sad_proxyjump_becomes_a_proxy_command(tmp_path):
    hosts = _parse(tmp_path, "Host jumped\n  HostName 10.0.0.5\n  ProxyJump admin@bastion:2222\n")
    cmd = hosts["jumped"].proxy_command
    assert cmd, "ProxyJump was dropped: the host would connect directly"
    argv = shlex.split(cmd)
    assert argv[0] == "ssh"
    assert "admin@bastion" in argv
    assert argv[argv.index("-p") + 1] == "2222"
    assert argv[argv.index("-W") + 1] == "%h:%p"


def test_edge_proxyjump_chain_and_none(tmp_path):
    hosts = _parse(tmp_path, (
        "Host chain\n  ProxyJump j1,ssh://u@j2:2022\n"
        "Host direct\n  ProxyJump none\n"
    ))
    argv = shlex.split(hosts["chain"].proxy_command)
    assert argv[argv.index("-J") + 1] == "j1"
    assert "u@j2" in argv and argv[argv.index("-p") + 1] == "2022"
    assert hosts["direct"].proxy_command == ""


def test_edge_first_of_proxycommand_and_proxyjump_wins(tmp_path):
    hosts = _parse(tmp_path, "Host x\n  ProxyCommand nc a 22\n  ProxyJump b\n")
    assert hosts["x"].proxy_command == "nc a 22"


def test_sad_proxyjump_hop_that_is_an_option_is_dropped(tmp_path):
    hosts = _parse(tmp_path, "Host x\n  ProxyJump -oProxyCommand=id\n")
    assert hosts["x"].proxy_command == ""


class _Profile:
    def __init__(self, host, username=""):
        self.host = host
        self.username = username
        self.key_file = ""
        self.port = 22


@pytest.mark.parametrize("host,user", [("-oProxyCommand=touch /tmp/x", ""),
                                       ("bastion", "-oProxyCommand=id")])
def test_sad_resolved_alias_never_becomes_an_ssh_option(host, user):
    with pytest.raises(ValueError):
        expand_proxy_command("ssh -W %h:%p bastion", host="t", port=22, username="u",
                             resolve_profile=lambda name: _Profile(host, user))


def test_happy_resolved_alias_expands():
    out = expand_proxy_command("ssh -W %h:%p bastion", host="t", port=22, username="u",
                               resolve_profile=lambda name: _Profile("10.0.0.1", "admin"))
    assert shlex.split(out) == ["ssh", "-W", "t:22", "admin@10.0.0.1"]
