"""A ProxyCommand's %h and %r never carry shell syntax or an option.

``expand_proxy_command`` put the profile's host and user name into the
command as they were. The command runs without a shell, but a common
ProxyCommand starts one (``sh -c 'nc %h %p'``, ``bash -c 'exec
3<>/dev/tcp/%h/%p ...'``) or hands %h to a program as an argument (``nc
%h %p``): a host name such as ``x$(touch /tmp/pwned)`` or ``-e/bin/sh``
- from an imported profile, a bookmark, a pasted link - ran a command on
this machine. The connection dialog refuses spaces, not ``$``, ``;``,
backticks or a leading ``-``. OpenSSH refuses such names in these
expansions since 9.6 (CVE-2023-51385); so does axross now, before
anything runs.
"""

from __future__ import annotations

import pytest

from core.ssh_client import SSHSession
from core.ssh_config import expand_proxy_command


def test_happy_ordinary_names_expand():
    out = expand_proxy_command(
        "sh -c 'nc %h %p' # %r", host="srv-1.example.org", port=22, username="alice.b_2"
    )
    assert out == "sh -c 'nc srv-1.example.org 22' # alice.b_2"
    assert "[fe80::1%eth0]:22" in expand_proxy_command(
        "ssh -W %h:%p jump", host="fe80::1%eth0", port=22, username="u")


@pytest.mark.parametrize(
    "host",
    ["x$(touch /tmp/p)", "x`id`", "a;b", "a|b", "a&b", "a>b", "-e/bin/sh", "a\\b",
     "a'b", 'a"b', "a b", "a\tb", "a{b}", "a(b)", "a<b"],
)
def test_sad_a_host_with_shell_syntax_is_refused(host):
    with pytest.raises(ValueError, match="ProxyCommand"):
        expand_proxy_command("sh -c 'nc %h %p'", host=host, port=22, username="u")


def test_sad_a_user_name_with_shell_syntax_is_refused():
    with pytest.raises(ValueError, match="ProxyCommand"):
        expand_proxy_command("ssh -l %r -W %h:%p j", host="h", port=22, username="u;id")


def test_edge_nothing_runs_when_the_host_is_refused(tmp_path):
    from core.profiles import ConnectionProfile

    marker = tmp_path / "pwned"
    profile = ConnectionProfile(
        name="p", protocol="sftp", host=f"x$(touch${{IFS}}{marker})", port=22, username="u",
        proxy_command="sh -c 'nc %h %p'",
    )
    s = SSHSession(profile)
    s._known_hosts_path = tmp_path / "known_hosts"
    with pytest.raises(ValueError):
        s.connect(password="pw")
    assert not marker.exists()


def test_edge_names_not_in_the_command_are_not_checked():
    # No %h / %r: the names never reach the command.
    assert expand_proxy_command("ssh -W 10.0.0.1:22 j %%", host="a;b", port=22,
                                username="u;v") == "ssh -W 10.0.0.1:22 j %"
