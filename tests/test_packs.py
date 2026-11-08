"""core.packs: a signed release with a manifest and wheels (a test key,
a fake fetcher) - installed, activated, removed; every tampering refused."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402
from core.units import Unit  # noqa: E402


def wheel(name: str, files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for path, data in files.items():
            z.writestr(path, data)
        z.writestr(f"{name}-1.0.dist-info/METADATA", f"Name: {name}\nVersion: 1.0\n")
    return buf.getvalue()


@pytest.fixture
def release(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)).decode()
    blobs = {
        "alpha-1.0-py3-none-any.whl": wheel("alpha", {"alpha/__init__.py": "VALUE = 'alpha'\n"}),
        "shared-1.0-py3-none-any.whl": wheel("shared", {"shared/__init__.py": "X = 1\n"}),
        "beta-1.0-py3-none-any.whl": wheel("beta", {"beta/__init__.py": "VALUE = 'beta'\n"}),
    }
    wheels = {n.split("-")[0]: (n, hashlib.sha256(d).hexdigest(), len(d), f"https://files.pythonhosted.org/x/{n}")
              for n, d in blobs.items()}
    units = [Unit("extra:a", "extra", "a", ("a",), (), frozenset({"alpha", "shared"})),
             Unit("extra:b", "extra", "b", ("b",), (), frozenset({"beta", "shared"})),
             Unit("extension:c", "extension", "c", ("a",), ("extra:a",), frozenset())]
    manifest = json.dumps(P.build_manifest("9.9.9", "linux-x86_64", wheels, units)).encode()
    files = dict(blobs)
    files[P.manifest_name("9.9.9")] = manifest
    sums = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(files.items())).encode()
    files["SHA256SUMS"] = sums
    files["SHA256SUMS.sig"] = key.sign(sums)
    state = {"files": files, "pub": pub, "fetched": []}

    def get(url, max_bytes, hosts):
        state["fetched"].append(url)
        name = url.rsplit("/", 1)[1]
        if "pythonhosted" in url:
            return state.get("pypi", {}).get(name, b"") or (_ for _ in ()).throw(OSError("404"))
        data = state["files"][name]
        if len(data) > max_bytes:
            raise OSError("too large")
        return data
    rel = SU.Release("9.9.9", "v9.9.9", "", "", tuple(
        SU.Asset(n, f"https://github.com/c0decave/axross/releases/download/v9.9.9/{n}", len(d))
        for n, d in files.items()))
    state["release"], state["fetch"] = rel, P.Fetcher(get)
    state["verify"] = lambda data, sig: SU.verify_signature(data, sig, keys=(pub,))
    return state


def _install(r, units, root):
    return P.install(r["release"], units, fetch=r["fetch"], root=root, verify=r["verify"])


def test_happy_install_activate_and_import(release, tmp_path):
    done = _install(release, ["extension:c"], tmp_path)     # needs extra:a
    assert sorted(done) == ["alpha-1.0-py3-none-any.whl", "shared-1.0-py3-none-any.whl"]
    path = []
    added = P.activate("9.9.9", tmp_path, path)
    assert len(added) == 2
    sys.path[:0] = path
    try:
        import alpha
        assert alpha.VALUE == "alpha"
    finally:
        for p in path:
            sys.path.remove(p)
        sys.modules.pop("alpha", None)
    assert _install(release, ["extra:a"], tmp_path) == []   # already there: nothing fetched again


def test_happy_remove_keeps_what_another_unit_needs(release, tmp_path):
    _install(release, ["extra:a", "extra:b"], tmp_path)
    gone = P.remove("9.9.9", "extra:a", tmp_path)
    assert gone == ["alpha-1.0-py3-none-any.whl"]
    assert (tmp_path / "9.9.9" / "shared-1.0-py3-none-any.whl").is_dir()   # beta still needs it
    assert P.installed("9.9.9", tmp_path) == ["extra:b"]


def test_sad_a_wrong_signature_installs_nothing(release, tmp_path):
    release["files"]["SHA256SUMS.sig"] = b"\0" * 64
    with pytest.raises(SU.SignatureError):
        _install(release, ["extra:a"], tmp_path)
    assert not (tmp_path / "9.9.9").exists()


def test_sad_a_changed_manifest_is_refused(release, tmp_path):
    name = P.manifest_name("9.9.9")
    m = json.loads(release["files"][name])
    m["blobs"]["alpha-1.0-py3-none-any.whl"]["sha256"] = "0" * 64
    release["files"][name] = json.dumps(m).encode()
    with pytest.raises(P.PackError, match="differs from the signed"):
        _install(release, ["extra:a"], tmp_path)


def test_sad_a_tampered_blob_falls_back_to_pypi_and_is_refused_if_that_is_wrong_too(release, tmp_path):
    good = release["files"]["alpha-1.0-py3-none-any.whl"]
    release["files"]["alpha-1.0-py3-none-any.whl"] = good[:-1] + b"X"
    with pytest.raises(P.PackError, match="could not be fetched"):
        _install(release, ["extra:a"], tmp_path)
    release["pypi"] = {"alpha-1.0-py3-none-any.whl": good}     # PyPI has the right file
    assert "alpha-1.0-py3-none-any.whl" in _install(release, ["extra:a"], tmp_path)
    assert any("pythonhosted" in u for u in release["fetched"])


def test_sad_a_wheel_that_leaves_its_folder_is_refused(tmp_path):
    bad = wheel("evil", {"../../escape.py": "x"})
    (tmp_path / "evil.whl").write_bytes(bad)
    with pytest.raises(P.PackError, match="leaves its folder"):
        P._unpack(tmp_path / "evil.whl", tmp_path / "out")
    assert not (tmp_path / "escape.py").exists() and not (tmp_path / "out").exists()


def test_sad_an_unknown_unit_and_a_blob_not_in_the_manifest(release, tmp_path):
    with pytest.raises(P.PackError, match="no unit"):
        _install(release, ["extra:nope"], tmp_path)
    m = {"format": 1, "version": "1", "units": {"u": {"blobs": ["missing.whl"]}}, "blobs": {}}
    with pytest.raises(P.PackError, match="does not list"):
        P.parse_manifest(json.dumps(m).encode())


def test_happy_the_packs_dialog_lists_adds_and_removes(release, tmp_path):
    import os
    import time

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    from ui.packs_dialog import PacksDialog

    app = QApplication.instance() or QApplication([])
    api = json.dumps({"tag_name": "v9.9.9", "html_url": "https://github.com/c0decave/axross/releases/tag/v9.9.9",
                      "body": "", "draft": False, "prerelease": False,
                      "assets": [{"name": a.name, "size": a.size, "browser_download_url": a.url}
                                 for a in release["release"].assets]}).encode()
    inner = release["fetch"].get

    def get(url, max_bytes, hosts):
        return api if "api.github.com" in url else inner(url, max_bytes, hosts)
    dlg = PacksDialog(version="9.9.9", fetch=P.Fetcher(get), root=tmp_path, verify=release["verify"],
                      path=[])     # a pure-Python unit goes on this list, not on sys.path
    end = time.monotonic() + 10
    while dlg.table.rowCount() == 0 and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)
    assert dlg.table.rowCount() == 3, dlg.status.text()
    rows = {dlg.table.item(r, 0).data(256): r for r in range(3)}
    dlg.table.selectRow(rows["extra:b"])
    dlg.add_selected()
    end = time.monotonic() + 10
    while "Added" not in dlg.status.text() and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)
    assert P.installed("9.9.9", tmp_path) == ["extra:b"]
    assert dlg.table.item(rows["extra:b"], 3).text() == "yes"
    dlg.table.selectRow(rows["extra:b"])
    dlg.remove_selected()
    assert P.installed("9.9.9", tmp_path) == []
    dlg.close()


@pytest.mark.parametrize("flavor,variant,asset", [
    ("full", "glibc-2.34", "axross-full"), ("slim", "glibc-2.34", "axross-slim"),
    ("base", "glibc-2.34", "axross-base"), ("full", "glibc-2.36", "axross-full-glibc2.36"),
    ("base", "glibc-2.36", "axross-base-glibc2.36"), ("full", "musl", ""),
])
def test_happy_each_binary_updates_to_its_own_variant(flavor, variant, asset):
    assert SU.asset_name("linux", "x86_64", flavor, variant) == asset


def test_happy_the_variant_is_read_from_the_bundle(tmp_path):
    (tmp_path / "axross").mkdir()
    (tmp_path / "axross" / SU.FLAVOR_FILE).write_text("base\n")
    exe = tmp_path / "axross-base"
    exe.write_bytes(b"")
    inst = SU.detect_install(frozen=True, executable=exe, bundle_dir=str(tmp_path), platform="linux",
                             machine="x86_64")
    assert inst.asset == "axross-base"                            # no variant file: glibc 2.34
    (tmp_path / "axross" / SU.VARIANT_FILE).write_text("glibc-2.36\n")
    inst = SU.detect_install(frozen=True, executable=exe, bundle_dir=str(tmp_path), platform="linux",
                             machine="x86_64")
    assert inst.asset == "axross-base-glibc2.36"


def test_happy_an_update_brings_the_installed_packs_along_first(release, tmp_path):
    # installed for the running version "9.9.8" ...
    (tmp_path / "9.9.8").mkdir()
    (tmp_path / "9.9.8" / "installed.json").write_text(json.dumps({"units": ["extra:b"], "manifest": {}}))
    calls = []

    def get(url, max_bytes, hosts):
        calls.append(url)
        return release["fetch"].get(url, max_bytes, hosts)
    import core.self_update as S

    orig = S.fetch
    S.fetch = lambda url, **kw: get(url, kw["max_bytes"], kw.get("hosts"))
    try:
        done = S._carry_packs(release["release"], opener=object(), current="9.9.8", root=tmp_path,
                              verify=release["verify"])
    finally:
        S.fetch = orig
    assert sorted(done) == ["beta-1.0-py3-none-any.whl", "shared-1.0-py3-none-any.whl"]
    assert P.installed("9.9.9", tmp_path) == ["extra:b"]
    # a release whose packs cannot be checked stops the update before the binary is fetched
    other = tmp_path / "other"
    (other / "9.9.8").mkdir(parents=True)
    (other / "9.9.8" / "installed.json").write_text(json.dumps({"units": ["extra:a"], "manifest": {}}))
    release["files"]["SHA256SUMS.sig"] = b"\0" * 64
    S.fetch = lambda url, **kw: get(url, kw["max_bytes"], kw.get("hosts"))
    try:
        with pytest.raises(SU.SignatureError):
            S._carry_packs(release["release"], opener=object(), current="9.9.8", root=other,
                           verify=release["verify"])
    finally:
        S.fetch = orig
    assert P.installed("9.9.9", other) == []
