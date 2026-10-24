"""The one-file binary verifies TLS against the host's CA certificates.

Reported: every voice model download in axross-full failed on Gentoo with
"CERTIFICATE_VERIFY_FAILED ... unable to get local issuer certificate".
Measured on the 0.13.121 binary (Arch): its OpenSSL comes from the
AlmaLinux build machine and looks for /etc/pki/tls/cert.pem and
/etc/pki/tls/certs - RHEL's paths; Debian, Ubuntu, Gentoo, Arch and
openSUSE keep the bundle elsewhere, so ssl.create_default_context() loaded
0 CA certificates (cert_store_stats x509_ca == 0) and every urllib/stdlib
TLS client failed (voice downloads, FTPS, IMAPS, NNTP, Gopher, the
OpenAI-compatible STT client). requests worked only through certifi.

core.tls_env: at the start, when the default store is empty and the user
set neither SSL_CERT_FILE nor SSL_CERT_DIR, point SSL_CERT_FILE at the
host's bundle (certifi's when the host has none).
"""

from __future__ import annotations

import datetime
import os
import ssl
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import subprocess_env as SE  # noqa: E402
from core import tls_env as TE  # noqa: E402

FROZEN = os.environ.get("AXROSS_FROZEN_BINARY", "")


@pytest.fixture(autouse=True)
def _fresh():
    TE._SET_BY_AXROSS.clear()
    yield
    TE._SET_BY_AXROSS.clear()


def _bundle(tmp_path, name="ca.pem", text="-----BEGIN CERTIFICATE-----\nx\n") -> str:
    path = tmp_path / name
    path.write_text(text)
    return str(path)


# -- happy -------------------------------------------------------------------

def test_happy_an_empty_store_gets_the_hosts_bundle(tmp_path):
    env = {}
    host = _bundle(tmp_path)
    assert TE.apply_ca_bundle(env, candidates=[str(tmp_path / "missing.crt"), host],
                              count=lambda: 0) == host
    assert env["SSL_CERT_FILE"] == host
    assert "SSL_CERT_FILE" in TE.set_by_axross()


def test_happy_a_store_that_works_is_left_alone(tmp_path):
    env = {}
    assert TE.apply_ca_bundle(env, candidates=[_bundle(tmp_path)], count=lambda: 140) is None
    assert env == {}


def test_happy_the_host_paths_cover_the_supported_systems():
    paths = set(TE.HOST_CA_FILES)
    assert "/etc/ssl/certs/ca-certificates.crt" in paths   # Debian, Ubuntu, Gentoo, Arch
    assert "/etc/pki/tls/certs/ca-bundle.crt" in paths     # RHEL, Fedora
    assert "/etc/ssl/ca-bundle.pem" in paths               # openSUSE
    assert "/etc/ssl/cert.pem" in paths                    # Alpine, macOS


# -- sad ---------------------------------------------------------------------

@pytest.mark.parametrize("var", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_sad_the_users_own_choice_wins(tmp_path, var):
    env = {var: "/my/own"}
    assert TE.apply_ca_bundle(env, candidates=[_bundle(tmp_path)], count=lambda: 0) is None
    assert env == {var: "/my/own"}


def test_sad_without_a_host_bundle_certifi_is_used(tmp_path):
    env = {}
    certifi = _bundle(tmp_path, "cacert.pem")
    assert TE.apply_ca_bundle(env, candidates=[str(tmp_path / "none")], count=lambda: 0,
                              certifi_path=certifi) == certifi


def test_sad_with_nothing_at_all_nothing_is_set(tmp_path):
    env = {}
    assert TE.apply_ca_bundle(env, candidates=[], count=lambda: 0, certifi_path="") is None
    assert env == {}


# -- edge --------------------------------------------------------------------

def test_edge_an_empty_or_unreadable_candidate_is_skipped(tmp_path):
    empty = _bundle(tmp_path, "empty.crt", "")
    folder = tmp_path / "dir.crt"
    folder.mkdir()
    good = _bundle(tmp_path, "good.crt")
    env = {}
    assert TE.apply_ca_bundle(env, candidates=[empty, str(folder), good], count=lambda: 0) == good


def test_edge_host_programs_do_not_inherit_it_workers_do(tmp_path):
    env = {}
    host = _bundle(tmp_path)
    TE.apply_ca_bundle(env, candidates=[host], count=lambda: 0)
    assert "SSL_CERT_FILE" not in SE.clean_child_env(env)
    assert SE.worker_env(env)["SSL_CERT_FILE"] == host


def test_edge_the_real_default_store_is_counted():
    assert TE.default_store_count() == ssl.create_default_context().cert_store_stats()["x509_ca"]


def test_edge_main_applies_it_before_anything_starts():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def main() -> int:"):]
    assert body.index("apply_ca_bundle(") < body.index('"--agent-worker"')


# -- e2e: a real TLS connection --------------------------------------------------

def _ca_and_server_cert(folder: Path) -> tuple[Path, Path, Path]:
    """A CA and a server certificate for 127.0.0.1 signed by it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "axross test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(
                ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    ca_path, cert_path, key_path = folder / "ca.pem", folder / "srv.pem", folder / "srv.key"
    ca_path.write_bytes(ca.public_bytes(pem))
    cert_path.write_bytes(cert.public_bytes(pem))
    key_path.write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return ca_path, cert_path, key_path


@pytest.fixture
def https_server(tmp_path):
    ca, cert, key = _ca_and_server_cert(tmp_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"model bytes"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://127.0.0.1:{server.server_address[1]}/model.bin", ca
    server.shutdown()


_FETCH = textwrap.dedent("""\
    import sys, urllib.request
    sys.path.insert(0, {root!r})
    from core import tls_env
    if {apply!r}:
        tls_env.apply_ca_bundle(candidates=[{ca!r}], count=lambda: 0)
    try:
        print(urllib.request.urlopen({url!r}, timeout=10).read().decode())
    except Exception as exc:
        print("FAILED", exc)
""")


def _fetch(url, ca, apply: bool) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SSL_CERT")}
    code = _FETCH.format(root=str(ROOT), apply=apply, ca=str(ca), url=url)
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=60, env=env).stdout


def test_e2e_a_download_verifies_against_the_chosen_bundle(https_server):
    url, ca = https_server
    assert _fetch(url, ca, apply=True).strip() == "model bytes"


def test_e2e_negative_control_without_the_bundle_the_download_fails(https_server):
    url, ca = https_server
    out = _fetch(url, ca, apply=False)
    assert "FAILED" in out and "CERTIFICATE_VERIFY_FAILED" in out


@pytest.mark.skipif(not FROZEN, reason="AXROSS_FROZEN_BINARY names no built binary")
def test_e2e_the_built_binary_loads_the_hosts_ca_certificates(tmp_path):
    """The release binary's own OpenSSL: 0 CA certificates on this host before."""
    out = tmp_path / "out.txt"
    script = tmp_path / "s.py"
    script.write_text(textwrap.dedent(f"""\
        import os, ssl
        stats = ssl.create_default_context().cert_store_stats()
        open({str(out)!r}, "w").write(f"{{stats['x509_ca']}} {{os.environ.get('SSL_CERT_FILE')}}")
    """))
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SSL_CERT", "AXROSS_"))}
    env.update(HOME=str(home), QT_QPA_PLATFORM="offscreen")
    subprocess.run([FROZEN, "--script", str(script)], env=env, capture_output=True, timeout=120)
    count, _, path = out.read_text().partition(" ")
    assert int(count) > 0, f"no CA certificates; SSL_CERT_FILE={path}"
