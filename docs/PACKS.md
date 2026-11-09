# axross-base and packs

Asked 2026-11-05: an `axross-base` binary, and everything else loadable from GitHub -
broken down as far as the single extension, so a base with only chosen parts is
possible. axross-full, axross-slim, the wheel and the PyPI sdist stay as they are.

## Units

A **unit** is the smallest thing one can add: one pip extra (each backend: `smb`, `s3`,
`webdav`, `gdrive`, ...), one bundled extension (Media Player, Audio Mixer, Bluetooth,
IRC, Matrix, XMPP, Arcade, Forensic Tools, VirtualBox, System Information, ...), and the
feature groups that are neither (voice, mail analysis + PST, sift). A unit names

- the third-party distributions it needs (from `build/requirements-bundle.txt`, so every
  one is a reviewed, baselined pin of the supply-chain gate),
- the axross modules that are its own (an extension's file, a backend's client module),
- the units it builds on (Matrix needs `chat`, the Bluetooth stick mode needs
  `bluetooth-raw`).

`core/units.py` holds the table; a test holds it equal to `pyproject.toml`'s extras, the
bundled extensions and `core/features.py`, as today's tests do for the extras.

## Artifacts per release

- `axross-base-<variant>`: the PyInstaller binary with Python, PyQt6/Qt and the core
  (local files, SFTP, the panes, the editor, settings) - the axross code of every unit is
  small and stays in it, switched off until its unit is there.
- **Blobs**: one archive per third-party distribution and platform tag (the wheel as
  locked, plus for the frozen build its native libraries from the target sysroot when it
  needs system ones), content-addressed by SHA-256. Shared dependencies are one blob
  (cryptography is downloaded once, whatever needs it).
- `packs-<version>.json`: every unit -> its blobs (name, version, platform, SHA-256, size,
  PyPI's URL of the same file, and the URL on the GitHub release for a blob PyPI does not
  have); signed through the release's `SHA256SUMS` (below) - the base carries only the
  pinned public key. A blob that is on PyPI is fetched from `files.pythonhosted.org` and
  checked against the manifest's SHA-256 and size; only the others are attached to the
  GitHub release (`scripts/assemble_release.py --pack-wheels unhosted`, the default): GitHub
  lists a release's files by name, and installed binaries read only the first 100, so a
  release with every wheel attached pushed `SHA256SUMS` out of their sight. An axross-base
  that can reach github.com but not files.pythonhosted.org cannot add such packs.
- axross-slim / axross-full: base + the slim / all units pre-installed, built as today.
  The wheel and sdist on PyPI: unchanged (pip installs extras as today).

## Signing - one chain, the existing release key

The release key (Ed25519, public half pinned in `core/self_update.TRUSTED_KEYS`) already
signs `SHA256SUMS` (`scripts/sign_release.py`, raw 64-byte signature in
`SHA256SUMS.sig`). Everything else hangs from that one signature:

- `SHA256SUMS` lists every binary (base / slim / full, every variant), every blob
  attached to the release and `packs-<version>.json` - so the manifest is signed through
  it, and every blob through the manifest's SHA-256 (a blob fetched from PyPI is listed
  only in the signed manifest; the ones attached to the release are in both).
- The installer checks in this order and stops at the first failure: the signature of
  `SHA256SUMS` against the pinned key; the manifest's SHA-256 against `SHA256SUMS`; each
  blob's size and SHA-256 against the manifest (and against `SHA256SUMS`); only then is
  anything unpacked. Nothing is trusted from GitHub's API alone (its `digest` must agree
  where it is given, as for the binaries today).
- A blob fetched from PyPI instead is the same file: same SHA-256, same checks.
- Key rotation as today: `TRUSTED_KEYS` may hold the old and the new key for a release.

## Updates over GitHub

- **Binaries** (base, slim, full): the self-update of today (`core/self_update.py`),
  extended by the variant - assets `axross-<flavor>` (glibc 2.34) and
  `axross-<flavor>-glibc2.36`, `axross-base`, `axross-base-glibc2.36`; the bundle carries
  its flavour *and* its variant (`axross/axross-bundle-flavor.txt`,
  `axross/axross-bundle-variant.txt`) and updates to exactly its own asset.
- **Packs**: units are bound to the release they came with. An update of the binary
  fetches the new release's manifest and the blobs of every installed unit that changed
  (a blob whose SHA-256 is already there is kept) before the new binary is started; if
  a unit cannot be fetched, the update says which and the old version keeps running.
  A unit the new release no longer has (dropped or renamed), and a unit that needs one,
  cannot come along: the update goes ahead without it and its message names it.
  *Help > Features…* also offers "Update packs" on its own when the release's manifest
  was re-issued (same version, a pack fixed): `core.packs.check_reissued` and `update`,
  through the same signed `SHA256SUMS` and blob checks as *Add*; the fixed packs are used
  from the next start. Each re-issue is numbered in the signed `SHA256SUMS`
  (`# axross-packs-issue N` after the release line, `scripts/sign_release.py
  --packs-issue N`; none is issue 0): `installed.json` keeps the highest issue installed
  (`issue`), and a lower one - an earlier signed issue uploaded again - or another
  manifest under the installed number is refused, by *Add* and "Update packs" alike. Until then the running session keeps the folders it imports
  from: a blob re-issued under its old file name is unpacked into a folder of its own
  (`<blob>.<sha256 prefix>`, recorded as `dirs` in `installed.json`), and a folder no
  unit needs any more is only listed as `retired` there.
- At the start, `core.packs.prune` removes the pack folders of versions *older* than the
  running one (the new version has started once) and the folders retired by "Update
  packs" or *Remove*. A newer version's folder stays: the update installs it before it
  replaces the binary, and the old binary may run once more (the new file waits in
  `~/.cache`, or a rollback to `<name>.previous`).
- A pack blob has no overall time limit (it may be hundreds of MiB on a slow line):
  each read times out after `READ_TIMEOUT`, and *Cancel* stops it between reads, as
  for the binary.

## In the base

Help > Features… lists the units with size and what they bring; *Add* downloads the
missing blobs (GitHub release asset, else PyPI - the same file: the SHA-256 decides),
checks each hash against the signed manifest, unpacks into
`~/.local/share/axross/packs/<version>/<blob>/` (0700, never over an existing one) and
adds them to `sys.path` at the next start (and at once for pure-Python units: every wheel
`py3-none-any`; the window says "ready to use", a unit with a native wheel waits for the
restart). *Remove* retires a unit's blobs that no other installed unit uses; their
folders are deleted at the next start, so what this session loaded or loads later
stays usable until then. Nothing is executed while
unpacking; a blob whose hash or signature does not match is refused and deleted. A
proxy and the offline case work as for the voice models. An update of axross brings a
new manifest: units are fetched again for the new version.

## Build

`scripts/build_dist.sh` gains the base variant and the blobs: after the gate passed,
each blob is built from the locked wheel (the same files the gate checked), the manifest
written and signed. The gate itself needs no change: every blob is a baselined pin.

## Tests

The unit table against extras / extensions; a manifest round trip; download, hash and
signature checks against a local HTTP server (a wrong hash, a wrong signature, a blob
not in the manifest, a path outside the folder in an archive); a frozen base build that
adds a pure-Python unit and a native one and uses them (the build tests).

## Order (the release contract in docs/PACKAGING.md is updated with step 2)

1. `core/units.py` + the table test.
2. Blob and manifest building in `build_dist.sh`, signing.
3. The pack installer (core) and Help > Features… in the base.
4. The `axross-base` variant of the bundle build; the variant marker and asset names.
5. Updates: binaries per variant, packs with the binary and on their own.
