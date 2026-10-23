# Third-Party Licenses

Axross is distributed under the Apache License 2.0 (see [LICENSE](LICENSE)).
At runtime it dynamically imports the packages listed below; these are
installed by the end user via `pip install`. None of these packages is vendored
into the axross source tree.

When a binary bundle is produced (PyInstaller / AppImage), the bundle
statically includes many of the packages in this list. Redistribution of
such bundles is governed by the strongest copyleft license among the
included components — currently **GPL-3.0** because of PyQt6. See `NOTICE`
for the distribution-layer license notice.

## Runtime dependencies

| Package | SPDX license | Upstream |
|---|---|---|
| PyQt6 | GPL-3.0-only OR Commercial (Riverbank) | https://www.riverbankcomputing.com/software/pyqt/ |
| paramiko | LGPL-2.1-or-later | https://www.paramiko.org |
| PySocks | BSD-3-Clause | https://github.com/Anorov/PySocks |
| keyring | MIT | https://github.com/jaraco/keyring |

## Optional (per-extra) dependencies

| Extra | Package | SPDX license | Upstream |
|---|---|---|---|
| `[smb]` | smbprotocol | MIT | https://github.com/jborean93/smbprotocol |
| `[webdav]` | requests | Apache-2.0 | https://requests.readthedocs.io |
| `[webdav]` | defusedxml | PSF-2.0 | https://github.com/tiran/defusedxml |
| `[s3]` | boto3 | Apache-2.0 | https://github.com/boto/boto3 |
| `[azure]` | azure-storage-blob | MIT | https://github.com/Azure/azure-sdk-for-python |
| `[azure]` | azure-storage-file-share | MIT | https://github.com/Azure/azure-sdk-for-python |
| `[onedrive]` | msal | MIT | https://github.com/AzureAD/microsoft-authentication-library-for-python |
| `[onedrive]` | requests | Apache-2.0 | https://requests.readthedocs.io |
| `[gdrive]` | google-api-python-client | Apache-2.0 | https://github.com/googleapis/google-api-python-client |
| `[gdrive]` | google-auth-oauthlib | Apache-2.0 | https://github.com/googleapis/google-auth-library-python-oauthlib |
| `[gdrive]` | google-auth-httplib2 | Apache-2.0 | https://github.com/googleapis/google-auth-library-python-httplib2 |
| `[dropbox]` | dropbox | MIT | https://github.com/dropbox/dropbox-sdk-python |
| `[fuse]` | fusepy | ISC | https://github.com/fusepy/fusepy |
| `[winrm]` | pywinrm | MIT | https://github.com/diyan/pywinrm |
| `[wmi]` | impacket | Apache-1.1-style (SecureAuth/Fortra Impacket License) | https://github.com/fortra/impacket |
| `[exchange]` | exchangelib | BSD-2-Clause | https://github.com/ecederstrand/exchangelib |
| `[adb]` | adb-shell | Apache-2.0 | https://github.com/JeffLIrion/adb_shell |
| `[archive]` | py7zr | LGPL-2.1-or-later | https://github.com/miurahr/py7zr |
| `[tftp]` | tftpy | MIT | https://github.com/msoulier/tftpy |
| `[metadata]` | pypdf | BSD-3-Clause | https://github.com/py-pdf/pypdf |
| `[voice]` | piper-tts | GPL-3.0-or-later | https://github.com/OHF-voice/piper1-gpl |
| `[voice]` | onnxruntime | MIT | https://github.com/microsoft/onnxruntime |
| `[voice]` | faster-whisper | MIT | https://github.com/SYSTRAN/faster-whisper |
| `[voice]` | ctranslate2 | MIT | https://github.com/OpenNMT/CTranslate2 |

## Binaries bundled in axross-full (Linux)

Static builds fetched by `Dockerfile.build` with pinned SHA-256 sums; their
licence files ship in the bundle under `licenses/search-tools/`.

| Tool | Binary | SPDX license | Purpose |
|---|---|---|---|
| ripgrep 15.2.0 | `rg` | MIT OR Unlicense | Find Files: content search (`core/file_search.py`) |
| fd 10.5.0 | `fd` | MIT OR Apache-2.0 | Find Files: name walk (`core/file_search.py`) |

## Speech components bundled in axross-full

The Agent dock's voice (`axross[voice]`) is part of axross-full. Its
packages ship in the bundle; the voices and the speech recognition models
are not bundled - Help > Features… downloads them (pinned SHA-256,
`core/voice_models.py`).

| Component | Version | SPDX license | Note |
|---|---|---|---|
| piper-tts | piper-tts 1.8.0 | GPL-3.0-or-later | speech synthesis; contains espeak-ng |
| espeak-ng | 1.52.0.1 (commit 724808c5a83f9ef95fdd0db886ba7ba537ff224a) | GPL-3.0-or-later | statically linked into piper's `espeakbridge`, with its data |
| onnxruntime | onnxruntime 1.31.0 | MIT | runs the voice models |
| faster-whisper | faster-whisper 1.2.1 | MIT | local speech recognition |
| ctranslate2 | ctranslate2 4.8.3 | MIT | runs the Whisper models |
| PyAV (av) | as resolved by faster-whisper | BSD-3-Clause | audio decoding (faster-whisper dependency) |

Because axross-full ships GPL-3.0-or-later code (as it already does with
PyQt6), the bundle carries the GPL-3 text (`licenses/voice/COPYING`, from
piper's distribution) and a written offer for the corresponding source
(`licenses/voice/SOURCE-OFFER.txt`, kept in `build/licenses/voice/`).

Downloaded at run time, not bundled: the Piper voices of
[rhasspy/piper-voices](https://huggingface.co/rhasspy/piper-voices) v1.0.0
(MIT; each voice's dataset terms in its `MODEL_CARD`: Thorsten CC0, Kerstin,
Ryan and Lessac as stated there) and Systran's faster-whisper conversions of
OpenAI Whisper base and small (MIT).

## System tools invoked via subprocess

These are not shipped with Axross; users install them through their distro
package manager. They are listed for transparency about the process boundary
Axross calls out to.

| Tool | SPDX license | Purpose |
|---|---|---|
| rsync | GPL-3.0-or-later | Rsync backend (`core/rsync_client.py`) |
| mount.nfs / umount (util-linux + nfs-utils) | GPL-2.0 | NFS backend |
| iscsiadm (open-iscsi) | GPL-2.0 | iSCSI backend |
| jmtpfs / simple-mtpfs / go-mtpfs | GPL-3.0 / GPL-2.0 / BSD | MTP backend (first-available-on-PATH) |
| pkexec (polkit) | LGPL-2.0 | "Open as root…" action (`core.elevated_io`) |
| ffprobe / ffmpeg (FFmpeg) | LGPL-2.1-or-later (GPL-2.0-or-later builds exist) | Reading and removing audio / video metadata (`core.metadata_formats`) |

## Notes for redistributors

- Source redistribution: retain `LICENSE`, `NOTICE`, and this file.
- Binary redistribution of a PyInstaller bundle that includes PyQt6: the
  binary inherits GPL-3.0. Ship `LICENSE` + `NOTICE` + this file alongside
  the binary, and also ensure the GPL-3.0 text is included (or linked) per
  GPL §4 requirements for offering corresponding source.
- `Dockerfile.mcp` produces a PyQt6-free image — that image is Apache-2.0
  only (no copyleft inheritance).
