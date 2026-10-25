# Third-Party Licenses

Axross is distributed under the Apache License 2.0 (see [LICENSE](LICENSE)).
It is built on the work of many other projects - thank you to all of them.
The tables below are generated from
[`resources/credits/third_party.json`](resources/credits/third_party.json)
(`python -m core.third_party --write`); the same data is shown in the app
under Help > Third-Party Software… and at the end of [README.md](README.md).
A test fails when a table drifts from the data, when a package that
`pyproject.toml` installs has no entry, and - at release time - when a built
binary contains a library or package without an entry.

None of these packages is vendored into the axross source tree; a source or
`pip` install imports them as installed by the user.

When a binary bundle is produced (PyInstaller), the bundle statically
includes many of the components listed here. Redistribution of such bundles
is governed by the strongest copyleft license among the included
components — currently **GPL-3.0** because of PyQt6. See `NOTICE` for the
distribution-layer license notice.

## Runtime dependencies

Installed by `pip install axross`.

<!-- third-party:runtime -->
| Package | SPDX license | Upstream |
|---|---|---|
| cryptography | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| keyring | MIT | https://github.com/jaraco/keyring |
| paramiko | LGPL-2.1-or-later | https://github.com/paramiko/paramiko |
| Pillow | MIT-CMU | https://github.com/python-pillow/Pillow |
| Pygments | BSD-2-Clause | https://github.com/pygments/pygments |
| PyQt6 | GPL-3.0-only OR LicenseRef-Riverbank-Commercial | https://www.riverbankcomputing.com/software/pyqt/ |
| PySocks | BSD-3-Clause | https://github.com/Anorov/PySocks |
| pywinpty | MIT | https://github.com/andfoy/pywinpty |
<!-- /third-party:runtime -->

## Optional (per-extra) dependencies

<!-- third-party:extras -->
| Extra | Package | SPDX license | Upstream |
|---|---|---|---|
| `[adb]` | adb_shell | Apache-2.0 | https://github.com/JeffLIrion/adb_shell |
| `[archive]` | backports.zstd | PSF-2.0 | https://github.com/rogdham/backports.zstd |
| `[archive]` | py7zr | LGPL-2.1-or-later | https://github.com/miurahr/py7zr |
| `[archive]` | rarfile | ISC | https://github.com/markokr/rarfile |
| `[azure]` | azure-storage-blob | MIT | https://github.com/Azure/azure-sdk-for-python |
| `[azure]` | azure-storage-file-share | MIT | https://github.com/Azure/azure-sdk-for-python |
| `[dns]` | dnspython | ISC | https://github.com/rthalley/dnspython |
| `[dropbox]` | dropbox | MIT | https://github.com/dropbox/dropbox-sdk-python |
| `[encoding]` | chardet | 0BSD | https://github.com/chardet/chardet |
| `[exchange]` | exchangelib | BSD-2-Clause | https://github.com/ecederstrand/exchangelib |
| `[fuse]` | fusepy | ISC | https://github.com/fusepy/fusepy |
| `[gdrive]` | google-api-python-client | Apache-2.0 | https://github.com/googleapis/google-api-python-client |
| `[gdrive]` | google-auth-httplib2 | Apache-2.0 | https://github.com/googleapis/google-cloud-python |
| `[gdrive]` | google-auth-oauthlib | Apache-2.0 | https://github.com/googleapis/google-cloud-python |
| `[git]` | dulwich | Apache-2.0 OR GPL-2.0-or-later | https://github.com/dulwich/dulwich |
| `[git]` | urllib3 | MIT | https://github.com/urllib3/urllib3 |
| `[ldap]` | ldap3 | LGPL-3.0-or-later | https://github.com/cannatag/ldap3 |
| `[mac]` | manuf | Apache-2.0 OR GPL-3.0-or-later | https://github.com/coolbho3k/manuf |
| `[magic]` | puremagic | MIT | https://github.com/cdgriffith/puremagic |
| `[media]` | numpy | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | https://github.com/numpy/numpy |
| `[metadata]` | pypdf | BSD-3-Clause | https://github.com/py-pdf/pypdf |
| `[mongo]` | pymongo | Apache-2.0 | https://github.com/mongodb/mongo-python-driver |
| `[ntp]` | ntplib | MIT | https://github.com/cf-natali/ntplib |
| `[onedrive]` | msal | MIT | https://github.com/AzureAD/microsoft-authentication-library-for-python |
| `[onedrive]` | requests | Apache-2.0 | https://github.com/psf/requests |
| `[postgres]` | psycopg | LGPL-3.0-only | https://github.com/psycopg/psycopg |
| `[redis]` | redis | MIT | https://github.com/redis/redis-py |
| `[s3]` | boto3 | Apache-2.0 | https://github.com/boto/boto3 |
| `[sift]` | sift-summarizer | MIT | https://github.com/c0decave/sift |
| `[smb]` | smbprotocol | MIT | https://github.com/jborean93/smbprotocol |
| `[snmp]` | pysnmp | BSD-2-Clause | https://github.com/lextudio/pysnmp |
| `[tftp]` | tftpy | MIT | https://github.com/msoulier/tftpy |
| `[voice]` | ctranslate2 | MIT | https://github.com/OpenNMT/CTranslate2 |
| `[voice]` | faster-whisper | MIT | https://github.com/SYSTRAN/faster-whisper |
| `[voice]` | onnxruntime | MIT | https://github.com/microsoft/onnxruntime |
| `[voice]` | piper-tts | GPL-3.0-or-later | https://github.com/OHF-voice/piper1-gpl |
| `[webdav]` | defusedxml | PSF-2.0 | https://github.com/tiran/defusedxml |
| `[webdav]` | requests | Apache-2.0 | https://github.com/psf/requests |
| `[whois]` | ipwhois | BSD-2-Clause | https://github.com/secynic/ipwhois |
| `[winrm]` | pywinrm | MIT | https://github.com/diyan/pywinrm |
| `[wmi]` | impacket | LicenseRef-Impacket-Apache-1.1-modified | https://github.com/fortra/impacket |
<!-- /third-party:extras -->

## Binaries bundled in axross-full (Linux)

Static builds fetched by `Dockerfile.build` with pinned SHA-256 sums; their
licence files ship in the bundle under `licenses/search-tools/`.

<!-- third-party:programs -->
| Tool | Binary | SPDX license | Purpose |
|---|---|---|---|
| fd 10.5.0 | `fd` | MIT OR Apache-2.0 | Find Files: name search |
| ripgrep 15.2.0 | `rg` | MIT OR Unlicense | Find Files: content search |
<!-- /third-party:programs -->

## Speech components bundled in axross-full

The Agent dock's voice (`axross[voice]`) is part of axross-full. Its
packages ship in the bundle; the voices and the speech recognition models
are not bundled - Help > Features… downloads them (pinned SHA-256,
`core/voice_models.py`).

<!-- third-party:voice -->
| Component | SPDX license | Note |
|---|---|---|
| ctranslate2 4.8.3 | MIT | Runs the Whisper speech recognition models |
| espeak-ng 1.52.0.1 (commit 724808c5a83f9ef95fdd0db886ba7ba537ff224a) | GPL-3.0-or-later | Phonemes for the Piper voices (statically linked into piper's espeakbridge, with its data) |
| faster-whisper 1.2.1 | MIT | Local speech recognition of the Agent dock |
| onnxruntime 1.31.0 | MIT | Runs the Piper voice models |
| piper-tts 1.8.0 | GPL-3.0-or-later | Speech output of the Agent dock (Piper) |
| PyAV | BSD-3-Clause | Audio decoding for local speech recognition (PyAV, FFmpeg) |
| Silero VAD | MIT | Voice activity detection model that faster-whisper ships |
<!-- /third-party:voice -->

Because axross-full ships GPL-3.0-or-later code (as it already does with
PyQt6), the bundle carries the GPL-3 text (`licenses/voice/COPYING`, from
piper's distribution) and a written offer for the corresponding source
(`licenses/voice/SOURCE-OFFER.txt`, kept in `build/licenses/voice/`).

## Downloaded at run time, not bundled

<!-- third-party:downloads -->
| Data | SPDX license | Note |
|---|---|---|
| faster-whisper models (Whisper base, small) | MIT | Local speech recognition models, downloaded in Help > Features…; Systran's CTranslate2 conversions of OpenAI Whisper (MIT) |
| Piper voices 1.0.0 | MIT | The Agent dock's voices, downloaded in Help > Features…; each voice's dataset terms are in its MODEL_CARD (Thorsten CC0; Kerstin, Ryan and Lessac as stated there) |
<!-- /third-party:downloads -->

## Python packages inside the binaries

Every Python distribution inside `axross-full` / `axross-slim` (Linux). The
build copies each one's own licence files (and SBOMs where the wheel has
them) into the bundle under `licenses/python/<name>-<version>/`
(`scripts/bundle_licenses.py`).

<!-- third-party:python-binaries -->
| Package | SPDX license | Used for | In |
|---|---|---|---|
| [adb_shell](https://github.com/JeffLIrion/adb_shell) | Apache-2.0 | Android devices over ADB | full, slim |
| [anyio](https://github.com/agronholm/anyio) | MIT | Used by httpx2: High-level concurrency and networking framework on top of asyncio or Trio | full, slim |
| [attrs](https://github.com/python-attrs/attrs) | MIT | Used by jsonschema: Classes Without Boilerplate | full, slim |
| [azure-core](https://github.com/Azure/azure-sdk-for-python) | MIT | Used by azure-storage-blob: Microsoft Azure Core Library for Python | full |
| [azure-storage-blob](https://github.com/Azure/azure-sdk-for-python) | MIT | Azure Blob Storage backend | full |
| [azure-storage-file-share](https://github.com/Azure/azure-sdk-for-python) | MIT | Azure Files backend | full |
| [backports.zstd](https://github.com/rogdham/backports.zstd) | PSF-2.0 | Zstandard compression on Python versions before 3.14 | full, slim |
| [bcrypt](https://github.com/pyca/bcrypt) | Apache-2.0 | Used by paramiko: Modern password hashing for your software and your servers | full, slim |
| [blinker](https://github.com/pallets-eco/blinker) | MIT | Used by Flask: Fast, simple object-to-object and broadcast signaling | full |
| [boto3](https://github.com/boto/boto3) | Apache-2.0 | Amazon S3 and S3-compatible storage | full, slim |
| [botocore](https://github.com/boto/botocore) | Apache-2.0 | Used by boto3: Low-level, data-driven core of boto 3 | full, slim |
| [brotli](https://github.com/google/brotli) | MIT | Used by py7zr: Python bindings for the Brotli compression library | full, slim |
| [cached-property](https://github.com/pydanny/cached-property) | BSD-3-Clause | Used by exchangelib: A decorator for caching properties in classes | full |
| [certifi](https://github.com/certifi/python-certifi) | MPL-2.0 | Mozilla's CA certificate bundle for TLS verification | full, slim |
| [cffi](https://github.com/python-cffi/cffi) | MIT-0 | Used by cryptography: Foreign Function Interface for Python calling C code | full, slim |
| [chardet](https://github.com/chardet/chardet) | 0BSD | Text encoding detection | full, slim |
| [charset-normalizer](https://github.com/jawah/charset_normalizer) | MIT | Used by impacket: The Real First Universal Charset Detector. Open, modern and actively maintained alternativ | full, slim |
| [click](https://github.com/pallets/click) | BSD-3-Clause | Used by Flask: Composable command line interface toolkit | full, slim |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | Encrypted overlay, certificate inspection; cryptography for SSH and TLS | full, slim |
| [ctranslate2](https://github.com/OpenNMT/CTranslate2) | MIT | Runs the Whisper speech recognition models | full |
| [defusedxml](https://github.com/tiran/defusedxml) | PSF-2.0 | Safe XML parsing (WebDAV responses and other XML input) | full, slim |
| [dnspython](https://github.com/rthalley/dnspython) | ISC | DNS lookups (scripting helpers and SRV discovery) | full, slim |
| [dropbox](https://github.com/dropbox/dropbox-sdk-python) | MIT | Dropbox backend | full |
| [dulwich](https://github.com/dulwich/dulwich) | Apache-2.0 OR GPL-2.0-or-later | Git repositories as a file system | full, slim |
| [exchangelib](https://github.com/ecederstrand/exchangelib) | BSD-2-Clause | Microsoft Exchange backend (EWS) | full |
| [faster-whisper](https://github.com/SYSTRAN/faster-whisper) | MIT | Local speech recognition of the Agent dock | full |
| [filelock](https://github.com/tox-dev/py-filelock) | MIT | Used by huggingface_hub: A platform independent file lock | full |
| [Flask](https://github.com/pallets/flask) | BSD-3-Clause | Used by impacket: A simple framework for building complex web applications | full |
| [fsspec](https://github.com/fsspec/filesystem_spec) | BSD-3-Clause | Used by huggingface_hub: File-system specification | full |
| [fusepy](https://github.com/fusepy/fusepy) | ISC | Mounting an axross connection as a local folder (FUSE) | full, slim |
| [google-api-core](https://github.com/googleapis/google-cloud-python) | Apache-2.0 | Used by google-api-python-client: Google API client core library | full |
| [google-api-python-client](https://github.com/googleapis/google-api-python-client) | Apache-2.0 | Google Drive backend | full |
| [google-auth](https://github.com/googleapis/google-cloud-python) | Apache-2.0 | Used by google-api-python-client: Google Authentication Library | full |
| [google-auth-httplib2](https://github.com/googleapis/google-cloud-python) | Apache-2.0 | HTTP transport of the Google Drive client | full |
| [google-auth-oauthlib](https://github.com/googleapis/google-cloud-python) | Apache-2.0 | Google sign-in (OAuth) for Google Drive | full |
| [googleapis-common-protos](https://github.com/googleapis/google-cloud-python) | Apache-2.0 | Used by google-api-core: Common protobufs used in Google APIs | full |
| [h11](https://github.com/python-hyper/h11) | MIT | Used by httpcore2: A pure-Python, bring-your-own-I/O implementation of HTTP/1.1 | full, slim |
| [hf-xet](https://github.com/huggingface/xet-core) | Apache-2.0 | Used by huggingface_hub: Fast transfer of large files with the Hugging Face Hub | full |
| [httpcore2](https://github.com/pydantic/httpx2) | BSD-3-Clause | Used by httpx2: A minimal low-level HTTP client | full, slim |
| [httplib2](https://github.com/httplib2/httplib2) | MIT | Used by google-api-python-client: A comprehensive HTTP client library | full |
| [httpx2](https://github.com/pydantic/httpx2) | BSD-3-Clause | Used by huggingface_hub: The next generation HTTP client | full, slim |
| [huggingface_hub](https://github.com/huggingface/huggingface_hub) | Apache-2.0 | Used by faster-whisper: Client library to download and publish models, datasets and other repos on the huggingface | full |
| [idna](https://github.com/kjd/idna) | BSD-3-Clause | Used by requests: Internationalized Domain Names in Applications (IDNA) | full, slim |
| [impacket](https://github.com/fortra/impacket) | LicenseRef-Impacket-Apache-1.1-modified | WMI / DCOM and SMB tooling for Windows hosts | full |
| [inflate64](https://github.com/miurahr/inflate64) | LGPL-2.1-or-later | Used by py7zr: deflate64 compression/decompression library | full, slim |
| [invoke](https://github.com/pyinvoke/invoke) | BSD-2-Clause | Used by paramiko: Pythonic task execution | full, slim |
| [ipwhois](https://github.com/secynic/ipwhois) | BSD-2-Clause | WHOIS / RDAP lookups | full, slim |
| [isodate](https://github.com/gweis/isodate) | BSD-3-Clause | Used by azure-storage-blob: An ISO 8601 date/time/duration parser and formatter | full |
| [itsdangerous](https://github.com/pallets/itsdangerous) | BSD-3-Clause | Used by Flask: Safely pass data to untrusted environments and back | full |
| [jaraco.classes](https://github.com/jaraco/jaraco.classes) | MIT | Used by keyring: Utility functions for Python class constructs | full, slim |
| [jaraco.context](https://github.com/jaraco/jaraco.context) | MIT | Used by keyring: Useful decorators and context managers | full, slim |
| [jaraco.functools](https://github.com/jaraco/jaraco.functools) | MIT | Used by keyring: Functools like those found in stdlib | full, slim |
| [jeepney](https://gitlab.com/takluyver/jeepney) | MIT | Used by keyring: Low-level, pure Python DBus protocol wrapper | full, slim |
| [Jinja2](https://github.com/pallets/jinja) | BSD-3-Clause | Used by Flask: A very fast and expressive template engine | full |
| [jmespath](https://github.com/jmespath/jmespath.py) | MIT | Used by boto3: JSON Matching Expressions | full, slim |
| [jsonschema](https://github.com/python-jsonschema/jsonschema) | MIT | Validates MCP tool arguments against their schemas | full, slim |
| [jsonschema-specifications](https://github.com/python-jsonschema/jsonschema-specifications) | MIT | Used by jsonschema: The JSON Schema meta-schemas and vocabularies, exposed as a Registry | full, slim |
| [keyring](https://github.com/jaraco/keyring) | MIT | Stores profile passwords in the operating system's keyring | full, slim |
| [ldap3](https://github.com/cannatag/ldap3) | LGPL-3.0-or-later | LDAP backend and helpers | full, slim |
| [lxml](https://github.com/lxml/lxml) | BSD-3-Clause | Used by exchangelib: Powerful and Pythonic XML processing library combining libxml2/libxslt with the ElementTre | full |
| [manuf](https://github.com/coolbho3k/manuf) | Apache-2.0 OR GPL-3.0-or-later | MAC address vendor lookup (Wireshark OUI database) | full, slim |
| [MarkupSafe](https://github.com/pallets/markupsafe) | BSD-3-Clause | Used by Flask: Safely add untrusted strings to HTML/XML markup | full |
| [more-itertools](https://github.com/more-itertools/more-itertools) | MIT | Used by jaraco.classes: More routines for operating on iterables, beyond itertools | full, slim |
| [msal](https://github.com/AzureAD/microsoft-authentication-library-for-python) | MIT | Microsoft sign-in for OneDrive and SharePoint | full |
| [multivolumefile](https://github.com/miurahr/multivolume) | LGPL-2.1-or-later | Used by py7zr: multi volume file wrapper library | full, slim |
| [ntplib](https://github.com/cf-natali/ntplib) | MIT | NTP time queries | full, slim |
| [numpy](https://github.com/numpy/numpy) | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | Equalizer and spectrum of the Media Player extension | full |
| [oauthlib](https://github.com/oauthlib/oauthlib) | BSD-3-Clause | Used by exchangelib: A generic, spec-compliant, thorough implementation of the OAuth request-signing logic | full |
| [onnxruntime](https://github.com/microsoft/onnxruntime) | MIT | Runs the Piper voice models | full |
| [opentelemetry-api](https://github.com/open-telemetry/opentelemetry-python) | Apache-2.0 | Used by google-api-core: OpenTelemetry Python API | full, slim |
| [packaging](https://github.com/pypa/packaging) | Apache-2.0 OR BSD-2-Clause | Used by onnxruntime: Core utilities for Python packages | full |
| [paramiko](https://github.com/paramiko/paramiko) | LGPL-2.1-or-later | SSH, SFTP and SCP connections | full, slim |
| [pathvalidate](https://github.com/thombashi/pathvalidate) | MIT | Used by piper-tts: pathvalidate is a Python library to sanitize/validate a string such as filenames/file-path | full |
| [Pillow](https://github.com/python-pillow/Pillow) | MIT-CMU | Image thumbnails, image metadata and the image viewer | full, slim |
| [piper-tts](https://github.com/OHF-voice/piper1-gpl) | GPL-3.0-or-later | Speech output of the Agent dock (Piper) | full |
| [protobuf](https://github.com/protocolbuffers/protobuf) | BSD-3-Clause | Used by onnxruntime | full |
| [psutil](https://github.com/giampaolo/psutil) | BSD-3-Clause | Drive overview extension; process information | full, slim |
| [psycopg](https://github.com/psycopg/psycopg) | LGPL-3.0-only | PostgreSQL backend | full, slim |
| [psycopg-binary](https://github.com/psycopg/psycopg) | LGPL-3.0-only | Compiled PostgreSQL driver with libpq | full, slim |
| [puremagic](https://github.com/cdgriffith/puremagic) | MIT | File type detection from file content | full, slim |
| [py7zr](https://github.com/miurahr/py7zr) | LGPL-2.1-or-later | 7z archives (browse, extract, pack) | full, slim |
| [pyasn1](https://github.com/pyasn1/pyasn1) | BSD-2-Clause | ASN.1 decoding (LDAP, SNMP) | full, slim |
| [pyasn1_modules](https://github.com/pyasn1/pyasn1-modules) | BSD-2-Clause | Used by impacket: A collection of ASN.1-based protocols modules | full |
| [PyAV](https://github.com/PyAV-Org/PyAV) | BSD-3-Clause | Audio decoding for local speech recognition (PyAV, FFmpeg) | full |
| [pybcj](https://github.com/miurahr/pybcj) | LGPL-2.1-or-later | Used by py7zr: bcj filter library | full, slim |
| [pycparser](https://github.com/eliben/pycparser) | BSD-3-Clause | Used by cffi: C parser in Python | full, slim |
| [pycryptodomex](https://github.com/Legrandin/pycryptodome) | BSD-2-Clause AND LicenseRef-PublicDomain | Used by impacket: Cryptographic library for Python | full, slim |
| [Pygments](https://github.com/pygments/pygments) | BSD-2-Clause | Syntax highlighting in the text editor | full, slim |
| [PyJWT](https://github.com/jpadilla/pyjwt) | MIT | Used by msal: JSON Web Token implementation in Python | full, slim |
| [pymongo](https://github.com/mongodb/mongo-python-driver) | Apache-2.0 | MongoDB / GridFS backend | full, slim |
| [PyNaCl](https://github.com/pyca/pynacl) | Apache-2.0 | Used by paramiko: Python binding to the Networking and Cryptography (NaCl) library | full, slim |
| [pyOpenSSL](https://github.com/pyca/pyopenssl) | Apache-2.0 | Used by impacket: Python wrapper module around the OpenSSL library | full, slim |
| [pyparsing](https://github.com/pyparsing/pyparsing) | MIT | Used by httplib2: pyparsing - Classes and methods to define and execute parsing grammars | full |
| [pypdf](https://github.com/py-pdf/pypdf) | BSD-3-Clause | Removing PDF metadata | full, slim |
| [pyppmd](https://github.com/miurahr/pyppmd) | LGPL-2.1-or-later | Used by py7zr: PPMd compression/decompression library | full, slim |
| [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) | GPL-3.0-only OR LicenseRef-Riverbank-Commercial | Python bindings for Qt: the whole user interface | full, slim |
| [PyQt6_sip](https://github.com/Python-SIP/sip) | BSD-2-Clause | Runtime support module of the PyQt6 bindings | full, slim |
| [pysnmp](https://github.com/lextudio/pysnmp) | BSD-2-Clause | SNMP helpers | full, slim |
| [PySocks](https://github.com/Anorov/PySocks) | BSD-3-Clause | SOCKS4/5 proxies for every connection | full, slim |
| [pyspnego](https://github.com/jborean93/pyspnego) | MIT | NTLM / Kerberos (Negotiate) authentication for proxies and SMB | full, slim |
| [python-dateutil](https://github.com/dateutil/dateutil) | Apache-2.0 AND BSD-3-Clause | Used by botocore: Extensions to the standard Python datetime module | full, slim |
| [pywinrm](https://github.com/diyan/pywinrm) | MIT | WinRM backend (Windows Remote Management) | full |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | Used by ctranslate2: YAML parser and emitter for Python | full, slim |
| [rarfile](https://github.com/markokr/rarfile) | ISC | RAR archives (browse, extract) | full, slim |
| [redis](https://github.com/redis/redis-py) | MIT | Redis backend | full, slim |
| [referencing](https://github.com/python-jsonschema/referencing) | MIT | Used by jsonschema: JSON Referencing + Python | full, slim |
| [requests](https://github.com/psf/requests) | Apache-2.0 | HTTP client of the WebDAV, OneDrive and other HTTP backends | full, slim |
| [requests-oauthlib](https://github.com/requests/requests-oauthlib) | ISC | Used by exchangelib: OAuthlib authentication support for Requests | full |
| [requests_ntlm](https://github.com/requests/requests-ntlm) | ISC | Used by exchangelib: This package allows for HTTP NTLM authentication using the requests library | full |
| [rpds-py](https://github.com/crate-py/rpds) | MIT | Used by jsonschema: Python bindings to Rust's persistent data structures (rpds) | full, slim |
| [rsa](https://github.com/sybrenstuvel/python-rsa) | Apache-2.0 | Used by adb_shell: Pure-Python RSA implementation | full, slim |
| [s3transfer](https://github.com/boto/s3transfer) | Apache-2.0 | Used by boto3: An Amazon S3 Transfer Manager | full, slim |
| [SecretStorage](https://github.com/mitya57/secretstorage) | BSD-3-Clause | Used by keyring: Python bindings to FreeDesktop.org Secret Service API | full, slim |
| [sift-summarizer](https://github.com/c0decave/sift) | MIT | sift: the Analysis dock's explanation of the selected file | full |
| [six](https://github.com/benjaminp/six) | MIT | Used by impacket: Python 2 and 3 compatibility utilities | full, slim |
| [smbprotocol](https://github.com/jborean93/smbprotocol) | MIT | SMB / CIFS file shares | full, slim |
| [stone](https://github.com/dropbox/stone) | MIT | Used by dropbox: Stone is an interface description language (IDL) for APIs | full |
| [tftpy](https://github.com/msoulier/tftpy) | MIT | TFTP backend | full, slim |
| [tokenizers](https://github.com/huggingface/tokenizers) | Apache-2.0 | Used by faster-whisper | full |
| [tqdm](https://github.com/tqdm/tqdm) | MPL-2.0 AND MIT | Used by faster-whisper: Fast, Extensible Progress Meter | full |
| [truststore](https://github.com/sethmlarson/truststore) | MIT | Used by httpcore2: Verify certificates using native system trust stores | full, slim |
| [typing_extensions](https://github.com/python/typing_extensions) | PSF-2.0 | Used by azure-storage-blob: Backported and Experimental Type Hints for Python 3.9+ | full, slim |
| [tzdata](https://github.com/python/tzdata) | Apache-2.0 | Used by exchangelib: Provider of IANA time zone data | full |
| [tzlocal](https://github.com/regebro/tzlocal) | MIT | Used by exchangelib: tzinfo object for the local timezone | full |
| [uritemplate](https://github.com/python-hyper/uritemplate) | BSD-3-Clause OR Apache-2.0 | Used by google-api-python-client: Implementation of RFC 6570 URI Templates | full |
| [urllib3](https://github.com/urllib3/urllib3) | MIT | HTTP connection pool (proxies, S3, WebDAV) | full, slim |
| [Werkzeug](https://github.com/pallets/werkzeug) | BSD-3-Clause | Used by Flask: The comprehensive WSGI web application library | full |
| [xmltodict](https://github.com/martinblech/xmltodict) | MIT | Used by pywinrm: Makes working with XML feel like you are working with JSON | full |
<!-- /third-party:python-binaries -->

## Native libraries and data inside the binaries

Shared libraries come from the Python wheels (Qt, Pillow, PyAV, psycopg,
numpy, CTranslate2) and from the builder image (AlmaLinux 9). For every
library the builder image contributes, the build copies the licence files of
its rpm package into `licenses/system/<package>/` and names the package in
`licenses/system/LIBRARIES.txt`. For the wheels' libraries the bundle has
what the wheel itself ships under `licenses/python/`: Pillow and numpy list
the licences of the libraries they bundle; the PyQt6-Qt6 wheel carries only
the LGPL-3.0 text (not ICU's or FFmpeg's), and the PyAV, psycopg-binary and
CTranslate2 wheels carry no texts for their bundled libraries (FFmpeg, x264,
x265, libpq, OpenSSL, ...). Four rpm packages of the builder image carry no
licence text at all (libxcb, lz4-libs, sqlite-libs, xcb-util-keysyms).

<!-- third-party:native-binaries -->
| Component | SPDX license | Used for | In |
|---|---|---|---|
| [alsa-lib](https://github.com/alsa-project/alsa-lib) | LGPL-2.1-or-later | ALSA device support of PyAV's FFmpeg | full |
| [Brotli (C library)](https://github.com/google/brotli) | MIT | Brotli decompression (Pillow, FreeType) | full, slim |
| [bzip2](https://sourceware.org/bzip2/) | bzip2-1.0.6 | bzip2 compression (Python's bz2 module) | full, slim |
| [Cyrus SASL](https://www.cyrusimap.org/sasl/) | BSD-Attribution-HPND-disclaimer | SASL authentication of the OpenLDAP client | full, slim |
| [D-Bus](https://www.freedesktop.org/wiki/Software/dbus/) | AFL-2.1 OR GPL-2.0-or-later | Desktop bus access of Qt (notifications, portals, keyring) | full, slim |
| [dav1d](https://code.videolan.org/videolan/dav1d) | BSD-2-Clause | AV1 decoder library of PyAV's FFmpeg | full |
| [espeak-ng](https://github.com/espeak-ng/espeak-ng) 1.52.0.1 (commit 724808c5a83f9ef95fdd0db886ba7ba537ff224a) | GPL-3.0-or-later | Phonemes for the Piper voices (statically linked into piper's espeakbridge, with its data) | full |
| [Expat](https://libexpat.github.io) | MIT | XML parsing (Python's xml modules) | full, slim |
| [FFmpeg (PyAV build)](https://ffmpeg.org) | LGPL-3.0-or-later | Audio decoding for local speech recognition; the build reports "libavcodec license: LGPL version 3 or later"; it loads the x264 and x265 libraries below | full |
| [FFmpeg (Qt Multimedia build)](https://ffmpeg.org) 7.1.2 | LGPL-2.1-or-later | Audio and video decoding of the media viewer and the Media Player (Qt Multimedia); the build reports "libavcodec license: LGPL version 2.1 or later" | full, slim |
| [FreeType](https://freetype.org) | FTL OR GPL-2.0-or-later | Font rendering of Pillow | full, slim |
| [GCC runtime libraries](https://gcc.gnu.org) | GPL-3.0-or-later WITH GCC-exception-3.1 | Fortran, OpenMP and atomic runtimes (numpy, CTranslate2, QtPdf); libquadmath is LGPL-2.1-or-later | full, slim |
| [GLib](https://gitlab.gnome.org/GNOME/glib) | LGPL-2.1-or-later | Main loop and D-Bus integration of Qt's platform plugins | full, slim |
| [GMP](https://gmplib.org) | LGPL-3.0-or-later OR GPL-2.0-or-later | Arbitrary-precision arithmetic used by Nettle | full |
| [GNU dbm](https://www.gnu.org.ua/software/gdbm/) | GPL-3.0-or-later | Key-value files of Python's dbm module | full |
| [GNU Readline](https://tiswww.case.edu/php/chet/readline/rltop.html) | GPL-3.0-or-later | Line editing of Python's readline module | full, slim |
| [GnuTLS](https://www.gnutls.org) | LGPL-2.1-or-later | TLS for network streams of PyAV's FFmpeg | full |
| [Graphite](https://github.com/silnrsi/graphite) | LGPL-2.1-or-later OR MPL-1.1 OR GPL-2.0-or-later | Smart-font rendering used by HarfBuzz | full, slim |
| [HarfBuzz](https://github.com/harfbuzz/harfbuzz) | MIT | Text shaping (Qt, Pillow) | full, slim |
| [ICU](https://icu.unicode.org) 73.2 | Unicode-DFS-2016 | Unicode support of Qt (collation, conversion, text boundaries) | full, slim |
| [Intel VPL dispatcher](https://github.com/intel/libvpl) | MIT | Hardware video acceleration dispatcher of PyAV's FFmpeg | full |
| [JBIG-KIT](https://www.cl.cam.ac.uk/~mgk25/jbigkit/) | GPL-2.0-or-later | JBIG compression used by the system LibTIFF | full, slim |
| [keyutils](https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git) | LGPL-2.1-or-later | Kernel key retention used by MIT Kerberos | full, slim |
| [libavif](https://github.com/AOMediaCodec/libavif) | BSD-2-Clause | AVIF images in Pillow | full, slim |
| [libcap](https://sites.google.com/site/fullycapable/) | BSD-3-Clause OR GPL-2.0-only | POSIX capabilities used by libsystemd | full, slim |
| [libdrm](https://gitlab.freedesktop.org/mesa/drm) | MIT | Direct Rendering Manager access of PyAV's FFmpeg | full |
| [libffi](https://sourceware.org/libffi/) | MIT | Foreign function calls (Python's ctypes, cffi) | full, slim |
| [libfuse 2](https://github.com/libfuse/libfuse) | LGPL-2.1-only | Kernel FUSE interface of the FUSE mounts (fusepy) | full, slim |
| [Libgcrypt and libgpg-error](https://www.gnupg.org/software/libgcrypt/) | LGPL-2.1-or-later | Cryptography used by libsystemd | full, slim |
| [libjpeg-turbo](https://libjpeg-turbo.org) | IJG AND BSD-3-Clause | JPEG images (Pillow, Qt image plugins) | full, slim |
| [libpng](https://www.libpng.org) | libpng-2.0 | PNG images (Pillow, Qt) | full, slim |
| [libpq](https://www.postgresql.org) | PostgreSQL | PostgreSQL client library of psycopg | full, slim |
| [libselinux](https://github.com/SELinuxProject/selinux) | LicenseRef-PublicDomain | SELinux library used by GLib and libpq | full, slim |
| [libsystemd](https://systemd.io) | LGPL-2.1-or-later AND MIT | Journal and D-Bus helpers used by system libraries | full, slim |
| [LibTIFF](https://libtiff.gitlab.io/libtiff/) | libtiff | TIFF images (Pillow, Qt image plugin) | full, slim |
| [libunistring](https://www.gnu.org/software/libunistring/) | LGPL-3.0-or-later OR GPL-2.0-or-later | Unicode string functions used by GnuTLS | full |
| [libvpx](https://chromium.googlesource.com/webm/libvpx) | BSD-3-Clause | VP8/VP9 codec library of PyAV's FFmpeg | full |
| [libwebp](https://chromium.googlesource.com/webm/libwebp) | BSD-3-Clause | WebP images (Pillow, Qt image plugin) | full, slim |
| [libxcb and xcb-util](https://xcb.freedesktop.org) | MIT | X protocol bindings of Qt's xcb platform plugin | full, slim |
| [libxcrypt](https://github.com/besser82/libxcrypt) | LGPL-2.1-or-later | Password hashing library used by libpq | full, slim |
| [libxkbcommon](https://xkbcommon.org) | MIT | Keyboard handling of Qt (X11 and Wayland) | full, slim |
| [libxml2](https://gitlab.gnome.org/GNOME/libxml2) | MIT | XML library used by system libraries | full, slim |
| [Little CMS](https://www.littlecms.com) | MIT | Colour management in Pillow | full, slim |
| [LZ4](https://github.com/lz4/lz4) | BSD-2-Clause | LZ4 compression used by system libraries | full, slim |
| [MIT Kerberos](https://web.mit.edu/kerberos/) | MIT | Kerberos / GSSAPI (libpq, system libraries); libcom_err comes from e2fsprogs (MIT) | full, slim |
| [mpdecimal](https://www.bytereef.org/mpdecimal/) | BSD-2-Clause | Decimal arithmetic of Python's decimal module | full, slim |
| [ncurses (libtinfo)](https://invisible-island.net/ncurses/) | X11 | Terminal capabilities used by Readline | full, slim |
| [Nettle](https://www.lysator.liu.se/~nisse/nettle/) | LGPL-3.0-or-later OR GPL-2.0-or-later | Cryptographic library used by GnuTLS | full |
| [OpenBLAS](https://github.com/OpenMathLib/OpenBLAS) | BSD-3-Clause | Linear algebra of numpy | full |
| [OpenJPEG](https://www.openjpeg.org) | BSD-2-Clause | JPEG 2000 images in Pillow | full, slim |
| [OpenLDAP client libraries](https://www.openldap.org) | OLDAP-2.8 | LDAP support of libpq | full, slim |
| [OpenSSL](https://www.openssl.org) | Apache-2.0 | TLS and cryptography (Python's ssl module, Qt, libpq) | full, slim |
| [Opus](https://opus-codec.org) | BSD-3-Clause | Opus audio codec library of PyAV's FFmpeg | full |
| [PCRE and PCRE2](https://www.pcre.org) | BSD-3-Clause | Regular expressions used by GLib and libselinux | full, slim |
| [Python](https://www.python.org) 3.12 | PSF-2.0 | The Python interpreter and standard library inside the binaries | full, slim |
| [Qt 6](https://www.qt.io) | LGPL-3.0-only | The GUI toolkit: widgets, graphics, PDF, SVG, multimedia, networking; Qt libraries and plugins as packaged in the PyQt6-Qt6 wheel | full, slim |
| [sift](https://github.com/c0decave/sift) | MIT | The Analysis dock's file explanations (sift-summarizer); a sister project of axross | full |
| [Silero VAD](https://github.com/snakers4/silero-vad) | MIT | Voice activity detection model that faster-whisper ships | full |
| [SQLite](https://www.sqlite.org) | blessing | Embedded database (Python's sqlite3 module) | full, slim |
| [SVT-AV1](https://gitlab.com/AOMediaCodec/SVT-AV1) | BSD-3-Clause-Clear | AV1 encoder library of PyAV's FFmpeg | full |
| [util-linux libraries](https://github.com/util-linux/util-linux) | LGPL-2.1-or-later AND BSD-3-Clause | UUIDs, block device and mount information (GLib, Python's uuid module); libuuid is BSD-3-Clause | full, slim |
| [VMAF](https://github.com/Netflix/vmaf) | BSD-2-Clause-Patent | Video quality metric library of PyAV's FFmpeg | full |
| [X.Org client libraries](https://www.x.org) | MIT AND X11 | X11 display connection of Qt's xcb platform plugin | full, slim |
| [x264](https://www.videolan.org/developers/x264.html) | GPL-2.0-or-later | H.264 encoder library linked by PyAV's FFmpeg | full |
| [x265](https://bitbucket.org/multicoreware/x265_git) | GPL-2.0-or-later | HEVC encoder library linked by PyAV's FFmpeg | full |
| [XZ Utils (liblzma)](https://tukaani.org/xz/) | 0BSD AND LicenseRef-PublicDomain | LZMA/XZ compression (Python's lzma module, Pillow); the system copy (xz 5.2) is public domain, Pillow's copy (5.8) 0BSD | full, slim |
| [zlib](https://zlib.net) | Zlib | Deflate compression (Python, Qt and many libraries) | full, slim |
| [Zstandard](https://github.com/facebook/zstd) | BSD-3-Clause OR GPL-2.0-only | Zstandard compression (Pillow, system libraries) | full, slim |
<!-- /third-party:native-binaries -->

## System tools invoked via subprocess

These are not shipped with Axross; users install them through their distro
package manager. They are listed for transparency about the process boundary
Axross calls out to.

<!-- third-party:host -->
| Tool | SPDX license | Purpose |
|---|---|---|
| [Bubblewrap (bwrap)](https://github.com/containers/bubblewrap) | LGPL-2.1-or-later | Agent sandbox |
| [Docker](https://www.docker.com) | Apache-2.0 | Agent sandbox and MCP server containers |
| [FFmpeg (ffmpeg, ffprobe)](https://ffmpeg.org) | LGPL-2.1-or-later OR GPL-2.0-or-later OR GPL-3.0-only | Video thumbnails, media details, removing audio/video metadata (distribution builds differ (Arch: GPL-3.0-only)) |
| [jmtpfs / simple-mtpfs / go-mtpfs](https://github.com/JasonFerrara/jmtpfs) | GPL-3.0-only OR GPL-2.0-or-later OR BSD-3-Clause | MTP backend (the first one found on PATH) (jmtpfs GPL-3.0, simple-mtpfs GPL-2.0, go-mtpfs BSD) |
| [nfs-utils (mount.nfs)](https://linux-nfs.org) | GPL-2.0-or-later | NFS backend |
| [open-iscsi (iscsiadm)](https://github.com/open-iscsi/open-iscsi) | GPL-2.0-or-later | iSCSI backend |
| [Podman](https://podman.io) | Apache-2.0 | Agent sandbox and MCP server containers |
| [polkit (pkexec)](https://github.com/polkit-org/polkit) | LGPL-2.0-or-later | "Open as root…" and privileged mounts |
| [qemu-img](https://www.qemu.org) | GPL-2.0-only | Opening virtual disk images |
| [rsh client (netkit-rsh or GNU Inetutils)](https://www.gnu.org/software/inetutils/) | BSD-4-Clause-UC OR GPL-3.0-or-later | rsh backend (any rsh implementation on PATH) |
| [rsync](https://rsync.samba.org) | GPL-3.0-or-later | rsync backend and fast copies |
| [Subversion](https://subversion.apache.org) | Apache-2.0 | Subversion backend |
| [TestDisk / PhotoRec](https://www.cgsecurity.org) | GPL-2.0-or-later | Recovering partitions and files |
| [The Sleuth Kit](https://www.sleuthkit.org) | IPL-1.0 AND CPL-1.0 AND GPL-2.0-or-later | Forensic file system access (fls, icat) |
| [UDisks (udisksctl)](https://github.com/storaged-project/udisks) | GPL-2.0-or-later | Loop-mounting disk images |
| [VirtualBox (VBoxManage)](https://www.virtualbox.org) | GPL-3.0-only | VirtualBox disk images |
| [xdg-utils (xdg-open)](https://gitlab.freedesktop.org/xdg/xdg-utils) | MIT | Opening files and links with the desktop's programs |
<!-- /third-party:host -->

## Containers and MCP servers

<!-- third-party:containers -->
| Project | SPDX license | Purpose | Note |
|---|---|---|---|
| [axross MCP hub](https://github.com/c0decave/axross-mcp-hub) | MIT | Catalogue of container-packaged MCP servers that the MCP catalog installs on request | each server's tool, wrapper, licence and base image are listed in servers/<name>/PROVENANCE.md of the hub |
| [Python container image (python:3.12-slim)](https://hub.docker.com/_/python) | PSF-2.0 AND LicenseRef-Debian-Packages | Base image of Dockerfile.mcp, Dockerfile.agent and Dockerfile.gui | built on Debian; each Debian package's licence is in /usr/share/doc/<package>/copyright inside the image |
<!-- /third-party:containers -->

## Notes for redistributors

- Source redistribution: retain `LICENSE`, `NOTICE`, and this file.
- Binary redistribution of a PyInstaller bundle that includes PyQt6: the
  binary inherits GPL-3.0. Ship `LICENSE` + `NOTICE` + this file alongside
  the binary, and also ensure the GPL-3.0 text is included (or linked) per
  GPL §4 requirements for offering corresponding source.
- `Dockerfile.mcp` produces a PyQt6-free image — that image is Apache-2.0
  only (no copyleft inheritance).
