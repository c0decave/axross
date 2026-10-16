# Protocol fuzzing

axross talks to servers it does not control. The fuzz suites in
`tests/test_fuzz_*.py` play the hostile server: they feed every protocol
client garbage, truncated and over-long answers, lying sizes and lengths,
invalid UTF-8, huge tokens, traversal names, deep nesting, early EOF and
stalls.

## The contract

Every backend call made against a hostile server must:

* return sane data (items with a `str` name and an `int` size), or raise
  `OSError` (or a documented subclass such as `PjlNotSupported` or
  `WebDavRequestError`). The pane and the transfer worker handle `OSError`;
* never raise one of the classes no caller handles: `IndexError`,
  `KeyError`, `ValueError`, `UnicodeError`, `AttributeError`, `TypeError`,
  `struct.error`, `RecursionError`, `OverflowError`, `MemoryError`, ...
  (`tests/fuzz_testkit.py`, `FORBIDDEN`);
* finish before a hard deadline, so a stalled server must time out;
* keep memory bounded (tested where a server could stream without end);
* list names that `core.path_policy.drop_unsafe_names` can filter, so a
  traversal name never escapes on download.

`check_contract()` in `tests/fuzz_testkit.py` runs one call in a bounded
thread and enforces the first three rules. When a call breaks the contract,
the failure message names the case (mutant number and payload prefix).

## How it works

* **Fake servers in process.** Every fake binds to `127.0.0.1` only, and no
  test reaches the network. Some protocols have no in-process server to aim
  the real library at. For those, the library boundary is replaced by a
  scripted fake: SMB uses `tests/smb_fake_client.py`, WMI a fake
  enumerator, SCP a fake paramiko client, rsh a fake rsh binary, and the
  database backends scripted adapters.
* **Deterministic mutation.** `mutants(corpus, seed, per_entry)` derives
  byte-level mutants from a corpus of valid answers with
  `random.Random(seed)`. The mutations are bit flips, truncation,
  duplication, odd tokens and huge numbers. A failing mutant is the same on
  every run. Hypothesis is not used.
* **Scripted hostile cases.** Each suite also has hand-written sad and edge
  cases (stall, hang-up, lying `Content-Length`, XXE, billion laughs,
  repeating paging cursors, endless trees), plus a happy-path test. The
  happy-path test proves that the fake speaks the protocol well enough to
  matter.

Shared kits: `fuzz_testkit.py` (contract, mutation, `ScriptedServer`),
`ftp_fuzz_server.py`, `http_fuzz_server.py`, `mail_fuzz_servers.py` (IMAP,
POP3, NNTP), `telnet_fuzz_server.py`, `snmp_fuzz_agent.py`,
`ldap_fuzz_server.py`, `sftp_hostile_kit.py` (scripted paramiko SFTP
server), `requests_fuzz_adapter.py` (a scripted transport for `requests`
and for the OneDrive, Dropbox, Google Drive and Azure SDKs),
`smb_fake_client.py` and `proxy_testkit.py`.

## What is fuzzed

| Suite | Server or boundary |
|---|---|
| `ftp` | raw fake FTP server: control replies, LIST/MLSD/NLST data, banners, PASV/EPSV |
| `sftp` | real paramiko SFTP server with scripted hostile listings, reads and hang-ups |
| `scp` | fake paramiko client: hostile `stat`/`ls`/`df` output and exit codes |
| `webdav` | raw HTTP server: PROPFIND XML (XXE, entity expansion, deep nesting), HTTP framing |
| `s3` | raw HTTP server under botocore: ListObjects/Versions XML, HEAD headers, framing |
| `azure` | Blob and Files SDKs on a scripted transport: listings, ranges, paging markers |
| `onedrive` | Graph API answers (personal and SharePoint) on a scripted transport |
| `gdrive` | googleapiclient (static discovery) with a scripted HTTP object |
| `dropbox` | Dropbox SDK on a scripted transport: route answers, errors, cursors |
| `imap`, `pop3`, `nntp` | raw line servers: untagged answers, literals, headers, charsets |
| `gopher` | raw Gopher menus and documents |
| `telnet` | fake login shell: IAC negotiation, subnegotiation, command output |
| `rsh`, `rsync` | fake rsh binary; fake rsync daemon and the list-only parser |
| `tftp` | scripted UDP server: OACK, DATA, ERROR and block numbers |
| `pjl` | fake PJL device: FSDIRLIST, FSUPLOAD, INFO |
| `slp` | SLP daemon over UDP and TCP, plus the packet parsers directly |
| `snmp` | fake SNMPv2c agent: malformed BER, odd value types, non-increasing walks |
| `ldap` | minimal in-process BER LDAP server: hostile entries and mutated BER |
| `smb` | scripted `smbclient` fake: library errors, links, endless trees |
| `wmi`, `winrm` | fake WMI enumerator; PowerShell JSON output |
| `svn` | hostile `svn --xml` output |
| `git` | mutated loose objects in the local object store |
| `dbfs` | Redis / MongoDB / PostgreSQL adapters returning hostile rows |
| `mcp` | the MCP server against a hostile client (dispatcher, stdio, HTTP) |
| `pac`, `proxy`, `socks_udp` | PAC results, HTTP CONNECT / NTLM / SOCKS handshakes, SOCKS5 UDP relay |

## Running

```sh
# The fast default sweep (about 3 minutes for all suites):
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest tests/test_fuzz_*.py

# One protocol:
.venv/bin/python -m pytest tests/test_fuzz_imap.py

# A deeper sweep: N mutants per corpus entry in every mutation loop.
AXROSS_FUZZ_ITERATIONS=500 .venv/bin/python -m pytest tests/test_fuzz_imap.py
```

`AXROSS_FUZZ_ITERATIONS` *replaces* each loop's default count. It does not
multiply it. The defaults are tuned so the whole sweep stays fast. Most of
the time goes into timeouts, because each stall case has to wait one out.
The seeds are fixed. A deeper sweep therefore extends the default sweep
instead of replacing it with different mutants. A sweep with
`AXROSS_FUZZ_ITERATIONS=200` found one defect (fixed in 0.9.21).

## Defects found and fixed

Each fix has its own regression test, written before the fix. The last
column is the version that carries the fix.

| Protocol | Defect | Fixed in |
|---|---|---|
| FTP | listing with an undecodable name raised `UnicodeDecodeError` | 0.9.6 |
| FTP | `exists()` raised `ValueError` on a non-numeric `213` SIZE reply | 0.9.7 |
| FTP | a name the session encoding cannot carry raised `UnicodeEncodeError` | 0.9.8 |
| PAC | a port in non-ASCII digits raised `ValueError` or was misread | 0.9.9 |
| HTTP proxy | `²` status / Content-Length and a bad chunk size raised `ValueError` | 0.9.10 |
| WebDAV | malformed XML, XXE and an unknown encoding escaped `_parse_propfind` | 0.9.12 |
| S3 | a broken HEAD answer escaped `stat()`/`exists()` as `ValueError`/`BotoCoreError` | 0.9.13 |
| IMAP | `IMAP4.abort`/`IMAP4.error` (BYE, dropped link) reached callers | 0.9.15 |
| IMAP | a mailbox name in broken modified UTF-7 crashed every listing | 0.9.16 |
| IMAP | a Subject in an unknown charset raised `LookupError` | 0.9.17 |
| IMAP | SEARCH tokens that are not UIDs raised `ValueError`/`UnicodeDecodeError` | 0.9.18 |
| IMAP, POP3 | an undecodable RFC 2047 word raised `HeaderParseError` | 0.9.19 |
| POP3 | an endless RETR answer was buffered without bound before the size cap | 0.9.20 |
| IMAP, POP3 | a charset name with a NUL byte raised `ValueError` | 0.9.21 |
| Gopher | an empty display name fell back to a raw selector with `/` in it | 0.9.23 |
| PJL | a cut-off FSUPLOAD was returned as the complete file | 0.9.25 |
| SLP | parser `ValueError` reached `list_dir`/`open_read` callers | 0.9.26 |
| SOCKS5 UDP | a short or fragmented datagram raised `TypeError`/`NotImplementedError` | 0.9.28 |
| telnet, SCP | malformed `stat` output raised `ValueError` | 0.9.30 |
| telnet | an unterminated subnegotiation was buffered without bound | 0.9.31 |
| SNMP | a value whose type disagrees with the MIB raised `AttributeError`/`TypeError` | 0.9.35 |
| SFTP | an over-long READ answer shifted the data: a silently wrong download | 0.9.36, 0.9.38 |
| SFTP | a dropped connection raised `SSHException`/`EOFError` | 0.9.37 |
| SFTP | a folder holding a non-UTF-8 name could not be listed; `readlink` returned bytes | 0.9.39 |
| MCP | a malformed request (bad `_meta`, list/bool cancel id, undecodable JSON) killed the server | 0.9.41 |
| OneDrive | a Graph answer of the wrong shape crashed; a repeating nextLink paged forever | 0.9.44 |
| Dropbox | SDK failures other than `ApiError` escaped; a repeating cursor paged forever | 0.9.46 |
| Google Drive | an answer of the wrong shape crashed; a repeating page token paged forever | 0.9.48 |
| Azure | short range answers gave a wrong file; a repeating marker paged forever; SDK errors escaped | 0.9.50 |
| LDAP | a BER answer ldap3 cannot decode raised `KeyError`/`IndexError`/`ValueError` | 0.9.51 |
| SMB | `SMBException` and re-raised parser errors escaped; FILETIME year 10000 crashed | 0.9.53 |
| SMB | a recursive delete followed links and deleted the target's contents | 0.9.54 |
| SFTP, FTP | a recursive delete of an endless tree hit `RecursionError` or never ended | 0.9.55 |
| DB backends | driver errors and stored rows of the wrong shape escaped as non-`OSError` | 0.9.56 |
| git | a corrupt loose object raised dulwich/zlib errors, hung forever, or read short silently | 0.9.57 |
| WinRM | PowerShell JSON of the wrong shape raised `AttributeError`/`ValueError`/`RecursionError` | 0.9.58 |
| Exchange | a body in an unknown or NUL-containing charset raised `LookupError`/`ValueError` | 0.9.59 |
| WMI | property values of the wrong type raised `ValueError`/`AttributeError` | 0.9.60 |

Shared helpers added along the way: `core/answer_fields.py` (typed reads of
JSON answers: `as_dict`, `as_list`, `as_str`, `as_size`,
`as_utc_datetime`) and `core/path_policy.py`
(`MAX_RECURSIVE_DELETE_DEPTH`, `check_tree_depth`).

## Not covered

* **Library wire layers without an in-process server.** smbprotocol's SMB2
  parser, impacket's DCOM transport, exchangelib's EWS stack and
  paramiko's SSH packet layer are not fuzzed end to end. The axross side of
  the boundary is fuzzed through scripted fakes of those libraries.
* **DFS-N** reuses the SMB session, and its fixes. Referral handling reads
  library objects, not wire data.
* **Cisco telnet** adds string handling on top of the telnet transport that
  `test_fuzz_telnet.py` covers.
* **Known limits that are not contract breaks:**
  * ftplib and rsh listings have no line-count cap.
  * An endless SFTP file is bounded only by the consumer's size limit.
  * A lying Azure `Content-Range` costs one request per 4 MiB of the
    claimed size before the length check fails.
  * The OneDrive paging guard detects cycles, not an endless series of
    distinct links.
