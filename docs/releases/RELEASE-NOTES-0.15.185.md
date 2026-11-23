# axross 0.15.185 - release notes

The notes of the GitHub release of axross 0.15.185 (the asset
`RELEASE-NOTES-0.15.185.md`). `scripts/assemble_release.py --changelog`
takes the section below; the short entry is in [CHANGELOG.md](../../CHANGELOG.md).

## 0.15.185 - 2026-11-23

0.15.185 is a hotfix for ADB: folders of an Android phone with entries the
shell may not read - `/` on every recent phone - listed with holes and a
warning "Skipping unsafe item name". The downloads are the same as for
0.15.184 (Linux, AppImages, macOS, Windows, packs, wheel and sdist, signed
`SHA256SUMS`); installed binaries update to it. axross-headless-mcp
0.15.185 carries the same fix for its file tools on ADB profiles. The
Markdown reader is that of axross-markdown 0.17.4.

**In short** (the update dialog shows the start of these notes):

- **ADB folders list whole again**: an entry the phone will not show is
  listed as what it is, and two lines of `ls` never become one name.
- **Markdown reader** (axross-markdown 0.17.4): HTML comments read as GFM
  reads them, a resize or zoom keeps the place read, every theme colour
  reaches AA, a code block of a million lines holds the window no more.

### The ADB listing

In `/` of a phone, toybox `ls` prints an entry the shell may not open
(`postinstall`, `config`, ...) as a line of question marks:
`d?????????   ? ?      ?             ?                ? postinstall`.
axross did not take that line for an entry, read it as the second line of
the name before it (a name with a line break), and refused the joined name:
both `oem` and `postinstall` were missing from the pane, and the log said
`Skipping unsafe item name ... name contains control chars: U+000A`.

- Such an entry is now listed with its name and type - a folder, a link, a
  file or an unknown type - and without size, date and permissions; it is
  marked the way a local entry that cannot be read is.
- Listings and file info now ask the phone for escaped names (`ls -b`), so
  a name with a blank, a line break, a backslash or a byte that is not
  UTF-8 is read exactly, and one line is always one entry. The toolbox
  `ls` of Android 5 and older cannot escape; there axross lists without
  it and leaves out a name with a line break, with a warning, rather than
  guess where it ends.
- Dates in the form `Jan  2 03:04` and `Mar 16  2023` (busybox, GNU),
  seconds in ISO dates and SELinux contexts (`ls -Z`) are read too.
- The MCP server's file tools on an ADB profile read folders through the
  same code and get the fix as well.
- Regression tests: listings in the shapes of Android 14 toybox, Android 6
  toolbox, busybox and `ls -Z` (including `?` entries, `/proc/self` and
  escaped names), and a fuzz test that no stray line ever ends up in
  another entry's name.

### The Markdown reader

The reader is that of axross-markdown 0.17.4 (its notes are in that
project's CHANGELOG):

- **Comments in the built-in parser** are read as GFM reads them: a `<!--`
  in a quote, a list item, a table's cell or a tag's attribute hid what
  followed - the rest of the quote, the next cells, the rest of the page.
- **A resize** of a long page read to its end showed it empty and then its
  top before the place read came back, a zoom its top; both now keep the
  place. A resize that keeps the text's width lays nothing out again
  (0.48 s a step of a drag over 10,000 sections, now 0.004 s).
- **A code block of 1,000,000 lines** after Ctrl+End and Ctrl+Home held the
  window up to 3.6 s a turn; no turn is over 0.05 s now.
- **Themes:** every text colour reaches AA (4.5:1) on every ground it is
  drawn on, 7:1 in the High Contrast themes; a theme chosen for a big page
  starts after 0.3 s and says so.
- The updater starts its child processes with the clean child environment.
