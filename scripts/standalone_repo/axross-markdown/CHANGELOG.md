# Changelog

What changed in each release of axross-markdown. The code is axross's
Markdown viewer (https://github.com/c0decave/axross), written out by axross's
`scripts/export_standalone.py markdown`.

## 0.16.5 - 2026-11-20

The 0.16.4 release's build failed; this one carries its fixes.

- **axross-mdcat.exe on Windows** no longer ends in an encoding error when its
  output goes into a pipe or a file (the ANSI code page has no "█"): output
  into a pipe or a file is UTF-8, and a console that cannot show a character
  gets it replaced.
- **Many emoji, many image chips:** a paragraph of 50,000 colour emoji held
  the window for seconds on a host with many fonts; emoji now count more in
  the pieces a paragraph is laid out in, and the page names the emoji font
  after its own (no search through every installed font). 20,000 image chips
  are fitted 2,000 a turn.
- **Tests on other machines:** the test of letters the page's fonts lack asks
  the installed fonts instead of assuming DejaVu's.

## 0.16.4 - 2026-11-20

- **YAML code is coloured again** - in the window, the exported page and
  axross-mdcat. The lexing process (0.16.3) asked the colour style for each
  token type and gave up on a type the style does not list, as YAML's plain
  values - the whole block stayed plain. A type the style leaves out now takes
  its parent's colour, as Pygments' own formatters do. Checked for 22 common
  languages (YAML, Python, JSON, TOML, Bash, JavaScript, C, Go, Rust, SQL and
  others) with the lock's dependencies; the editor (F4) colours YAML too.

## 0.16.3 - 2026-11-20

The nineteenth review's fixes. Every figure below was measured with the
dependencies of `requirements.lock.txt` (markdown-it-py 4.2, mdit-py-plugins
0.6.1, linkify-it-py 2.2, PyQt6 6.11).

- **The shipped tests pass in a fresh install:** in an environment made from
  the lock 13 of them failed - nine ran axross's own module names in a child
  process or patched them by name (and the release's SVG check imported one),
  two found the quoted formula below, two the 10 MB line with linkify. The
  export now renames those names too; `python -m pytest tests` is green there
  (the golden-image tests skip without numpy).
- **A long line of inline spans no longer freezes the window:** a paragraph
  without spaces was laid out by Qt in one go - 25,000 code spans
  (`` `a`` 49,500 times) took 13 s of the window's own time, 99,000 letters in
  one word 1.1 s, 30,000 formulas 0.7 s. Such a paragraph is now cut into
  pieces laid out one per turn: the longest turn is 0.02 to 0.07 s. A table of
  60 columns is drawn in smaller parts (0.30 s a turn before, 0.16 s now).
- **linkify-it-py on a line of 10 MB:** its search held Python's lock while
  a worker parsed - the window stood still 4.9 s. Now a piece at a time: 0.16 s.
- **Code is coloured in a child process:** a Pygments lexer whose regular
  expression gets stuck in backtracking held the window (the editor measured
  8.7 s; a patched lexer here 1.1 s in the window, 5.3 s with Qt's own
  parser). Code blocks are now lexed in a separate process with a 5-second
  bound - in the window, the exported page and axross-mdcat - and shown plain
  past it; the colours are the same as before.
- **A display formula in a quote** (`> $$` / `> a = \frac12` / `> $$`) showed
  as "> a = ½ >" in the window, the terminal, the exported page and a copy;
  the quote's marks are no longer part of the formula.
- **Inline footnotes (`^[...]`):** a long text with them was parsed whole
  before anything showed. 3.8 MB with 1,500 of them: the terminal's first
  lines after 0.6 s (4.3 s before), the window's first part after 1.2 s (2.7 s).
- **The editor's preview follows the typing:** typed at line 170, it stayed
  at the top; now it shows the place typed at.
- **PDF export:** a box crossing a page break (an alert, a code block) drew
  its background through the margins, under the page number and at the next
  page's top; it now stays between the margins.
- **The zoom button shows the zoom level** (110 %, 90 %); a click is still
  the original size (Ctrl+0).
- **axross-mdcat:** `--watch` of a missing file says so and waits for it (it
  was silent for ever); `| head` ends it at once (it rendered all of the rest:
  6.4 s for 2.7 MB); a full disk (`> /dev/full`) is said, exit 1, not a
  traceback; at most 200 pictures are drawn for a whole text, as in the
  window (6,000 were all drawn - 26.8 MB of output, 3.0 MB now); every option
  has its help text.
- **Windows:** the viewer is a window program - no console window beside it;
  its `--term` / `--html` / `--version` write into the console it was started
  from, or a file or pipe. The terminal view is also `axross-mdcat.exe`, a
  console program of its own.
- **Screenshots** retaken (Open…, View; light and dark themes), by a script.

## 0.16.2 - 2026-11-20

The eighteenth review's fixes, and what 0.16.1 left unsaid.

- **A formula nested a thousand deep** (`\sqrt{\sqrt{...}}`) no longer
  blanks the page (the window lost its outline; `axross-mdcat` and `--html`
  printed a traceback): one past 64 groups is shown as its TeX with a note,
  and any step of the maths that fails shows that formula as written - in
  the window, the terminal and the exported page. A page whose drawing fails
  is shown as written with a notice, never blank.
- **A link of a megabyte in the terminal** takes a second, not an hour: a
  link is checked once, and one longer than terminals take (2,083
  characters) is shown as its text, not as a hyperlink.
- **The window never waits for its own workers:** a line of 10 MB, a page of
  backticks, an HTML export, typing in the editor beside the preview - the
  longest pause of the event loop under a tenth of a second. A short text of
  brackets nested thousands deep is read off the window's thread.
- **Long texts of one kind are fast:** 50,000 task items, 100,000 emoji short
  codes, 50,000 bare links or link definitions, 200 formulas of 200
  fractions - the first part in about 0.2 s. `axross-mdcat` draws a table of
  100,000 rows as it goes (the first rows at once, a twelfth of the memory)
  and a line of 10 MB in a fifth of the time; a table of more than 64 columns
  is shown as written, as in the window.
- **Themes:** the program follows the desktop's light or dark scheme (light
  when the desktop does not say) and changes with it; *View > Theme* (Alt+V)
  chooses another, kept in the program's own settings
  (`~/.config/axross-markdown/settings.json`). It was always dark.
- **HTML export** keeps relative links (`notes.md`, `foo(and(bar))`) and
  leaves out the reader's own formula marks.
- **Small things:** a footnote ending in a code block has its ↩ in the note;
  an image of a refused address (`file:`, a `data:` that is no image) is a box,
  not "!x"; a file that is no text is said to be one, not shown as garbage; a
  copy no longer begins with an empty line; the start logs no language line;
  the editor is "Editor — axross-markdown"; an emoji short code no installed
  font can draw stays as written instead of an empty box.
- **SVG pictures (0.16.1, unsaid there):** an SVG is drawn in a process of its
  own, ended after 10 seconds - one that would take minutes cannot hold the
  window - and a PDF or PostScript file is never taken for a picture. A
  one-file build's drawing process is now accepted under the build's own
  launcher (on Linux it was refused: no SVG was drawn); the release's smoke
  test draws one through it.
- **Tests:** the export carries the reader's own tests (`python -m pytest
  tests`).
- **README:** the screenshot first, the ten points, the contents; the details
  - keys, export, themes, the terminal's options, the security model, the
  limits, the ways to install - in `docs/README-extended.md`.

## 0.16.1 - 2026-11-19

A hotfix and the seventeenth review's fixes.

- **`[~x~]` no longer hangs the viewer:** a single-tilde strike-through inside
  a link label made the parser loop (markdown-it 4.2) or fail (4.3). A text
  the parser cannot read, or that takes it too long, is now shown as written
  with a notice saying why - never a blank page or a hang.
- **Export and Print take the whole page:** a long file's PDF was cut short;
  now it is complete, built in pieces with progress and *Cancel*, and the
  window stays usable.
- **Find** reaches matches inside folded `<details>`, in page order, and
  counts them.
- **Wide tables** grow past the text and scroll sideways instead of breaking
  their words.
- **Copy** writes table rows tab-separated, without trailing spaces.
- **The scroll bar** stays where it is put after Ctrl+End.
- **Files that are not UTF-8** are read as Windows-1252 / Latin-1.
- **The terminal** numbers ordered lists of task items (`1. ☐ a`).
- **A missing system library** (libEGL on a minimal Linux) is named, with the
  package to install, instead of a traceback.
- **Maths:** `\pmod p` without braces, `\mathcal` letters where a maths font has
  them, a root sign as tall as the fraction under it.
- **The image zoom window** has the same title row and close button as every
  other window.

## 0.16.0 - 2026-11-19

The first public release.

- **A Markdown file in a window of its own:** CommonMark with GitHub's tables
  (aligned as written), task lists, strike-through, autolinks, footnotes,
  definition lists and YAML / TOML front matter; the headings as an outline
  beside the text, fenced code coloured by Pygments, local images beside the
  file, light and dark themes, find (Ctrl+F), zoom (Ctrl + / - / 0), Reload
  (F5), Edit (F4) with the rendering beside the text.
- **Formulas:** TeX in `$...$` and `$$...$$` (and GitHub's `` $`...`$ ``) in
  display style - fractions, roots, matrices, large operators with limits,
  stacked `\overset` / `\underset` / `\cfrac` in display formulas; Copy takes a
  formula as its TeX.
- **In the terminal:** `axross-mdcat FILE.md` (or `axross-markdown --term`)
  draws tables with box characters, coloured code, hyperlinks (OSC 8) and
  images (kitty, iTerm2 or half-blocks), `--toc` lists the headings, `--watch`
  follows a file; `axross-markdown --html FILE` writes a page for a web
  browser. Neither starts Qt.
- **Shown, never run:** raw HTML is kept to a safe subset, nothing is loaded
  from the network, images are read only beside the file (never a secret file,
  bounded in size and count), a web link opens only after a question that
  shows its real address, look-alike host names are shown in punycode.
- **Downloads:** one-file programs for Linux (also as an AppImage), macOS
  (also as a disk image with an app) and Windows, besides the Python package
  on PyPI.

Known limitations: a few large documents still pause the window for about a
quarter of a second while a part is laid out; inline and in the terminal,
`\overset`, `\underset`, `\stackrel` and `\cfrac` are written side by side,
not stacked. The macOS and Windows programs are not notarized or signed.
