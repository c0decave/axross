# Changelog

What changed in each release of axross-markdown. The code is axross's
Markdown viewer (https://github.com/c0decave/axross), written out by axross's
`scripts/export_standalone.py markdown`.

## 0.16.10 - 2026-11-21

The twenty-third review's fixes. "Turn" is the window's own CPU in one
event-loop turn; "gap" is the longest time the window did not answer at all,
measured by a heartbeat on the GUI thread - what a worker thread holding
Python's lock costs the window, which the turn does not show. "Qt's own
parser" is the page without markdown-it-py (the fallback here, and axross's
own viewer, which ships without it).

- **A line of backticks froze the window:** the footnote pass looked for
  code spans with a regular expression that was cubic in a run of backticks,
  on every line. `x` and 1,200 backticks held the window 11.7 s; in a big
  file the same pass ran on a worker but held Python's lock, so the window
  froze 12.6 s while the turn read 0.08 s. Code spans are found in one pass
  now (0.04 s), and the pass runs only when the text has a footnote.
- **Every regular expression checked:** the reader's patterns were each run
  against runs of backticks, brackets, stars, underscores, pipes,
  backslashes, spaces and more. Also fixed: a footnote reference's pattern
  on `[^` repeated (40 KB: 3.9 s), quotes before a `$$` block (exponential in
  the number of `>`), the formula passes on runs of spaces (8,000 spaces:
  1.2 s) - all linear now.
- **Qt's own parser cuts more paragraphs and parts:** a paragraph with a `|`
  in it (a table needs a delimiter row; 2 MB took 1.2 s), a long word in a
  link, an autolink, a bare address or emphasis (cut and the link or the
  emphasis begun again in each piece - same address, no markup shown; 1.3 to
  1.5 s), list marks nested on one line (`+ ` 90,000 times 7.9 s, `1. `
  60,000 times 4.3 s: shown 16 deep, the rest as text), lines of `=`
  (300,000: 12 to 18 s) and a table header of 30,000 columns. All under
  0.1 s now.
- **Windows:** local images were never shown and a relative link went to the
  drive's root - paths were joined with `posixpath` and compared with "/".
  The file's own path functions are used now (`C:\docs\a.md` and
  `C:/docs/a.md` alike); the tests simulate Windows paths on Linux.
- **A table too wide to lay out** was shown as written in one code line that
  was never cut: 200,000 columns took 4.6 s. Its lines are cut as a code
  block's are (0.05 s).
- **Parsing off the GUI thread:** texts of up to 20,000 characters were
  parsed on the GUI thread - at every pause in the editor's typing. From
  2,000 on they are parsed on a worker. markdown-it-py's inline HTML and
  linkify rules were quadratic (19 KB of `<!--` or `http:// `: 0.8 to 0.9 s;
  200 KB of them 18 to 97 s before the page showed): both are linear now.
- **Export HTML with Qt's own parser** laid out the whole page and wrote it
  in one turn (0.4 to 4.4 s): it now writes a part a turn and makes the page
  safe on a worker.
- **Export and Print ask first:** the file dialog (and the print dialog)
  waited until the whole page was laid out in the window - 24 s to more than
  ten minutes on a big file. They show at once; the images the export needs
  are read on a worker, with Cancel.
- **The emoji font scan** is under its 0.25 s deadline all of it now (the
  default font's pass was not: 0.6 s of the first view with 2,000 fonts), and
  the maths font check asks the font itself, not Qt's fallback fonts.
- **Zoom on a big page read to its end** made the next scroll or Find lay all
  of it out again (a table of 20,000 rows: 0.65 to 1.6 s). A zoom lays the
  page out anew a part a turn, from the place read.
- **A footnote cited twice** rendered as broken HTML (its ways back on lines
  of their own); they are in the note's paragraph now, as GitHub shows them.
- **Ctrl+End and Ctrl+Home** work on a page laid out whole as well.
- **Small things:** Find without a match on a big page no longer searches
  all of it twice at each Enter (2.7 MB: 0.185 s); a letter keeps at most 64
  combining marks (99,000 on one letter: 0.14 s); a short text with fenced
  code is prepared on a worker (a stuck lexer held the window 1 s - found by
  the heartbeat); `axross-markdown --term` names itself in its messages.
- **Qt's own parser and the GFM spec:** `<details>` is folded unless it says
  `open`, as GitHub and markdown-it's page show it, its summary a link that
  opens it; an autolink with a backtick, `[a](<b)c`, `Foo\` over `---`,
  `&#10;`, a header row of more cells than its delimiter row, a heading in a
  list item followed by a paragraph and `[foo]: <bar>(baz)` show as the spec
  says.
- **Release and CI:** pytest (and what it needs) is installed from
  `packaging/requirements-test.txt`, every pin hashed, in the CI and the
  release; the release builds the sdist and wheel before any test tool is
  installed.
- **Tests:** a heartbeat on the GUI thread now measures the wall-clock gap in
  every stress test, beside the turn, so a lock held by a worker fails them.
  The emoji test that failed once in six runs measures again before it fails
  and prints a profile when it does.

## 0.16.9 - 2026-11-20

The twenty-second review's fixes. Times are the window's own CPU in one
event-loop turn; "Qt's own parser" is the page without markdown-it-py (the
fallback here, and axross's own viewer, which ships without it).

- **A long line of raw HTML:** a block of raw HTML was cut by its elements
  and lines, never by its characters, so a line of 2 MB in a `<div>` was one
  piece: 1.1 s in the window, and 18 s exporting a PDF or printing (each page
  drew the whole block again). A text in raw HTML now weighs its characters
  and a long one is cut at a space: 0.01 s, the PDF 0.02 s.
- **Closing the window during an export or a print:** the export waited in
  an event loop for a result the closed window never got - until the
  program ended, and then it raised. It now ends at once, cancelled.
- **Qt's own parser cuts a page where a block ends without an empty line:**
  after a heading of either kind, a fenced block, a link's definition, a
  rule - and between the headings of a quote. 50,000 setext headings (4.2 s),
  50,000 headings in a quote (4.1 s), a long paragraph right under a heading,
  a fence or a definition (1.1 to 1.4 s) and 50,000 definitions with their
  references (1.5 s): now 0.02 to 0.03 s.
- **Every Unicode space counts in a run of spaces:** 300,000 no-break spaces
  held the window 11 s (only spaces and tabs were cut). Now 0.004 s.
- **Runs of brackets and tags with Qt's own parser:** "<a" 49,500 times
  (4.1 s), "<" 99,000 times (7 s), "[a" and "[" (1 s) and "*a" (0.14 s) are
  cut in pieces too (0.01 to 0.06 s). Its passes before the page are linear:
  "![" 49,500 times took them 132 s, 100,000 addresses on a line 129 s; now
  well under a second.
- **Qt's own parser on the GFM spec:** 74 examples shown otherwise than the
  spec's, now 51 (most of those on purpose: raw HTML is not shown). No
  private-use mark shows in the page or a link any more; an escaped tag
  (`\<br/>`) is text, not a line break; an image by reference with emphasis
  in its alt shows once (`![foo *bar*]` twice before, `![foo *bar*][]` not
  at all); a link never closed leaves no "["; a tag that is none (`<a
  href="hi'>`) is text; `&#0;` is U+FFFD, and entities such as `&Dcaron;`
  and `&HilbertSpace;` are their characters.
- **No false "lists nested more than 16 deep":** code indented 33 columns or
  more (deep JSON, YAML, HTML in a fenced block) said the page was laid out
  flatter, and took the slow path. Only a list made flatter is said now.
- **Big tables:** the first part of a big table is a quarter as long, a
  table with footnotes counts its references, and a later part's cells are
  made unbreakable before it goes into the page (there each one laid all of
  the table out again): 20,000 rows 0.15 s, 5,000 footnoted rows 0.21 s - now
  0.06 and 0.04 s. A PDF lays out smaller parts of a table and draws a page a
  turn: 0.20 and 0.30 s, now 0.04 and 0.02 s.
- **Small things:** Find says "N+" once, not "N++". A code block's label is
  its info string unescaped (`foo\+bar` is "foo+bar", `f&ouml;&ouml;`
  "föö"). An installed colour emoji font is the page's emoji family even
  where Qt's fallback reaches it from the default font (that font took its
  place). The program no longer logs "Backend registry initialized: 40
  backends" at every start.
- **Release and CI:** the sdist and wheel are built with build and twine from
  `packaging/requirements-build.txt` (every pin hashed) and
  `python -m build --no-isolation`, the backend (setuptools) from
  `requirements.lock.txt`: nothing unpinned comes from PyPI for the
  artifacts. A stress test over its turn budget measures the machine again
  and runs once more before it fails (a runner shared with another job ran
  5 % slower for a while).

## 0.16.8 - 2026-11-20

The twenty-first review's fixes, and the CI's tests green again. Times are the
window's own CPU in one event-loop turn.

- **Emoji with the CI's font:** Ubuntu's Noto Color Emoji (the runner's) is a
  bitmap font: FreeType decodes a glyph's PNG at every layout and every paint,
  67 µs an emoji (2 µs with an outline colour font). With Qt's own parser an
  emoji now weighs its 128 letters in a part too (a part held 1,080 of them:
  0.31 s), in a quote or a list item as well (3,000 of them a piece: 1 s). A
  heading or a table cell is cut by that weight too (1,000 emoji in a heading:
  0.4 s, in a cell 0.8 s). While the laid-out page was shorter than the view,
  the scroll bar was hidden and shown again at each part, and Qt laid the
  whole page out again each time (0.19 s); it now stays on while parts are to
  come. 50,000 emoji with that font: 0.31 and 0.19 s, now 0.10 s, about half
  of it Qt painting a view full of them.
- **Budgets by what the layout costs, not by shape:** every block weighs in a
  part (100,000 rules: 1.3 to 3.4 s; 50,000 one-line code blocks: 2.5 to
  9 s). A part is cut past twice its budget wherever a block begins, inside
  any container. A paragraph is also cut inside a link, emphasis or a strike,
  the open spans ended and begun again (8,000 images in emphasis: 4.6 s). A
  table's part is also cut by its characters (300 rows of long cells: 1.3 s).
  A formula longer than 4,000 characters shows as its TeX (0.6 to 0.8 s), and
  a code line of 80,000 characters is wrapped.
- **Find, Copy and PDF of such pages:** Find counts matches for at most
  0.03 s a turn and shows "N+" past that (0.15 s at each Find Next). A copy
  takes 25 ms of pieces a turn. On a page read to its end, a copy no longer
  goes through every frame of the page at each piece, and may cut inside a
  quote's box (50,000 code blocks: 0.42 s a turn; 20,000 in a quote: 0.12 s),
  and Find looks for the view's top by halves (0.09 s).
- **The editor's preview follows the typing** inside a long table or code
  block (it stayed rows away), and 3,000 code blocks no longer stall a pause
  in the typing (0.34 s).
- **Opening a file no longer freezes the window while the fonts are searched
  for emoji:** where no font had every emoji, each of hundreds of font
  families was asked for every emoji (minutes on some machines). Each family
  is now asked only for what is still missing, and the search ends after
  0.25 s.
- **Small things:** a missing file is said in words ("it does not exist"),
  not "[Errno 2] …" with its path. A folder given to the program opens its
  README. A cp1252 console shows boxes and rules as ASCII ("+--+"), not "?".
  Zoom reaches exactly 25 % and 400 %. "~~~x~~~" in a line stays as written.
  An alert in a list or in another quote is a quote, as on GitHub.
- **CI:** a failed test run shows its pytest summary as annotations, readable
  through the API. The build backend (setuptools) is pinned in the lock and
  installed from it (`--no-build-isolation`). The new stress tests' budget of
  0.1 s a turn grows with how much slower the machine lays out a fixed page
  (at most three times), and a page of emoji may take what Qt needs to paint
  a view of them once.

## 0.16.7 - 2026-11-20

- **A paragraph of many emoji on a host with many fonts:** 0.16.6's CI runner
  (hundreds of fonts, a colour emoji font among them) still took 0.42 s a
  turn for 50,000 emoji (0.68 s with Qt's own parser). An emoji now counts as
  128 letters in a paragraph's pieces whatever the fonts, and a piece holds
  as few as 40 characters, so each turn lays out about 14 times fewer emoji.
  Here, with Noto Color Emoji: 0.035 and 0.043 s a turn before, 0.015 and
  0.014 s now; with DejaVu alone 0.009 and 0.014 s.
- **The release waits for the supply-chain gate and the tests:** release.yml
  calls tests.yml before it builds anything, and the gate checks out
  axross at a pinned commit (v0.15.180) instead of its default branch, which
  can be an older release with an older baseline.

## 0.16.6 - 2026-11-20

The twentieth review's fixes - each stall fixed for its whole class, and a
test that puts every hostile shape into every container (top level, a table's
cell, a heading, a list, a quote, an alert, a footnote, a definition, a
`<details>`) under both parsers. Measured with the dependencies of
`requirements.lock.txt`; times are the window's own CPU in one event-loop
turn.

- **A long line in a table cell or a heading** no longer freezes the window
  (1.2 to 2.1 s before): a heading's or a cell's text past 2,000 characters
  is cut with "…" (the editor shows all of it), in any container. **One code
  span of 90,000 characters** (0.8 to 1.8 s in any container) is laid out in
  pieces. Every shape in every container now stays under 0.25 s a turn.
- **A footnote cited 100,000 times:** its ways back are the first 20 and "and
  99,980 more"; Ctrl+End reached the end after 4.3 s with one 3.8-second
  turn, now 0.2 s (turns of 0.02 s).
- **Many headings:** each part of a page with thousands of headings was
  laid out slower than the last (a heading's anchor name made Qt compare
  every new format with all the earlier ones): 30,000 headings took 104 s,
  their last parts 1.2 to 1.6 s each; now each part costs the same (0.01 s),
  1.5 s in all.
- **The editor's preview follows the typing** far down a long text (36,000
  lines) and in a text without headings - it finds the line typed at.
- **Display math in an alert** (`> [!NOTE]` / `> $$` / ...), or after a line
  of text, is a display formula, as on GitHub - in the window, --html and
  axross-mdcat.
- **A long text of one kind shows its first part at once:** 20,000 small
  tables, 150,000 lines of short code spans, a line of 700 KB - axross-mdcat's
  first lines after 0.2 to 0.5 s (3.8, 9.5 and 6.9 s before), the window's
  first part likewise.
- **The release checks every child of the binary:** `--lex-worker` (a YAML
  and a Python block, their colours), `--image-worker` (a picture) and the
  terminal view's colours, also through `axross-mdcat.exe`. The lexing and
  decoding children find the package they belong to even when it is not
  installed.
- **Emoji on a host without a colour emoji font** (0.16.5's CI runner: 50,000
  of them held the window 0.43 s a turn, 0.70 s with Qt's own parser): there
  Qt looks each emoji's glyph up through the fonts, so an emoji now counts as
  128 letters in a paragraph's pieces instead of 8 (a colour emoji font
  keeps 8). With DejaVu alone: 0.007 and 0.012 s a turn.
- **Small things:** a lazy line in a quoted formula; Ctrl+wheel and Ctrl+=
  zoom through the button's level, between 25 % and 400 %; image boxes take
  a theme chosen later; a file that cannot be read says why in the page; the
  extended README no longer repeats the README, lists all its sections, says
  where the theme is kept and names the guards.

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
