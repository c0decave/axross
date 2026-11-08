"""A mail's HTML made safe to show: an allow-list of plain formatting tags,
no attributes but a link's address and a cell's span, no scripts, styles,
frames, forms, objects or images (an image becomes "[image: its alt text]"),
links only to http(s) and mailto - and every link shows where it really
goes beside its text ("Your bank [→ evil.example]"), which is the point of
looking at a suspicious mail. Nothing is fetched; the result is meant for
a viewer that loads no resource at all (ui/mail_project.py SafeBrowser).
"""

from __future__ import annotations

import html
import unicodedata
from html.parser import HTMLParser
from urllib.parse import SplitResult, urlsplit

ALLOWED = {"p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "a", "ul", "ol", "li", "table",
           "thead", "tbody", "tfoot", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
           "pre", "code", "hr", "small", "sub", "sup", "center", "font", "dl", "dt", "dd", "caption"}
DROP_WITH_CONTENT = {"script", "style", "head", "title", "iframe", "frame", "frameset", "object", "embed",
                     "applet", "noscript", "template", "svg", "math", "form", "select", "textarea", "button",
                     "video", "audio", "canvas", "link", "meta", "base"}
#: HTML's void elements (they never have an end tag): one of them must not
#: start a dropped region that only an end tag could close.
VOID = {"area", "base", "basefont", "bgsound", "br", "col", "command", "embed", "frame", "hr", "img", "input",
        "keygen", "link", "meta", "param", "source", "track", "wbr"}
MAX_OUTPUT = 2 * 1024 * 1024
#: Elements open at once; deeper ones are left out (keeps every end tag cheap).
MAX_NESTING = 256


def split_url(url: str) -> SplitResult | None:
    """``urlsplit(url)``, or None when it cannot be split: "https://[x"
    raises ValueError (an unclosed IPv6 bracket, a bad port), and one such
    link kept a whole mail out of the analysis and the safe view."""
    try:
        parts = urlsplit(url)
        parts.hostname, parts.port  # noqa: B018 - these raise ValueError too
    except ValueError:
        return None
    return parts


def hidden_chars(text: str) -> bool:
    """*text* holds format characters (Unicode Cf: bidi overrides and
    isolates, zero-width spaces and joiners), which show an address in
    another order or hide part of it."""
    return any(unicodedata.category(c) == "Cf" for c in text)


def strip_hidden(text: str) -> str:
    """*text* without its format characters (see :func:`hidden_chars`)."""
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


class _Sanitiser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.size = 0
        self.skip = 0                       # inside a dropped element
        self.stack: list[str] = []
        self.link_target: list[str] = []

    def _emit(self, text: str, *, closing: bool = False) -> None:
        # end tags of open elements always go out: the output stays balanced
        if self.size < MAX_OUTPUT or closing:
            self.out.append(text)
            self.size += len(text)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in DROP_WITH_CONTENT:
            if tag not in VOID:
                self.skip += 1       # only these count: their end tags count down
            return
        if self.skip:
            return
        if tag == "img":
            alt = next((v for k, v in attrs if k.lower() == "alt" and v), "")
            self._emit(html.escape(f"[image: {alt}]" if alt else "[image]"))
            return
        if tag not in ALLOWED:
            return
        if tag not in VOID and len(self.stack) >= MAX_NESTING:
            return
        kept = ""
        if tag == "a":
            raw = next((v for k, v in attrs if k.lower() == "href" and v), "").strip()
            # A bidi override in the address would show the target label
            # below in another order: removed, and the label says so.
            href = strip_hidden(raw)
            note = " (hidden characters removed)" if href != raw else ""
            parts = split_url(href)
            if parts is None:
                self.link_target.append(("", "malformed link - not followed"))
            elif parts.scheme.lower() in ("http", "https", "mailto"):
                kept = f' href="{html.escape(href, quote=True)}"'
                host = parts.hostname or (href[7:] if href.lower().startswith("mailto:") else "")
                self.link_target.append((href, (host or "not a web address") + note))
            else:
                self.link_target.append(("", "not a web address"))
        elif tag in ("td", "th"):
            for k, v in attrs:
                if k.lower() in ("colspan", "rowspan") and (v or "").isdigit() and int(v) < 100:
                    kept += f' {k.lower()}="{int(v)}"'
        self._emit(f"<{tag}{kept}>")
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if tag in DROP_WITH_CONTENT or self.skip:
            return                   # <svg/> is empty: it starts no dropped region
        depth = len(self.stack)
        self.handle_starttag(tag, attrs)
        if tag not in VOID and len(self.stack) > depth:
            self._pop()

    def _pop(self) -> str:
        """Close the innermost open element."""
        open_tag = self.stack.pop()
        if open_tag == "a":
            _target, label = self.link_target.pop() if self.link_target else ("", "not a web address")
            self._emit(f"</a> <small>[&#8594; {html.escape(strip_hidden(label))}]</small>", closing=True)
        else:
            self._emit(f"</{open_tag}>", closing=True)
        return open_tag

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip:
            if tag in DROP_WITH_CONTENT and tag not in VOID:   # </embed> closes nothing
                self.skip -= 1
            return
        if tag not in self.stack:
            return
        while self.stack and self._pop() != tag:
            pass

    def handle_data(self, data):
        if not self.skip:
            self._emit(html.escape(data))

    def close(self):
        super().close()
        self.skip = 0                # a dropped element never closed ends with the text
        while self.stack:
            self._pop()


class _Links(HTMLParser):
    """Every <a href> with its text, as a browser reads them: an <a> ends at
    its end tag, at the next <a> or at the end of the text."""

    def __init__(self, limit: int, text_limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit, self.text_limit = limit, text_limit
        self.found: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._size = 0

    def _end(self) -> None:
        if self._href is not None and len(self.found) < self.limit:
            self.found.append((self._href, "".join(self._text)))
        self._href, self._text, self._size = None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        self._end()
        href = next((v for k, v in attrs if k.lower() == "href" and v is not None), None)
        self._href = href

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() == "a":
            self._end()

    def handle_endtag(self, tag):
        if tag.lower() == "a":
            self._end()

    def handle_data(self, data):
        if self._href is not None and self._size < self.text_limit:
            self._text.append(data[:self.text_limit - self._size])
            self._size += min(len(data), self.text_limit - self._size)

    def close(self):
        super().close()
        self._end()


def links(text: str, *, limit: int = 100_000, text_limit: int = 4096) -> list[tuple[str, str]]:
    """(href, text) of the first *limit* links of an HTML text, both
    unescaped. One pass of the parser: the time grows with the length and
    nothing else (core.mail_analyse used a regular expression that took
    minutes for a few hundred KB of unclosed <a>)."""
    p = _Links(limit, text_limit)
    _feed(p, text or "", lambda: len(p.found) >= limit)
    return p.found


_CHUNK = 64 * 1024


def _feed(parser: HTMLParser, text: str, done) -> None:
    """*text* in pieces, until *done()* says the rest is not needed."""
    for start in range(0, len(text), _CHUNK):
        if done():
            break
        parser.feed(text[start:start + _CHUNK])
    parser.close()


def sanitise(text: str) -> str:
    p = _Sanitiser()
    _feed(p, text or "", lambda: p.size >= MAX_OUTPUT)
    return "".join(p.out)


def message_html(msg) -> str:
    """The message as safe HTML: its HTML part sanitised, else its text."""
    if msg.html:
        return sanitise(msg.html)
    return "<pre>" + html.escape(msg.text or "") + "</pre>"
