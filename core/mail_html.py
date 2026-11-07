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
from html.parser import HTMLParser
from urllib.parse import urlsplit

ALLOWED = {"p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "a", "ul", "ol", "li", "table",
           "thead", "tbody", "tfoot", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
           "pre", "code", "hr", "small", "sub", "sup", "center", "font", "dl", "dt", "dd", "caption"}
DROP_WITH_CONTENT = {"script", "style", "head", "title", "iframe", "frame", "frameset", "object", "embed",
                     "applet", "noscript", "template", "svg", "math", "form", "select", "textarea", "button",
                     "video", "audio", "canvas", "link", "meta", "base"}
VOID = {"br", "hr", "img", "input", "meta", "link", "base", "wbr", "col", "area", "source", "track", "param"}
MAX_OUTPUT = 2 * 1024 * 1024


class _Sanitiser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.size = 0
        self.skip = 0                       # inside a dropped element
        self.stack: list[str] = []
        self.link_target: list[str] = []

    def _emit(self, text: str) -> None:
        if self.size < MAX_OUTPUT:
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
        kept = ""
        if tag == "a":
            href = next((v for k, v in attrs if k.lower() == "href" and v), "").strip()
            scheme = urlsplit(href).scheme.lower()
            if scheme in ("http", "https", "mailto"):
                kept = f' href="{html.escape(href, quote=True)}"'
                self.link_target.append(href)
            else:
                self.link_target.append("")
        elif tag in ("td", "th"):
            for k, v in attrs:
                if k.lower() in ("colspan", "rowspan") and (v or "").isdigit() and int(v) < 100:
                    kept += f' {k.lower()}="{int(v)}"'
        self._emit(f"<{tag}{kept}>")
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID and not self.skip and tag.lower() in ALLOWED:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip:
            if tag in DROP_WITH_CONTENT:
                self.skip -= 1
            return
        if tag not in self.stack:
            return
        while self.stack:
            open_tag = self.stack.pop()
            if open_tag == "a":
                target = self.link_target.pop() if self.link_target else ""
                host = urlsplit(target).hostname or (target[7:] if target.lower().startswith("mailto:") else "")
                self._emit(f"</a> <small>[&#8594; {html.escape(host or 'not a web address')}]</small>")
            else:
                self._emit(f"</{open_tag}>")
            if open_tag == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self._emit(html.escape(data))

    def close(self):
        super().close()
        while self.stack:
            self.handle_endtag(self.stack[-1])


def sanitise(text: str) -> str:
    p = _Sanitiser()
    p.feed(text or "")
    p.close()
    return "".join(p.out)


def message_html(msg) -> str:
    """The message as safe HTML: its HTML part sanitised, else its text."""
    if msg.html:
        return sanitise(msg.html)
    return "<pre>" + html.escape(msg.text or "") + "</pre>"
