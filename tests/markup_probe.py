"""What a tooltip or label really shows, for tests of untrusted names.

Qt renders a tooltip (and a label in AutoText) as rich text when
``Qt.mightBeRichText`` says it looks like markup. A name such as
:data:`WIDE` then lays the tip out thousands of pixels wide and
:data:`BOLD` restyles it, instead of being read. These helpers answer
"what does the user read?" the way Qt does.
"""

from __future__ import annotations

#: As rich text, an image 4000 pixels wide.
WIDE = "<img width=4000 height=4000 src=x>"
#: As rich text, a bold "x".
BOLD = "<b>x</b>"
#: :data:`BOLD` as a file name (which has no "/").
BOLD_FILE = "<b>x"
PAYLOADS = (WIDE, BOLD)


def shown(text: str, rich: bool | None = None) -> str:
    """The text a user reads for *text*: rendered when Qt takes it (or
    *rich* says it is) for rich text, else *text* itself."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QTextDocument

    if rich is None:
        rich = Qt.mightBeRichText(text)
    if not rich:
        return text
    doc = QTextDocument()
    doc.setHtml(text)
    return doc.toPlainText()


def tooltip_width(tip: str) -> int:
    """The width of the tooltip Qt shows for *tip*, in pixels."""
    from PyQt6.QtCore import QPoint
    from PyQt6.QtWidgets import QApplication, QToolTip

    app = QApplication.instance()
    QToolTip.showText(QPoint(5, 5), tip)
    app.processEvents()
    width = max((w.sizeHint().width() for w in app.topLevelWidgets()
                 if w.metaObject().className() == "QTipLabel" and w.isVisible()),
                default=0)
    QToolTip.hideText()
    app.processEvents()
    return width


def _rendered_as_markup(text: str, fmt=None) -> bool:
    """Whether Qt renders *text* (a tooltip when *fmt* is None, else a
    label in text format *fmt*) as rich text."""
    from PyQt6.QtCore import Qt

    if fmt is None:
        return Qt.mightBeRichText(text)
    # A label left in AutoText is a guess away from markup: what it shows
    # depends on where the name lands in the text, so only PlainText counts.
    return fmt != Qt.TextFormat.PlainText


def _has_children(model, index) -> bool:
    try:
        return model.hasChildren(index)
    except TypeError:  # a flat (list, table) model: private there, and none
        return False


def _model_tooltips(view):
    """Every tooltip of the items of *view*'s model (list, tree, table),
    with a short name of where it is."""
    from PyQt6.QtCore import QModelIndex, Qt

    model = view.model()
    if model is None:
        return
    todo = [QModelIndex()]
    while todo:
        parent = todo.pop()
        try:
            columns = max(1, model.columnCount(parent))
        except TypeError:  # a list model: one column, and the count is private
            columns = 1
        for row in range(model.rowCount(parent)):
            for col in range(columns):
                index = model.index(row, col, parent)
                tip = model.data(index, Qt.ItemDataRole.ToolTipRole)
                if tip:
                    yield f"{type(view).__name__} item ({row}, {col})", str(tip)
                if col == 0 and _has_children(model, index):
                    todo.append(index)


def texts(root):
    """``(where, text, fmt)`` for every label text and tooltip under the
    widget *root* - its widgets, their actions and the items of every
    list, tree and table (*fmt* is None for a tooltip)."""
    from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QLabel, QWidget

    widgets = [root] + root.findChildren(QWidget)
    for w in widgets:
        name = f"{type(w).__name__} {w.objectName()!r}"
        if w.toolTip():
            yield f"{name} tooltip", w.toolTip(), None
        if isinstance(w, QLabel) and w.text():
            yield f"{name} text", w.text(), w.textFormat()
        for action in w.actions():
            if action.toolTip():
                yield f"{name} action tooltip", action.toolTip(), None
        if isinstance(w, QAbstractItemView) and not isinstance(w, QHeaderView):
            for where, tip in _model_tooltips(w):
                yield where, tip, None


def markup_leaks(root, payloads=PAYLOADS) -> tuple[list[str], int]:
    """The places under *root* where one of *payloads* is rendered as rich
    text, and how many places show one as text (so a test sees that its
    names reached the window at all)."""
    from PyQt6.QtCore import Qt

    leaks, seen = [], 0
    for where, text, fmt in texts(root):
        for payload in payloads:
            if payload in text and _rendered_as_markup(text, fmt):
                leaks.append(f"{where}: {text[:120]!r}")
            elif payload in shown(text, Qt.mightBeRichText(text) if fmt is None
                                   else fmt == Qt.TextFormat.RichText):
                seen += 1
    return leaks, seen
