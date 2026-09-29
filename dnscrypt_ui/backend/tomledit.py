"""
Minimal, comment-preserving editor for dnscrypt-proxy.toml.

Only touches *active* assignments of the requested key inside the requested
table. Commented-out examples are never uncommented, multi-line values are
replaced as a whole, and duplicate assignments are collapsed into one.
"""

import re
from typing import List, Optional, Tuple

_HEADER_RE = re.compile(r"^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(#.*)?$")


def _normalize_table(name: str) -> str:
    """'static.\"x\"' / \"static.'x'\" / 'static . x' -> 'static.x'."""
    parts = []
    current = ""
    quote = None
    for c in name:
        if quote:
            if c == quote:
                quote = None
            else:
                current += c
        elif c in ("'", '"'):
            quote = c
        elif c == ".":
            parts.append(current.strip())
            current = ""
        else:
            current += c
    parts.append(current.strip())
    return ".".join(parts)


def _bracket_delta(line: str) -> int:
    """Net '[' minus ']' outside of strings and comments."""
    depth = 0
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == "#":
            break
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        i += 1
    return depth


def _scan(lines: List[str]) -> List[Tuple[Optional[str], int, int, Optional[str]]]:
    """
    Returns a list of (table, start, end, key) spans.
    key is None for non-assignment lines; for assignments, [start, end) covers
    every physical line of the (possibly multi-line) value.
    """
    spans = []
    table = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        m = _HEADER_RE.match(line)
        if m and not stripped.startswith("#"):
            table = _normalize_table(m.group(1))
            spans.append((table, i, i + 1, None))
            i += 1
            continue
        km = re.match(r"^\s*([A-Za-z0-9_\-]+)\s*=", line)
        if km and not stripped.startswith("#"):
            start = i
            depth = _bracket_delta(line.split("=", 1)[1])
            i += 1
            while depth > 0 and i < len(lines):
                depth += _bracket_delta(lines[i])
                i += 1
            spans.append((table, start, i, km.group(1)))
            continue
        spans.append((table, i, i + 1, None))
        i += 1
    return spans


def _table_region(spans, table: Optional[str]) -> Optional[Tuple[int, int]]:
    """Line range [start, end) of the body of a table (root = None)."""
    start = None
    end = None
    for t, s, e, key in spans:
        if t == table:
            if start is None:
                start = s if table is None else s + 1
            end = e
        elif start is not None and end is not None and t != table:
            break
    if table is None and start is None:
        return (0, 0)
    if start is None:
        return None
    return (start, end)


def get_key_span(text: str, table: Optional[str], key: str):
    lines = text.split("\n")
    return [(s, e) for t, s, e, k in _scan(lines) if t == table and k == key]


def set_key(text: str, table: Optional[str], key: str, value: str) -> str:
    """Set `key = value` (value is a TOML literal) inside `table`."""
    lines = text.split("\n")
    spans = _scan(lines)
    matches = [(s, e) for t, s, e, k in spans if t == table and k == key]
    new_line = f"{key} = {value}"

    if matches:
        # Replace the first, remove any duplicates (bottom-up to keep indices valid)
        for s, e in reversed(matches[1:]):
            del lines[s:e]
        s, e = matches[0]
        lines[s:e] = [new_line]
        return "\n".join(lines)

    region = _table_region(spans, table)
    if region is None:
        header = f"[{table}]"
        suffix = "" if text.endswith("\n") else "\n"
        return f"{text}{suffix}\n{header}\n{new_line}\n"

    start, end = region
    # Prefer placing it right below a commented example of the same key
    example = re.compile(rf"^\s*#+\s*{re.escape(key)}\s*=")
    for idx in range(start, end):
        if example.match(lines[idx]):
            lines.insert(idx + 1, new_line)
            return "\n".join(lines)

    if table is None:
        # Before the first table header, after trailing blank lines are trimmed
        insert_at = end
        while insert_at > start and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines[insert_at:insert_at] = ["", new_line]
    else:
        insert_at = end
        while insert_at > start and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines.insert(insert_at, new_line)
    return "\n".join(lines)


def remove_key(text: str, table: Optional[str], key: str) -> str:
    lines = text.split("\n")
    matches = [(s, e) for t, s, e, k in _scan(lines) if t == table and k == key]
    for s, e in reversed(matches):
        del lines[s:e]
    return "\n".join(lines)


def has_table(text: str, table: str) -> bool:
    return any(t == table for t, _, _, _ in _scan(text.split("\n")))


def toml_str(value: str) -> str:
    """Single-quoted TOML literal string (no escapes possible, so reject quotes)."""
    if "'" in value or "\n" in value:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return f"'{value}'"


def toml_str_list(values: List[str]) -> str:
    return "[" + ", ".join(toml_str(v) for v in values) + "]"


def toml_bool(value: bool) -> str:
    return "true" if value else "false"
