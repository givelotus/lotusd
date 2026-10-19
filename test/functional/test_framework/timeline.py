#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A test's logs merged into one time-ordered timeline.

A functional test writes test_framework.log, and each node writes
node<N>/<chain>/debug.log, all with ISO-8601 timestamps. This module reads
them as streams of events and merges them by wall-clock time:

- each event has `time` (RFC 3339 with microseconds), `source` ("test",
  "node0", ...), `level` (when known), `message` and the raw text;
- a line without a leading timestamp continues the previous event, so
  tracebacks stay together;
- a node line's "(mocktime: ...)" is kept as a field; ordering uses the wall
  clock before it;
- when a node also wrote a JSON-lines log (`debug-framework.jsonl`, or another
  *.jsonl file, in its chain directory), that file is read instead of
  debug.log; so is `test_framework.jsonl` instead of test_framework.log.

Three ways to read them, by cost:

- read_timeline(): events one by one (heapq merge of streamed files), for
  combine_logs.py and as the reference for the faster paths;
- write_combined_log(): the whole timeline as text, merged in large binary
  blocks by comparing the timestamps' bytes (fixed-width ISO 8601 with
  microseconds orders correctly as bytes), without parsing lines; only
  blocks with lines that do not start with a timestamp (e.g. tracebacks)
  are parsed as events;
- failure_excerpt(): the end of the timeline up to the failure, reading
  only the end of each log (binary search for the failure's time), so it
  costs the same whatever the size of the logs.

Memory does not grow with the size of the logs. This module only uses the
standard library, so that combine_logs.py can use it without the rest of
the framework.
"""

import calendar
import glob
import heapq
import itertools
import json
import os
import random
import re
import shutil
import tempfile
import time
import unittest
from operator import itemgetter, le
from typing import IO, Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Matches the timestamp at the start of a log event (as written by bitcoind
# and by the framework's text formatter)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?Z")
# Any RFC 3339 timestamp, e.g. in a JSON record's "time" or "@timestamp"
RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)
MOCKTIME = re.compile(r" ?\(mocktime: ([^)]*)\)")
FRAMEWORK_LINE = re.compile(r"(\S+) \((\w+)\): ?")
SOURCE_LOCATION = re.compile(r".+\.\w+:\d+$")
CATEGORY = re.compile(r"([A-Za-z0-9_.]+)(?::(\w+))?$")
# The framework's logged exception, after which it only shuts down: the
# failure that a test's timeline is cut at (see failure_excerpt)
FAILURE_MESSAGE = re.compile(r"(Unexpected exception|Called Process failed)")

# The JSON-lines logs read in preference to the text logs
FRAMEWORK_JSON_LOG = "test_framework.jsonl"
NODE_JSON_LOG = "debug-framework.jsonl"

# Events a source may be out of order by (an asynchronous logger can write
# records slightly out of timestamp order); they are reordered within this
# window before merging
REORDER_WINDOW = 1024
# Width of the source column in the rendered timeline ("node10" fits)
SOURCE_WIDTH = 6
# Longest line shown in a failure excerpt (the full line is in combined.log)
EXCERPT_LINE_LENGTH = 500

LEVEL_NAMES = {
    "critical": "error",
    "fatal": "error",
    "err": "error",
    "warn": "warning",
}


class Event:
    """One log event (possibly several lines) from one source.

    A text event's level, message and fields are parsed from its raw text
    only when used: merging and writing combined.log need only the time."""

    __slots__ = (
        "micros",
        "order",
        "seq",
        "source",
        "raw",
        "_time",
        "_level",
        "_message",
        "_fields",
        "is_json",
    )

    def __init__(
        self,
        micros: int,
        source: str,
        message: Optional[str],
        raw: str,
        level: Optional[str] = None,
        fields: Optional[Dict[str, Any]] = None,
        order: int = 0,
        seq: int = 0,
        time: Optional[str] = None,
        is_json: bool = False,
    ):
        self.micros = micros
        # Whether this is a record of a JSON-lines log
        self.is_json = is_json
        self.source = source
        self.raw = raw
        self._time = time
        # None for a text event that is not parsed yet
        self._message = message
        self._level = level
        self._fields = fields
        # Position of the source and of the event in its source: the order of
        # events with the same timestamp
        self.order = order
        self.seq = seq

    def _parse(self):
        if self._message is None:
            self._fields, self._level, self._message = parse_text(self.source, self.raw)

    @property
    def message(self) -> str:
        self._parse()
        assert self._message is not None
        return self._message

    @property
    def level(self) -> Optional[str]:
        self._parse()
        return self._level

    @property
    def fields(self) -> Dict[str, Any]:
        self._parse()
        return self._fields if self._fields is not None else {}

    @property
    def time(self) -> str:
        if self._time is None:
            self._time = format_time(self.micros)
        return self._time

    def sort_key(self) -> Tuple[int, int, int]:
        return (self.micros, self.order, self.seq)

    def __repr__(self):
        return f"Event({self.time}, {self.source}, {self.message!r})"


_seconds_cache: Dict[Tuple[int, ...], int] = {}


def parse_time(text: Any) -> Optional[int]:
    """Microseconds since the epoch of an RFC 3339 timestamp, or None."""
    if not isinstance(text, str):
        return None
    match = RFC3339.match(text.strip())
    if not match:
        return None
    y, mo, d, h, mi, s, fraction, zone = match.groups()
    key = (int(y), int(mo), int(d), int(h), int(mi), int(s))
    seconds = _seconds_cache.get(key)
    if seconds is None:
        if len(_seconds_cache) > 4096:
            _seconds_cache.clear()
        seconds = _seconds_cache[key] = calendar.timegm(key + (0, 0, 0))
    if zone and zone != "Z":
        sign = -1 if zone[0] == "+" else 1
        zone = zone[1:].replace(":", "")
        seconds += sign * (int(zone[:2]) * 3600 + int(zone[2:]) * 60)
    micros = int((fraction or "").ljust(6, "0")[:6] or 0)
    return seconds * 1_000_000 + micros


def format_time(micros: int) -> str:
    """RFC 3339, UTC, with microseconds."""
    seconds, fraction = divmod(micros, 1_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + (
        f".{fraction:06d}Z"
    )


def split_brackets(text: str) -> Tuple[List[str], List[int], str]:
    """Leading "[...]" groups of a line (nested brackets allowed), where each
    starts, and the rest of the line."""
    groups = []
    starts = []
    pos = 0
    while pos < len(text) and text[pos] == "[":
        depth = 0
        for end in range(pos, len(text)):
            if text[end] == "[":
                depth += 1
            elif text[end] == "]":
                depth -= 1
                if depth == 0:
                    break
        else:
            break
        groups.append(text[pos + 1 : end])
        starts.append(pos)
        pos = end + 1
        if pos < len(text) and text[pos] == " ":
            pos += 1
    return groups, starts, text[pos:]


def parse_node_prefix(rest: str) -> Tuple[Dict[str, Any], Optional[str], str]:
    """The fields, level and message of a bitcoind text log line, after its
    timestamp: "(mocktime: ...)", then "[thread]", "[file:line]",
    "[function]" and "[category]" or "[category:level]" (each optional)."""
    fields: Dict[str, Any] = {}
    match = MOCKTIME.match(rest)
    if match:
        fields["mocktime"] = match.group(1)
        rest = rest[match.end() :]
    rest = rest.lstrip(" ")
    groups, starts, message = split_brackets(rest)
    location = next((i for i, g in enumerate(groups) if SOURCE_LOCATION.match(g)), None)
    if location is not None:
        if location > 0:
            fields["thread"] = groups[location - 1]
        fields["source_location"] = groups[location]
        after = groups[location + 2 :]
    else:
        # Only short tags; anything else belongs to the message
        tags = []
        for g in groups:
            if not CATEGORY.match(g):
                break
            tags.append(g)
        if len(tags) < len(groups):
            message = rest[starts[len(tags)] :]
        if len(tags) > 1:
            fields["thread"] = tags[0]
        after = tags[-1:]
    level = None
    if after:
        category = CATEGORY.match(after[-1])
        if category:
            fields["category"] = category.group(1)
            level = category.group(2)
        elif location is not None:
            message = " ".join(f"[{g}]" for g in after) + " " + message
    if level is None:
        # bitcoind writes uncategorized lines at info level and categorized
        # ones (LogPrint) at debug level unless it says otherwise
        level = "debug" if "category" in fields else "info"
    return fields, normalize_level(level), message


def normalize_level(level: Any) -> Optional[str]:
    if not isinstance(level, str) or not level:
        return None
    level = level.lower()
    return LEVEL_NAMES.get(level, level)


def _reordered(events: Iterator[Event], window: int) -> Iterator[Event]:
    """Events in timestamp order, as long as none is more than `window`
    events late."""
    heap: List[Tuple[Tuple[int, int, int], Event]] = []
    for event in events:
        heapq.heappush(heap, (event.sort_key(), event))
        if len(heap) > window:
            yield heapq.heappop(heap)[1]
    while heap:
        yield heapq.heappop(heap)[1]


def parse_text(source: str, raw: str) -> Tuple[Dict[str, Any], Optional[str], str]:
    """Fields, level and message of a text log event (see text_events)."""
    lines = raw.split("\n")
    match = TIMESTAMP_PATTERN.match(lines[0])
    rest = lines[0][match.end() :].lstrip(" ") if match else lines[0]
    if source == "test":
        head = FRAMEWORK_LINE.match(rest)
        level, fields = None, {}
        if head:
            fields = {"category": head.group(1)}
            level = normalize_level(head.group(2))
            rest = rest[head.end() :]
    else:
        fields, level, rest = parse_node_prefix(rest)
    return fields, level, "\n".join([rest] + lines[1:])


def _file_mtime_micros(path: str) -> int:
    try:
        return int(os.path.getmtime(path) * 1_000_000)
    except OSError:
        return 0


def _open_lines(path: str) -> Optional[IO[str]]:
    try:
        return open(path, encoding="utf-8", errors="replace", newline="\n")
    except OSError:
        return None


def text_events(source: str, path: str, order: int = 0) -> Iterator[Event]:
    """Events of a text log (the framework's or a node's). A line that does
    not start with a timestamp continues the previous event; lines before
    the first timestamp take that timestamp. Empty lines are skipped."""
    stream = _open_lines(path)
    if stream is None:
        return
    with stream:
        yield from text_line_events(
            source, stream, order, lambda: _file_mtime_micros(path)
        )


def text_line_events(
    source: str,
    lines: Iterable[str],
    order: int = 0,
    fallback: Any = lambda: 0,
) -> Iterator[Event]:
    """text_events() over lines (with or without their newline);
    `fallback()` is the time of lines when no line has a timestamp."""
    seq = itertools.count()
    seconds_of: Dict[str, int] = {}
    event_lines: List[str] = []
    stamp: Optional[str] = None
    micros = 0
    pending: List[List[str]] = []  # Events before the first timestamp

    def event(lines: List[str], micros: int, stamp: Optional[str]) -> Event:
        return Event(
            micros,
            source,
            None,
            "\n".join(lines),
            order=order,
            seq=next(seq),
            time=stamp,
        )

    for line in lines:
        if line.endswith("\n"):
            line = line[:-1]
        if not line:
            continue
        match = TIMESTAMP_PATTERN.match(line)
        if match:
            if match.group(1) is None:
                # No microseconds: add zeroes
                new_stamp = match.group()[:-1] + ".000000Z"
                line = new_stamp + line[match.end() :]
            else:
                new_stamp = match.group()
            seconds = seconds_of.get(new_stamp[:19])
            if seconds is None:
                if len(seconds_of) > 4096:
                    seconds_of.clear()
                seconds = seconds_of[new_stamp[:19]] = (
                    parse_time(new_stamp[:19] + "Z") or 0
                ) // 1_000_000
            new_micros = seconds * 1_000_000 + int(new_stamp[20:26])
            if event_lines:
                if stamp is None:
                    pending.append(event_lines)
                else:
                    yield event(event_lines, micros, stamp)
            for early in pending:
                yield event(early, new_micros, new_stamp)
            pending = []
            stamp, micros, event_lines = new_stamp, new_micros, [line]
        else:
            event_lines.append(line)
    if event_lines:
        if stamp is None:
            pending.append(event_lines)
        else:
            yield event(event_lines, micros, stamp)
    if pending:
        when = fallback()
        for early in pending:
            yield event(early, when, None)


def record_time(record: Dict[str, Any]) -> Optional[int]:
    for key in ("time", "@timestamp", "timestamp"):
        micros = parse_time(record.get(key))
        if micros is not None:
            return micros
    return None


def record_level(record: Dict[str, Any]) -> Optional[str]:
    for key in ("level", "log.level", "severity"):
        if key in record:
            return normalize_level(record[key])
    return None


def json_events(source: str, path: str, order: int = 0) -> Iterator[Event]:
    """Events of a JSON-lines log. A record without a timestamp takes its
    predecessor's; a line that is not a JSON object (a partly written last
    line, say) is kept as a message."""
    stream = _open_lines(path)
    if stream is None:
        return
    with stream:
        yield from json_line_events(
            source, stream, order, lambda: _file_mtime_micros(path)
        )


def json_line_events(
    source: str,
    lines: Iterable[str],
    order: int = 0,
    fallback: Any = lambda: 0,
) -> Iterator[Event]:
    """json_events() over lines (see text_line_events)."""
    seq = itertools.count()
    micros = None
    for line in lines:
        if line.endswith("\n"):
            line = line[:-1]
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            record = {"message": line, "unparsed": True}
        micros = record_time(record) or micros
        if micros is None:
            micros = fallback()
        message = record.get("message", "")
        yield Event(
            micros,
            source,
            message if isinstance(message, str) else json.dumps(message),
            line,
            record_level(record),
            record,
            order,
            next(seq),
            is_json=True,
        )


def chain_dir_name(testdir: str) -> str:
    """The chain's directory name in a node's datadir ("regtest")."""
    paths = sorted(glob.glob(os.path.join(testdir, "node*", "*", "debug.log")))
    paths += sorted(glob.glob(os.path.join(testdir, "node*", "*", NODE_JSON_LOG)))
    if paths:
        return os.path.basename(os.path.dirname(paths[0]))
    return "regtest"


def node_json_log(chain_dir: str) -> Optional[str]:
    """A node's JSON-lines log in its chain directory, if any."""
    preferred = os.path.join(chain_dir, NODE_JSON_LOG)
    if os.path.isfile(preferred):
        return preferred
    others = sorted(glob.glob(os.path.join(chain_dir, "*.jsonl")))
    return others[0] if others else None


def log_sources(testdir: str, prefer_json: bool = True) -> List[Tuple[str, str, str]]:
    """(source, path, kind) of each log of a test directory, kind being
    "text" or "json"; the framework first, then the nodes by number."""
    sources = []
    framework_json = os.path.join(testdir, FRAMEWORK_JSON_LOG)
    if prefer_json and os.path.isfile(framework_json):
        sources.append(("test", framework_json, "json"))
    else:
        sources.append(("test", os.path.join(testdir, "test_framework.log"), "text"))
    chain = chain_dir_name(testdir)
    numbers = []
    for path in glob.glob(os.path.join(testdir, "node*")):
        suffix = os.path.basename(path)[len("node") :]
        if suffix.isdigit() and os.path.isdir(path):
            numbers.append(int(suffix))
    for n in sorted(numbers):
        chain_dir = os.path.join(testdir, f"node{n}", chain)
        json_log = node_json_log(chain_dir) if prefer_json else None
        if json_log:
            sources.append((f"node{n}", json_log, "json"))
        elif os.path.isfile(os.path.join(chain_dir, "debug.log")):
            sources.append((f"node{n}", os.path.join(chain_dir, "debug.log"), "text"))
    return sources


def merge(streams: Iterable[Iterator[Event]]) -> Iterator[Event]:
    """Merge streams of events, each in time order, into one."""
    return heapq.merge(
        *(_reordered(s, REORDER_WINDOW) for s in streams), key=Event.sort_key
    )


def read_timeline(testdir: str, prefer_json: bool = True) -> Iterator[Event]:
    """Every log event of a test directory, in time order."""
    streams = []
    for order, (source, path, kind) in enumerate(log_sources(testdir, prefer_json)):
        reader = json_events if kind == "json" else text_events
        streams.append(reader(source, path, order))
    return merge(streams)


def is_failure(event: Event) -> bool:
    """Whether this is the framework logging the exception that failed the
    test."""
    return (
        event.source == "test"
        and event.level == "error"
        and FAILURE_MESSAGE.match(event.message) is not None
    )


def compact_fields(event: Event) -> str:
    """A few identifying structured fields of a record, as "key=value"."""
    out = []
    for key in COMPACT_FIELDS:
        value = event.fields.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, str) and len(value) == 64 and key in HASH_FIELDS:
            value = value[:16] + "…"
        out.append(f"{key}={value}")
    return " ".join(out)


# Structured fields shown with a record's message in the failure excerpt
COMPACT_FIELDS = (
    "event",
    "peer_id",
    "peer",
    "addr",
    "msg_type",
    "txid",
    "block_hash",
    "height",
    "reason",
    "error",
)
HASH_FIELDS = {"txid", "block_hash"}


def text_of(event: Event) -> str:
    """The event as plain text: its raw line(s) for a text log; time, level,
    category and message (plus a few fields) for a JSON record."""
    if event.is_json and "unparsed" not in event.fields:
        head = [event.time]
        if event.fields.get("mocktime"):
            head.append(f"(mocktime: {event.fields['mocktime']})")
        if event.fields.get("thread"):
            head.append(f"[{event.fields['thread']}]")
        category = event.fields.get("category")
        head.append(f"[{category}:{event.level}]" if category else f"[{event.level}]")
        text = " ".join(head) + " " + event.message
        extra = compact_fields(event)
        if extra:
            text += f"  {{{extra}}}"
        exception = event.fields.get("exception")
        if exception:
            text += "\n" + str(exception).rstrip()
        return text
    return event.raw


def render(event: Event) -> str:
    """An event as it appears in combined.log: source column, then its text;
    following lines are indented to the text."""
    text = text_of(event)
    if not event.is_json and not TIMESTAMP_PATTERN.match(text):
        # Lines before a log's first timestamp: shown with the time they
        # are ordered by
        text = f"{event.time} {text}"
    lines = text.split("\n")
    pad = " " * (SOURCE_WIDTH + 1)
    return "\n".join(
        [f"{event.source:<{SOURCE_WIDTH}} {lines[0]}"]
        + [pad + line for line in lines[1:]]
    )


def short_lines(event: Event, first_only: bool = False) -> List[str]:
    """An event as compact lines for the failure block: source, time of day,
    level when it is a warning or worse, category and message (without the
    source location), and a few structured fields."""
    time_of_day = event.time[11:26]
    message = event.message
    category = event.fields.get("category")
    tag = ""
    if event.source != "test" and category:
        tag = f"[{category}] "
    if event.level in ("warning", "error"):
        tag = f"{event.level.upper()} " + tag
    exception = event.fields.get("exception") if not first_only else None
    lines = message.split("\n")
    if exception:
        lines += str(exception).rstrip().split("\n")
    if event.is_json and "unparsed" not in event.fields:
        extra = compact_fields(event)
        if extra:
            lines[0] += f"  {{{extra}}}"
    if first_only:
        lines = lines[:1]
    pad = " " * (SOURCE_WIDTH + 1 + len(time_of_day) + 1)
    out = [f"{event.source:<{SOURCE_WIDTH}} {time_of_day} {tag}{lines[0]}"]
    out += [pad + line for line in lines[1:]]
    return [fit(line, EXCERPT_LINE_LENGTH) for line in out]


def fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


# The fast path. A test's logs are already in time order and their
# timestamps are fixed-width ISO 8601 with microseconds, which order
# correctly as bytes. So the full timeline is merged in large binary blocks:
# no per-line parsing, regular expression or datetime; a line starts an event
# when it has a timestamp at a fixed position, and the merge compares the
# timestamp bytes. Blocks with anything else (lines without a timestamp, e.g.
# tracebacks, or timestamps without microseconds) go through the event
# parser above instead.

BLOCK_SIZE = 4 << 20
# Bytes of the source column: "node0  ", "test   ", "node10 "
PREFIX_WIDTH = SOURCE_WIDTH + 1
INDENT = b" " * PREFIX_WIDTH
# Where the timestamp is in a line of combined.log
COMBINED_KEY = slice(PREFIX_WIDTH, PREFIX_WIDTH + 27)
# The combined log is the text logs merged (see write_combined_log)
COMBINED_PREFERS_JSON = False


def _is_stamp(key: bytes) -> bool:
    """Whether 27 bytes look like a timestamp with microseconds, checking
    only the fixed punctuation (cheap enough for every line)."""
    return (
        key[26:27] == b"Z"
        and key[19:20] == b"."
        and key[10:11] == b"T"
        and key[4:5] == b"-"
        and key[:1].isdigit()
    )


def _all_stamped(lines: List[bytes], key: slice) -> bool:
    """Whether every line has a timestamp (see _is_stamp) at `key`: checked
    on all the lines' keys at once, with byte operations only."""
    n = len(lines)
    keys = b"".join(map(itemgetter(key), lines))
    return (
        len(keys) == 27 * n
        and keys[26::27] == b"Z" * n
        and keys[19::27] == b"." * n
        and keys[16::27] == b":" * n
        and keys[13::27] == b":" * n
        and keys[10::27] == b"T" * n
        and keys[4::27] == b"-" * n
        and keys[0::27].isdigit()
    )


def _blocks(path: str) -> Iterator[bytes]:
    """The file in blocks of whole lines (each ending with a newline)."""
    try:
        f = open(path, "rb")
    except OSError:
        return
    with f:
        rest = b""
        while True:
            data = f.read(BLOCK_SIZE)
            if not data:
                if rest:
                    yield rest + b"\n"
                return
            if rest:
                data = rest + data
            cut = data.rfind(b"\n") + 1
            rest = data[cut:]
            if cut:
                yield data[:cut]


def _text_batches(source: str, path: str, order: int) -> Iterator[List[bytes]]:
    """A text log as lists of combined.log entries (bytes, without the
    final newline), in file order: render() of each event."""
    prefix = f"{source:<{SOURCE_WIDTH}} ".encode()
    # The last event's raw lines (without prefix): following lines without
    # a timestamp continue it
    held: Optional[bytes] = None

    def entry(raw: bytes) -> bytes:
        return prefix + raw.replace(b"\n", b"\n" + INDENT)

    for block in _blocks(path):
        lines = (prefix + block[:-1].replace(b"\n", b"\n" + prefix)).split(b"\n")
        if _all_stamped(lines, COMBINED_KEY):
            batch = [entry(held)] if held is not None else []
            held = lines.pop()[PREFIX_WIDTH:]
            batch += lines
            yield batch
            continue
        # Lines without a timestamp (or one without microseconds): parse
        # the held event and this block as events, as the slow path does
        text = block[:-1].decode("utf-8", "replace").split("\n")
        if held is not None:
            text = held.decode("utf-8", "replace").split("\n") + text
        events = list(
            text_line_events(source, text, order, lambda: _file_mtime_micros(path))
        )
        if not events:
            held = None
            continue
        if getattr(events[-1], "_time") is None:
            # No timestamp yet: keep all of it for the next block
            held = "\n".join(text).encode()
            continue
        held = events.pop().raw.encode()
        if events:
            yield [render(e).encode() for e in events]
    if held is not None:
        if _is_stamp(held[:27]):
            yield [entry(held)]
        else:
            text = held.decode("utf-8", "replace").split("\n")
            yield [
                render(e).encode()
                for e in text_line_events(
                    source, text, order, lambda: _file_mtime_micros(path)
                )
            ]


def _count_below(batch: List[bytes], limit: bytes, key: slice) -> int:
    """How many entries of a sorted batch have a key < limit."""
    lo, hi = 0, len(batch)
    while lo < hi:
        mid = (lo + hi) // 2
        if batch[mid][key] < limit:
            lo = mid + 1
        else:
            hi = mid
    return lo


def merge_batches(
    sources: List[Iterator[List[bytes]]], key: slice
) -> Iterator[List[bytes]]:
    """Merge sources of batches of entries into batches in key order.

    Each source must be in key order; each batch is sorted as it is read,
    which also fixes disorder within a batch. Entries with equal keys keep
    their source's order, then their order within the source (Python's
    sort is stable).

    An entry can be emitted once every source still being read has
    buffered an entry with a greater key: each round emits the entries with
    keys below the smallest last key of those sources (an entry equal to it
    could be followed by more of the same key in that source's next batch),
    reading more from the sources at that key when nothing is below it."""
    getter = itemgetter(key)
    buffers: List[List[bytes]] = [[] for _ in sources]
    done = [False] * len(sources)

    def read(i: int) -> bool:
        try:
            batch = next(sources[i])
        except StopIteration:
            done[i] = True
            return False
        if buffers[i]:
            buffers[i] += batch
            buffers[i].sort(key=getter)
        else:
            keys = list(map(getter, batch))
            if not all(map(le, keys, keys[1:])):
                batch.sort(key=getter)
            buffers[i] = batch
        return True

    while True:
        for i in range(len(sources)):
            while not buffers[i] and not done[i]:
                read(i)
        live = [i for i, b in enumerate(buffers) if b]
        if not live:
            return
        limits = [buffers[i][-1][key] for i in live if not done[i]]
        out: List[bytes] = []
        if not limits:
            for i in live:
                out += buffers[i]
                buffers[i] = []
        else:
            limit = min(limits)
            for i in live:
                batch = buffers[i]
                n = _count_below(batch, limit, key)
                if n == len(batch):
                    out += batch
                    buffers[i] = []
                elif n:
                    out += batch[:n]
                    buffers[i] = batch[n:]
            if not out:
                for i in live:
                    if not done[i] and buffers[i][-1][key] == limit:
                        read(i)
                continue
        if len(live) > 1:
            out.sort(key=getter)
        yield out


def _write_batches(batches: Iterator[List[bytes]], path: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        for batch in batches:
            if batch:
                f.write(b"\n".join(batch))
                f.write(b"\n")
    os.replace(tmp, path)


def write_combined_log(testdir: str, path: Optional[str] = None) -> str:
    """Write <testdir>/combined.log: the text logs (test_framework.log and
    each node's debug.log) merged by time, each line prefixed by its source,
    continuation lines indented. Returns its path."""
    path = path or os.path.join(testdir, "combined.log")
    sources = [
        _text_batches(source, log, order)
        for order, (source, log, _) in enumerate(log_sources(testdir, False))
    ]
    _write_batches(merge_batches(sources, COMBINED_KEY), path)
    return path


def combined_text_slow(testdir: str) -> str:
    """combined.log's content built event by event (the reference that the
    fast path is tested against)."""
    return "".join(render(e) + "\n" for e in read_timeline(testdir, False))


# The failure excerpt only needs the end of each log up to the failure:
# it reads that from the end of each file, so its cost does not depend on
# the size of the logs.

TAIL_BLOCK = 1 << 16
FAILURE_TEXT = re.compile(
    rb"\n(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z) TestFramework \(ERROR\): "
    rb"(?:Unexpected exception|Called Process failed)"
)
FAILURE_JSON = re.compile(
    rb'\n\{"time": ?"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z)", ?"level": ?"error"'
    rb'[^\n]*?"message": ?"(?:Unexpected exception|Called Process failed)'
)


def _line_key(line: bytes) -> Optional[bytes]:
    """The timestamp bytes of a text or JSON log line, if it has one."""
    if line[:1] == b"{":
        # Compact JSON, as the nodes write it, or with spaces
        key = line[9:36] if line[:9] == b'{"time":"' else line[10:37]
    else:
        key = line[:27]
    return key if _is_stamp(key) else None


def _find_failure(path: str, kind: str) -> Optional[Tuple[int, bytes]]:
    """(end of its first line, timestamp) of the framework's logged
    exception: the last match, searching backwards from the end."""
    pattern = FAILURE_JSON if kind == "json" else FAILURE_TEXT
    try:
        f = open(path, "rb")
    except OSError:
        return None
    with f:
        end = f.seek(0, 2)
        pos = end
        while pos > 0:
            start = max(0, pos - TAIL_BLOCK * 16)
            f.seek(start)
            # Overlap the previous window by a line's worth
            data = b"\n" + f.read(min(end, pos + 4096) - start)
            last = None
            for last in pattern.finditer(data):
                pass
            if last is not None:
                line_end = data.find(b"\n", last.start() + 1)
                if line_end < 0:
                    line_end = len(data)
                return start + line_end - 1, last.group(1)
            pos = start
    return None


def _first_at_or_after(f: IO[bytes], size: int, limit: bytes, strict: bool) -> int:
    """Offset of the first line whose timestamp is > limit (strict) or
    >= limit (the file's size if none is), by binary search over the file,
    which is in time order. Lines without a timestamp are skipped."""

    def after(key: bytes) -> bool:
        return key > limit if strict else key >= limit

    def next_key(pos: int) -> Tuple[int, Optional[bytes]]:
        # The first line with a timestamp starting after pos (or at 0)
        f.seek(pos)
        if pos:
            f.readline()
        while True:
            at = f.tell()
            line = f.readline()
            if not line:
                return size, None
            key = _line_key(line)
            if key is not None:
                return at, key

    lo, hi = 0, size
    while hi - lo > TAIL_BLOCK:
        mid = (lo + hi) // 2
        at, key = next_key(mid)
        if key is not None and not after(key):
            lo = at + 1
        else:
            hi = mid
    # From lo, the first line that qualifies
    at, key = next_key(lo)
    while key is not None and not after(key):
        at, key = next_key(at + 1)
    return at


def _tail_events(
    source: str, path: str, kind: str, order: int, end: int, count: int
) -> List[Event]:
    """The last `count` events of a log before byte offset `end`."""
    try:
        f = open(path, "rb")
    except OSError:
        return []
    with f:
        start = end
        data = b""
        while start > 0:
            start = max(0, start - TAIL_BLOCK)
            f.seek(start)
            data = f.read(end - start)
            starts = sum(1 for line in data.split(b"\n") if _line_key(line))
            if starts > count + 1:
                break
    lines = data.split(b"\n")
    if start > 0:
        # Start at the first line with a timestamp: anything before it
        # belongs to an earlier event
        first = next((i for i, line in enumerate(lines) if _line_key(line)), 0)
        lines = lines[first:]
    data = b"\n".join(lines)
    text = data.decode("utf-8", "replace").split("\n")
    reader = json_line_events if kind == "json" else text_line_events
    events = list(reader(source, text, order, lambda: _file_mtime_micros(path)))
    return events[-count:]


def failure_excerpt(
    testdir: str, excerpt_lines: int = 40, stop_at_failure: bool = True
) -> Tuple[List[str], bool]:
    """The compact excerpt of a failed test's timeline: the last
    `excerpt_lines` lines up to and including the framework's logged
    exception (only its first line: the traceback is shown separately), or
    the last lines of all if it logged none. Also returns whether the
    exception was found. Reads only the end of each log: the framework log
    up to the exception, and each node's log up to the exception's time
    (found by binary search, since logs are in time order)."""
    sources = log_sources(testdir)
    failure = None
    if stop_at_failure and sources:
        _, path, kind = sources[0]
        failure = _find_failure(path, kind)
    events: List[Event] = []
    for order, (source, path, kind) in enumerate(sources):
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        end = size
        if failure is not None:
            if order == 0:
                end = failure[0]
            else:
                # Events at the exception's time come after it
                with open(path, "rb") as f:
                    end = _first_at_or_after(f, size, failure[1], strict=False)
        events += _tail_events(source, path, kind, order, end, excerpt_lines)
    events.sort(key=Event.sort_key)
    events = events[-excerpt_lines:]
    found = bool(events) and failure is not None and is_failure(events[-1])
    lines: List[str] = []
    for event in events:
        lines += short_lines(event, first_only=found and event is events[-1])
    return (lines[-excerpt_lines:] if excerpt_lines else []), found


class TestTimeline(unittest.TestCase):
    T = "2026-10-19T12:00:0{}.{:06d}Z"

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="timeline_unit_")
        self.addCleanup(shutil.rmtree, self.dir)

    def t(self, second, micro=0):
        return self.T.format(second, micro)

    def write(self, relpath, lines):
        path = os.path.join(self.dir, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(line + "\n" for line in lines))
        return path

    def framework(self, lines):
        self.write("test_framework.log", lines)

    def node(self, n, lines, name="debug.log"):
        return self.write(f"node{n}/regtest/{name}", lines)

    def sources_and_messages(self, **kwargs):
        return [(e.source, e.message) for e in read_timeline(self.dir, **kwargs)]

    def test_parse_time(self):
        self.assertEqual(parse_time("1970-01-01T00:00:01Z"), 1_000_000)
        self.assertEqual(parse_time("1970-01-01T00:00:01.5Z"), 1_500_000)
        self.assertEqual(parse_time("1970-01-01T00:00:01.123456789Z"), 1_123_456)
        self.assertEqual(parse_time("1970-01-01T01:00:00+01:00"), 0)
        self.assertIsNone(parse_time("yesterday"))
        self.assertIsNone(parse_time(None))
        self.assertEqual(format_time(1_123_456), "1970-01-01T00:00:01.123456Z")

    def test_interleaving_three_sources(self):
        self.framework(
            [
                f"{self.t(1)} TestFramework (INFO): start",
                f"{self.t(4)} TestFramework (INFO): check",
            ]
        )
        self.node(0, [f"{self.t(2)} n0 a", f"{self.t(5)} n0 b"])
        self.node(1, [f"{self.t(3)} [net] n1 a", f"{self.t(6)} n1 b"])
        self.assertEqual(
            self.sources_and_messages(),
            [
                ("test", "start"),
                ("node0", "n0 a"),
                ("node1", "n1 a"),
                ("test", "check"),
                ("node0", "n0 b"),
                ("node1", "n1 b"),
            ],
        )
        events = list(read_timeline(self.dir))
        self.assertEqual(events[0].level, "info")
        self.assertEqual(events[0].fields["category"], "TestFramework")
        self.assertEqual(events[2].fields["category"], "net")
        self.assertEqual(events[2].level, "debug")
        self.assertEqual(events[2].time, self.t(3))
        self.assertEqual(events[2].raw, f"{self.t(3)} [net] n1 a")

    def test_equal_timestamps_keep_order(self):
        # The framework's timestamps have millisecond resolution: lines with
        # the same timestamp keep their order, then sources keep theirs.
        self.framework([f"{self.t(1)} TestFramework (INFO): {c}" for c in "zyx"])
        self.node(0, [f"{self.t(1)} b", f"{self.t(1)} a"])
        self.node(1, [f"{self.t(1)} c"])
        self.assertEqual(
            [m for _, m in self.sources_and_messages()],
            ["z", "y", "x", "b", "a", "c"],
        )

    def test_node_order_is_numeric(self):
        for n in (10, 2):
            self.node(n, [f"{self.t(1)} from {n}"])
        self.assertEqual(
            [s for s, _ in self.sources_and_messages()], ["node2", "node10"]
        )

    def test_multiline_events(self):
        self.framework(
            [
                f"{self.t(1)} TestFramework (ERROR): Unexpected exception",
                "Traceback (most recent call last):",
                '  File "x.py", line 1',
                "AssertionError: boom",
                f"{self.t(3)} TestFramework (INFO): Stopping",
            ]
        )
        self.node(0, [f"{self.t(2)} node line"])
        events = list(read_timeline(self.dir))
        self.assertEqual([e.source for e in events], ["test", "node0", "test"])
        self.assertEqual(
            events[0].message.splitlines(),
            [
                "Unexpected exception",
                "Traceback (most recent call last):",
                '  File "x.py", line 1',
                "AssertionError: boom",
            ],
        )
        self.assertTrue(is_failure(events[0]))
        rendered = render(events[0]).splitlines()
        self.assertTrue(rendered[0].startswith("test   2026"))
        self.assertEqual(rendered[1], "       Traceback (most recent call last):")

    def test_mocktime_orders_on_wall_clock(self):
        self.node(
            0,
            [
                f"{self.t(1)} (mocktime: 2030-01-01T00:00:00Z) [/src/net.cpp:5] "
                "[void F(int [x])] [net:trace] mocked",
                f"{self.t(3)} later",
            ],
        )
        self.node(1, [f"{self.t(2)} (mocktime: 2000-01-01T00:00:00Z) between"])
        events = list(read_timeline(self.dir))
        self.assertEqual([e.message for e in events], ["mocked", "between", "later"])
        self.assertEqual(events[0].fields["mocktime"], "2030-01-01T00:00:00Z")
        self.assertEqual(events[0].fields["source_location"], "/src/net.cpp:5")
        self.assertEqual(events[0].fields["category"], "net")
        self.assertEqual(events[0].level, "trace")
        self.assertEqual(events[1].level, "info")

    def test_thread_and_bracketed_message(self):
        self.node(
            0,
            [
                f"{self.t(1)} [msghand] [/src/a.cpp:1] [f] [net] hello",
                f"{self.t(2)} [avalanche proof] not a tag",
            ],
        )
        events = list(read_timeline(self.dir))
        self.assertEqual(events[0].fields["thread"], "msghand")
        self.assertEqual(events[0].message, "hello")
        self.assertEqual(events[1].message, "[avalanche proof] not a tag")

    def test_json_sidecar_preferred(self):
        self.framework([f"{self.t(1)} TestFramework (INFO): start"])
        self.node(0, [f"{self.t(2)} text line"])
        record = {
            "time": self.t(2, 5),
            "level": "warning",
            "category": "net",
            "thread": "msghand",
            "message": "json line",
            "event": "peer_connected",
            "peer_id": 3,
            "source": {"file": "net.cpp", "line": 1, "function": "f"},
        }
        self.node(0, [json.dumps(record)], name=NODE_JSON_LOG)
        events = list(read_timeline(self.dir))
        self.assertEqual([e.message for e in events], ["start", "json line"])
        self.assertEqual(events[1].level, "warning")
        self.assertEqual(events[1].fields["peer_id"], 3)
        self.assertIn("{event=peer_connected peer_id=3}", render(events[1]))
        self.assertIn(
            "WARNING [net] json line  {event=peer_connected peer_id=3}",
            short_lines(events[1])[0],
        )
        # The text log is still read when asked to
        self.assertEqual(
            [m for _, m in self.sources_and_messages(prefer_json=False)],
            ["start", "text line"],
        )
        # Any *.jsonl in the chain directory, e.g. with -debuglogjsonfile
        os.rename(
            os.path.join(self.dir, "node0", "regtest", NODE_JSON_LOG),
            os.path.join(self.dir, "node0", "regtest", "custom.jsonl"),
        )
        self.assertEqual(self.sources_and_messages()[1], ("node0", "json line"))

    def test_json_without_time_or_partial(self):
        self.node(
            0,
            [
                json.dumps({"@timestamp": self.t(1), "log.level": "ERROR"}),
                json.dumps({"message": "no time"}),
                '{"time": "' + self.t(2),
            ],
            name=NODE_JSON_LOG,
        )
        events = list(read_timeline(self.dir))
        self.assertEqual(events[0].level, "error")
        self.assertEqual(events[1].micros, events[0].micros)
        self.assertEqual(events[2].fields["unparsed"], True)

    def test_missing_or_empty_logs(self):
        # No framework log, an empty node log and a node without a log
        self.node(0, [])
        os.makedirs(os.path.join(self.dir, "node1", "regtest"))
        self.node(2, [f"{self.t(1)} only line"])
        self.assertEqual(self.sources_and_messages(), [("node2", "only line")])
        empty = tempfile.mkdtemp(dir=self.dir)
        self.assertEqual(list(read_timeline(empty)), [])
        self.assertEqual(failure_excerpt(empty), ([], False))
        with open(write_combined_log(empty), "rb") as f:
            self.assertEqual(f.read(), b"")

    def test_lines_before_first_timestamp(self):
        self.node(0, ["no timestamp yet", f"{self.t(2)} stamped"])
        self.node(1, [f"{self.t(1)} first"])
        self.assertEqual(
            [m for _, m in self.sources_and_messages()],
            ["first", "no timestamp yet", "stamped"],
        )

    def test_reordering_within_a_source(self):
        self.node(0, [f"{self.t(2)} b", f"{self.t(1)} a", f"{self.t(3)} c"])
        self.assertEqual([m for _, m in self.sources_and_messages()], ["a", "b", "c"])

    def test_cut_at_failure(self):
        self.framework(
            [f"{self.t(1, i)} TestFramework (INFO): step {i}" for i in range(50)]
            + [
                f"{self.t(3)} TestFramework (ERROR): Unexpected exception",
                "Traceback (most recent call last):",
                "AssertionError: boom",
                f"{self.t(5)} TestFramework (INFO): Not stopping nodes",
            ]
        )
        self.node(
            0,
            [
                f"{self.t(2)} [net:warning] relevant node line",
                f"{self.t(4)} after the failure",
            ],
        )
        excerpt, found = failure_excerpt(self.dir, excerpt_lines=10)
        self.assertTrue(found)
        self.assertEqual(len(excerpt), 10)
        self.assertEqual(
            excerpt[-1], "test   12:00:03.000000 ERROR Unexpected exception"
        )
        self.assertEqual(
            excerpt[-2], "node0  12:00:02.000000 WARNING [net] relevant node line"
        )
        self.assertEqual(excerpt[-3], "test   12:00:01.000049 step 49")
        text = "\n".join(excerpt)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("after the failure", text)
        self.assertEqual((excerpt, found), self.slow_excerpt(10))
        # combined.log has everything, the traceback once
        path = write_combined_log(self.dir)
        self.assertEqual(path, os.path.join(self.dir, "combined.log"))
        with open(path, encoding="utf-8") as f:
            combined = f.read()
        self.assertEqual(combined.count("Traceback"), 1)
        self.assertIn("node0  " + self.t(4) + " after the failure", combined)
        self.assertEqual(len(combined.splitlines()), 50 + 3 + 1 + 2)
        # Without a logged exception: the last lines of all
        excerpt, found = failure_excerpt(
            self.dir, excerpt_lines=2, stop_at_failure=False
        )
        self.assertFalse(found)
        self.assertEqual(excerpt[-1], "test   12:00:05.000000 Not stopping nodes")

    def test_streams_large_logs(self):
        # Events are produced lazily: the first one comes before the file is
        # read to the end.
        path = self.node(0, [f"{self.t(1)} line {i}" for i in range(10000)])
        stream = text_events("node0", path)
        self.assertEqual(next(stream).message, "line 0")
        with open(write_combined_log(self.dir), "rb") as f:
            self.assertEqual(len(f.read().splitlines()), 10000)

    def slow_excerpt(self, count, stop=True):
        """The excerpt as the merged timeline gives it, event by event."""
        recent: Any = __import__("collections").deque(maxlen=count)
        failure = None
        for event in read_timeline(self.dir):
            recent.append(event)
            if stop and is_failure(event):
                failure = event
                break
        lines: List[str] = []
        for event in recent:
            lines += short_lines(event, first_only=event is failure)
        return lines[-count:], failure is not None

    def small_blocks(self):
        """Blocks of a few lines, so that events span block boundaries."""
        global BLOCK_SIZE, TAIL_BLOCK
        saved = BLOCK_SIZE, TAIL_BLOCK
        BLOCK_SIZE, TAIL_BLOCK = 300, 200

        def restore():
            global BLOCK_SIZE, TAIL_BLOCK
            BLOCK_SIZE, TAIL_BLOCK = saved

        self.addCleanup(restore)

    def random_logs(self, rng, failure=True):
        """Three sources in time order, with equal timestamps across and
        within them, tracebacks, blank lines, whitespace-only lines,
        mocktime, lines before the first timestamp, and sometimes a log with
        whole-second timestamps; nodes keep logging after the failure."""

        def stamp(us):
            return f"2026-10-19T12:00:{us // 1_000_000:02d}.{us % 1_000_000:06d}Z"

        framework = []
        us = 0
        for i in range(rng.randrange(50, 150)):
            us += rng.choice([0, 0, 1000, 3000])
            framework.append(f"{stamp(us)} TestFramework (INFO): step {i}  ")
            if rng.random() < 0.05:
                framework += ["  continued", "   ", "Traceback-ish line"]
        if failure:
            us += 1000
            framework += [
                f"{stamp(us)} TestFramework (ERROR): Unexpected exception",
                "Traceback (most recent call last):",
                "AssertionError: boom",
            ]
        framework.append(f"{stamp(us + 1000)} TestFramework (INFO): Not stopping")
        self.framework(framework)
        for n in (0, 1):
            lines = ["", "before any timestamp"] if n == 1 else []
            # A log without microseconds (still in time order)
            seconds_only = n == 1 and rng.random() < 0.3
            t = 0
            while t < us + 500_000:
                t += rng.choice([0, 1, 7, 1000, 2500])
                line = f"{stamp(t)} (mocktime: 2030-01-01T00:00:00Z) [net] m{t}"
                if seconds_only:
                    line = line[:19] + line[26:]
                lines.append(line)
                if rng.random() < 0.02:
                    lines += ["", "  continuation"]
            self.node(n, lines)

    def test_fast_combined_log_matches_slow(self):
        rng = random.Random(1)
        for block_size in (None, 300):
            for _ in range(5):
                shutil.rmtree(self.dir)
                os.makedirs(self.dir)
                if block_size:
                    self.small_blocks()
                self.random_logs(rng)
                with open(write_combined_log(self.dir), "rb") as f:
                    fast = f.read()
                self.assertEqual(fast, combined_text_slow(self.dir).encode())

    def test_fast_excerpt_matches_slow(self):
        rng = random.Random(2)
        self.small_blocks()
        for failure in (True, True, True, False):
            shutil.rmtree(self.dir)
            os.makedirs(self.dir)
            self.random_logs(rng, failure)
            for count in (1, 5, 40):
                self.assertEqual(
                    failure_excerpt(self.dir, count),
                    self.slow_excerpt(count),
                )

    def test_binary_search(self):
        lines = [f"{self.t(1, i // 3)} line {i}" for i in range(3000)]
        lines.insert(10, "continuation")
        path = self.node(0, lines)
        self.small_blocks()
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            for micro in (0, 1, 500, 999, 1000):
                limit = self.t(1, micro).encode()
                for strict in (False, True):
                    at = _first_at_or_after(f, size, limit, strict)
                    f.seek(0)
                    data = f.read()
                    expected = size
                    offset = 0
                    for line in data.split(b"\n"):
                        key = _line_key(line)
                        if key and (key > limit if strict else key >= limit):
                            expected = offset
                            break
                        offset += len(line) + 1
                    self.assertEqual(at, expected, (micro, strict))
