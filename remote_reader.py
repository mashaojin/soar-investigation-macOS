"""Read-only Ubuntu-side batch reader, transmitted over SSH; never installed."""
import base64
import glob
import hashlib
import json
import os
from pathlib import Path
import sys


LIMIT = 262144
MAX_LINE = 1048576


class CollectionGap(ValueError):
    pass


def identity(stat):
    return f"{stat.st_dev}:{stat.st_ino}"


def anchor(stream, offset):
    stream.seek(max(0, offset - 256))
    return hashlib.sha256(stream.read(min(offset, 256))).hexdigest()


def read_batch(request):
    path = Path(request["path"])
    if not path.is_absolute():
        raise ValueError("Log path must be absolute")
    previous = request.get("cursor")
    # Only uncompressed files can retain the original checkpoint identity.
    candidates = []
    rotated_names = sorted(glob.glob(glob.escape(str(path)) + ".*"))
    if len(rotated_names) > 100:
        raise CollectionGap("Too many rotation files to inspect safely")
    for name in [str(path)] + rotated_names:
        try:
            stat = os.stat(name)
            if Path(name).is_file():
                candidates.append((name, stat))
        except FileNotFoundError:
            pass
    # Drained rotated files advance chronologically; active file is always last.
    candidates.sort(key=lambda item: (item[0] == str(path), item[1].st_mtime_ns, item[0]))
    selected = next((i for i, (_, st) in enumerate(candidates)
                     if previous and identity(st) == previous["identity"]), None)
    if previous and selected is None:
        raise CollectionGap("Checkpoint file is missing or compressed; retained history needs review")
    if not previous:
        selected = next((i for i, (name, _) in enumerate(candidates) if name == str(path)), None)
        if selected is None:
            raise FileNotFoundError(str(path))
    name, expected = candidates[selected]
    if name.endswith((".gz", ".xz", ".bz2", ".zip")):
        raise CollectionGap("Unread rotated history is compressed; operator recovery required")
    with open(name, "rb") as stream:
        stat = os.fstat(stream.fileno())
        if identity(stat) != identity(expected):
            raise OSError("Log rotated during open; retry without advancing checkpoint")
        if previous:
            offset = previous["offset"]
            if stat.st_size < offset or anchor(stream, offset) != previous["anchor"]:
                raise CollectionGap("Log was truncated or rewritten; unread history may be lost")
        elif request.get("start_at", "end") == "end":
            # Keep an incomplete final line for the next batch.
            stream.seek(max(0, stat.st_size - MAX_LINE))
            tail = stream.read()
            newline = tail.rfind(b"\n")
            if stat.st_size and newline < 0:
                raise CollectionGap("Cannot find a complete-line baseline within the line-size limit")
            offset = stat.st_size - len(tail) + newline + 1
        else:
            offset = 0
        skipped = offset if not previous else 0
        stream.seek(offset)
        lines = []
        total = 0
        partial = False
        while total < LIMIT:
            start = stream.tell()
            line = stream.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE:
                raise CollectionGap("Log line exceeds 1 MiB; operator review required")
            if not line:
                break
            if not line.endswith(b"\n"):
                partial = True
                stream.seek(start)
                break
            lines.append(base64.b64encode(line).decode("ascii"))
            total += len(line)
        offset = stream.tell()
        current_stat = os.fstat(stream.fileno())
        more = offset < current_stat.st_size and not partial
        cursor = {"identity": identity(stat), "offset": offset,
                  "anchor": anchor(stream, offset)}
        rotated = False
        if not more and name != str(path):
            if partial:
                raise CollectionGap("Rotated file has an incomplete final line")
            if selected + 1 < len(candidates):
                next_name, next_stat = candidates[selected + 1]
                if next_name.endswith((".gz", ".xz", ".bz2", ".zip")):
                    raise CollectionGap("Compressed rotation lies before the active log; operator recovery required")
                cursor = {"identity": identity(next_stat), "offset": 0,
                          "anchor": hashlib.sha256(b"").hexdigest()}
                more = True
                rotated = True
        return {"cursor": cursor, "lines": lines, "has_more": more,
                "baseline_skipped_bytes": skipped, "rotation_advanced": rotated}


def main():
    try:
        print(json.dumps({"ok": True, **read_batch(json.load(sys.stdin))}))
    except CollectionGap as exc:
        print(json.dumps({"ok": False, "kind": "gap", "error": str(exc)}))
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"ok": False, "kind": "read_error", "error": str(exc)}))


if __name__ == "__main__":
    main()
