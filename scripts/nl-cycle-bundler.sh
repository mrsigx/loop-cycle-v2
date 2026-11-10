#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-}"
if [ -z "$cmd" ]; then
    echo "usage: nl-cycle-bundler.sh bundle --repo <dir> --output <manifest.json> [--path <rel> ...] | verify --manifest <manifest.json>" >&2
    exit 64
fi
shift

case "$cmd" in
    bundle)
        python3 - "$@" <<'PY'
import hashlib, json, os, subprocess, sys, tarfile

args = sys.argv[1:]
repo = None
output = None
paths = []
i = 0
while i < len(args):
    if args[i] == "--repo" and i + 1 < len(args):
        repo = args[i + 1]
        i += 2
    elif args[i] == "--output" and i + 1 < len(args):
        output = args[i + 1]
        i += 2
    elif args[i] == "--path" and i + 1 < len(args):
        paths.append(args[i + 1])
        i += 2
    else:
        print(f"unrecognized argument: {args[i]}", file=sys.stderr)
        sys.exit(64)

if not repo or not output:
    print("bundle requires --repo and --output", file=sys.stderr)
    sys.exit(64)

raw = subprocess.check_output(
    ["git", "-C", repo, "status", "--porcelain=v1", "-z", "-uall"]
)
entries = [e for e in raw.split(b"\x00") if e]
dirty = set()
idx = 0
while idx < len(entries):
    item = entries[idx].decode("utf-8", errors="surrogateescape")
    status = item[:2]
    rel = item[3:]
    dirty.add(rel)
    if "R" in status or "C" in status:
        idx += 1
        if idx < len(entries):
            dirty.add(entries[idx].decode("utf-8", errors="surrogateescape"))
    idx += 1

allowed = set(paths)
unreviewed = sorted(dirty - allowed)
if unreviewed:
    print(f"nl-cycle refused bundle: unreviewed working-tree drift: {unreviewed}", file=sys.stderr)
    sys.exit(2)

os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
archive_path = output + ".tar.gz"

file_records = []
with tarfile.open(archive_path, "w:gz") as tf:
    for rel in sorted(allowed):
        full = os.path.join(repo, rel)
        if os.path.exists(full):
            h = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            tf.add(full, arcname=rel, recursive=False)
            file_records.append({"path": rel, "present": True, "sha256": h.hexdigest()})
        else:
            file_records.append({"path": rel, "present": False, "sha256": None})

h512 = hashlib.sha512()
with open(archive_path, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        h512.update(chunk)

manifest = {
    "schema": "loop-cycle-bundle/1",
    "archive_path": archive_path,
    "archive_sha512": h512.hexdigest(),
    "files": file_records,
}
with open(output, "w", encoding="utf-8", newline="\n") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY
        ;;
    verify)
        python3 - "$@" <<'PY'
import hashlib, json, os, sys

args = sys.argv[1:]
manifest_path = None
i = 0
while i < len(args):
    if args[i] == "--manifest" and i + 1 < len(args):
        manifest_path = args[i + 1]
        i += 2
    else:
        print(f"unrecognized argument: {args[i]}", file=sys.stderr)
        sys.exit(64)

if not manifest_path or not os.path.isfile(manifest_path):
    print("verify requires an existing --manifest file", file=sys.stderr)
    sys.exit(2)

with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

archive_path = manifest.get("archive_path", "")
expected_sha512 = manifest.get("archive_sha512", "")
if not archive_path or not os.path.isfile(archive_path) or not expected_sha512:
    print("bundle archive missing or archive_sha512 unset", file=sys.stderr)
    sys.exit(2)

h512 = hashlib.sha512()
with open(archive_path, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        h512.update(chunk)

if h512.hexdigest() != expected_sha512:
    print("archive_sha512 mismatch", file=sys.stderr)
    sys.exit(2)

print("nl-cycle verified manifest")
PY
        ;;
    *)
        echo "unsupported command: $cmd" >&2
        exit 64
        ;;
esac
