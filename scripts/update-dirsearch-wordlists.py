#!/usr/bin/env python3
"""Vendor only dirsearch/db from a resolved Git commit, or check its integrity."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
DESTINATION = ROOT / "dirscan/wordlists/dirsearch"
REPOSITORY = "https://github.com/maurosoria/dirsearch.git"
LOCK = "upstream.json"


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE
    ).stdout


def inventory(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlinks are not allowed: {path}")
        if path.is_file() and path.relative_to(directory).as_posix() != LOCK:
            files[path.relative_to(directory).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return files


def check(directory):
    if directory.is_symlink():
        raise ValueError("snapshot directory must not be a symlink")
    lock = json.loads((directory / LOCK).read_text(encoding="utf-8"))
    if lock["repository"] != REPOSITORY or lock["format"] != 1:
        raise ValueError("unrecognized upstream lock")
    if inventory(directory) != lock["files_sha256"]:
        raise ValueError("snapshot differs from lock; move local changes outside the snapshot")
    return lock


def export(repo, ref, destination):
    # Resolve refs before reading files; never copy a source working tree.
    commit = git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()
    tree = git(repo, "rev-parse", commit + ":db").decode().strip()
    entries = git(repo, "ls-tree", "-rz", "--full-tree", commit, "--", "db").split(b"\0")
    count = 0
    for entry in filter(None, entries):
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        relative = PurePosixPath(raw_path.decode("utf-8"))
        if mode not in (b"100644", b"100755") or kind != b"blob":
            raise ValueError(f"unsupported Git entry: {relative}")
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "db":
            raise ValueError(f"unsafe Git path: {relative}")
        output = destination.joinpath(*relative.parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(git(repo, "cat-file", "blob", oid.decode()))
        output.chmod(0o755 if mode == b"100755" else 0o644)
        count += 1
    if not count:
        raise ValueError("upstream db is empty")
    # Keep original attribution and licensing statements alongside the data.
    for source, name in [
        ("README.md", "README.upstream.md"),
        ("pyproject.toml", "PACKAGING.upstream.txt"),
    ]:
        (destination / name).write_bytes(git(repo, "show", commit + ":" + source))
    lock = {
        "format": 1,
        "repository": REPOSITORY,
        "upstream_path": "db",
        "commit": commit,
        "db_tree": tree,
        "files_sha256": inventory(destination),
    }
    (destination / LOCK).write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", help="commit/tag/branch to import; defaults to the locked commit")
    parser.add_argument("--source", type=Path, help="read objects from a local Git checkout (offline)")
    parser.add_argument("--check", action="store_true", help="verify local files without network access")
    args = parser.parse_args()
    if args.check:
        if args.ref or args.source:
            parser.error("--check cannot be combined with --ref or --source")
        lock = check(DESTINATION)
        print(f"Verified {len(lock['files_sha256'])} files at {lock['commit']}")
        return
    previous = check(DESTINATION) if DESTINATION.exists() else None
    ref = args.ref or (previous["commit"] if previous else None)
    if not ref or ref.startswith("-"):
        parser.error("initial import needs --ref COMMIT; refs cannot start with '-'")
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dirsearch-update-") as temporary:
        repo = args.source.resolve() if args.source else Path(temporary) / "upstream.git"
        if not args.source:
            subprocess.run(["git", "init", "--bare", "--quiet", str(repo)], check=True)
            git(repo, "fetch", "--depth=1", REPOSITORY, ref)
            ref = "FETCH_HEAD"
        # Stage beside the destination so directory renames stay on one filesystem.
        with tempfile.TemporaryDirectory(prefix=".dirsearch-update-", dir=DESTINATION.parent) as staged:
            stage = Path(staged) / "snapshot"
            stage.mkdir()
            lock = export(repo, ref, stage)
            check(stage)
            # Recheck before replacement to avoid overwriting edits made during fetch.
            if previous is not None:
                if check(DESTINATION) != previous:
                    raise ValueError("snapshot changed during update")
            elif DESTINATION.exists() or DESTINATION.is_symlink():
                raise ValueError("snapshot appeared during update")
            backup = Path(staged) / "previous"
            if previous is not None:
                os.replace(DESTINATION, backup)
            try:
                os.replace(stage, DESTINATION)
            except OSError:
                if backup.exists():
                    os.replace(backup, DESTINATION)
                raise
    print(f"Pinned dirsearch/db at {lock['commit']} ({len(lock['files_sha256'])} files)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"dirsearch update failed: {error}") from error
