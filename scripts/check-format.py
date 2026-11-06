#!/usr/bin/env python3
"""Check all maintained Go files without modifying the working tree."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    go = sys.argv[1] if len(sys.argv) > 1 else "go"
    goroot = subprocess.check_output([go, "env", "GOROOT"], text=True).strip()
    gofmt = Path(goroot) / "bin" / ("gofmt.exe" if sys.platform == "win32" else "gofmt")
    files = [
        str(path) for path in sorted(ROOT.rglob("*.go"))
        if not any(part.startswith(".") or part in ("vendor", "node_modules")
                   for part in path.relative_to(ROOT).parts)
    ]
    result = subprocess.run([str(gofmt), "-l", *files], text=True, capture_output=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.stdout:
        print(result.stdout, end="")
        print("Run make fmt and review the resulting changes.")
    return result.returncode or bool(result.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
