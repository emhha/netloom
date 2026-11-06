#!/usr/bin/env python3
"""Check maintained Markdown links and Netloom's module/package layout offline."""

import ipaddress
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
MODULE = "github.com/emhha/netloom"
UPSTREAM = ("dirscan/wordlists/dirsearch/",)
REQUIRED = (
    "README.md", "AGENTS.md", "CONTRIBUTING.md", "Makefile",
    "docs/README.md", "docs/architecture.md", "docs/development.md",
    "docs/testing.md", "docs/UPGRADING.md", "docs/provenance/README.md",
    "examples/README.md", "httpclient/README.md", "mapping/README.md",
    "enterprise/README.md", "httpdata/netloomdata/convert.go",
)


def maintained_markdown(relative):
    name = relative.name
    path = relative.as_posix()
    return not (
        path.startswith(UPSTREAM)
        or ".upstream." in name
        or name.startswith(("README.wappalyzergo", "LICENSE"))
    )


def markdown_links(text):
    # Fences and inline code can contain illustrative links, not actual targets.
    text = re.sub(r"^```[^\n]*\n.*?^```[^\n]*$", "", text, flags=re.M | re.S)
    text = re.sub(r"`[^`\n]+`", "", text)
    return re.findall(r"!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)", text)


def check_links(root, path):
    errors = []
    for raw in markdown_links(path.read_text(encoding="utf-8")):
        target = raw.strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        destination = (path.parent / unquote(parsed.path)).resolve()
        if not destination.is_relative_to(root.resolve()):
            errors.append(f"{path.relative_to(root)}: link leaves repository: {target}")
        elif not destination.exists():
            errors.append(f"{path.relative_to(root)}: missing link target: {target}")
    return errors


def check_privacy(root, path):
    text = path.read_text(encoding="utf-8")
    relative = path.relative_to(root)
    errors = []
    # Inspect examples and code fences too; they can leak deployment details.
    private_networks = tuple(ipaddress.ip_network(network) for network in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    ))
    for url in re.findall(r'https?://[^\s<>"`\)\]]+', text, flags=re.I):
        try:
            address = ipaddress.IPv4Address(urlsplit(url).hostname)
        except (ValueError, TypeError):
            continue
        if address.is_loopback or address.is_link_local or any(address in network for network in private_networks):
            errors.append(f"{relative}: private deployment URL in maintained documentation")
    if re.search(r"/(?:home|Users)/[^/\s`]+(?:/[^\s`]+)?", text):
        errors.append(f"{relative}: per-user absolute workspace path in maintained documentation")
    return errors


def check(root):
    errors = []
    for name in REQUIRED:
        if not (root / name).is_file():
            errors.append(f"missing required file: {name}")
    module = root / "go.mod"
    if not module.is_file() or not re.search(
        rf"^module {re.escape(MODULE)}$", module.read_text(), re.M
    ):
        errors.append(f"go.mod must declare module {MODULE}")
    if (root / "httpdata/netrtdata").exists():
        errors.append("obsolete adapter directory: httpdata/netrtdata")
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part.startswith(".") or part in ("node_modules", "vendor") for part in relative.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix == ".md" and maintained_markdown(relative):
            errors.extend(check_links(root, path))
            errors.extend(check_privacy(root, path))
        if path.suffix != ".go":
            continue
        text = path.read_text(encoding="utf-8")
        imports = []
        for block, single in re.findall(
            r'(?m)^import\s+(?:\(([\s\S]*?)^\)|((?:[.\w]+\s+)?"[^"\n]+"))', text
        ):
            imports.extend(re.findall(r'"([^"\n]+)"', block or single))
        if any(re.match(r"^(?:netloom(?:/|$)|netloom\.local/|netrt\.local/)", name) for name in imports):
            errors.append(f"{relative}: obsolete Go name/import")
        # Runtime and neutral snapshots must stay independent of extensions.
        if not path.name.endswith("_test.go"):
            local_refs = [name for name in imports if name == MODULE or name.startswith(MODULE + "/")]
            if path.parent == root and local_refs:
                errors.append(f"{relative}: root runtime must not import extensions")
            if path.parent == root / "httpdata" and local_refs:
                errors.append(f"{relative}: neutral httpdata must not import runtime/extensions")
        if re.search(r"\bnetrt\b|\bnetrtdata\b|netloom\.local/", text, re.I):
            errors.append(f"{relative}: obsolete Go name/import")
        if path.parent == root and not re.search(r"^package netloom(?:_test)?$", text, re.M):
            errors.append(f"{relative}: root Go package must be netloom")
        if path.parent == root / "httpdata/netloomdata" and not re.search(
            r"^package netloomdata(?:_test)?$", text, re.M
        ):
            errors.append(f"{relative}: adapter Go package must be netloomdata")
    return errors


def main():
    errors = check(ROOT)
    if errors:
        for error in errors:
            print(error)
        return 1
    print("Repository checks passed (local links, module, package layout, Go naming).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
