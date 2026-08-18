#!/usr/bin/env python3
"""Fail when Markdown in a public candidate links to an absent local target."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


LINK = re.compile(
    r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^\s)]+)(?:\s+['\"][^'\"]*['\"])?\)"
)


def missing_links(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    findings: list[str] = []
    for markdown in sorted(root.rglob("*.md")):
        text = markdown.read_text(encoding="utf-8", errors="replace")
        for match in LINK.finditer(text):
            target = match.group("target")
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            relative = Path(unquote(parsed.path))
            if relative.is_absolute():
                findings.append(
                    f"{markdown.relative_to(root)}: absolute local link: {target}"
                )
                continue
            resolved = (markdown.parent / relative).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                findings.append(
                    f"{markdown.relative_to(root)}: link escapes candidate: {target}"
                )
                continue
            if not resolved.exists():
                findings.append(
                    f"{markdown.relative_to(root)}: missing local target: {target}"
                )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    findings = missing_links(args.candidate)
    if findings:
        print("Public-candidate Markdown link check failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print("Public-candidate Markdown local links resolve inside the candidate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
