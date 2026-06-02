#!/usr/bin/env python3
"""Copy posts ready to publish from private repo into public repo."""
from __future__ import annotations

import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

PUBLIC = Path("public")
PRIVATE = Path("private")
PRIVATE_POSTS = PRIVATE / "content" / "post"
PUBLIC_POSTS = PUBLIC / "content" / "post"
PRIVATE_IMAGES = PRIVATE / "static" / "images"
PUBLIC_IMAGES = PUBLIC / "static" / "images"


def parse_front_matter(text: str) -> tuple[bool | None, datetime | None]:
    draft: bool | None = None
    date_val: datetime | None = None
    fm = ""

    if text.startswith("+++"):
        end = text.find("+++", 3)
        if end == -1:
            return None, None
        fm = text[3:end]
        if re.search(r"^draft\s*=\s*true\s*$", fm, re.M | re.I):
            draft = True
        elif re.search(r"^draft\s*=\s*false\s*$", fm, re.M | re.I):
            draft = False
        m = re.search(r'^date\s*=\s*("?[^"\n]+"?)', fm, re.M)
        if m:
            date_val = parse_date(m.group(1))
    elif text.startswith("---"):
        end = text.find("---", 3)
        if end == -1:
            return None, None
        fm = text[3:end]
        if re.search(r"^draft:\s*true\s*$", fm, re.M | re.I):
            draft = True
        elif re.search(r"^draft:\s*false\s*$", fm, re.M | re.I):
            draft = False
        m = re.search(r"^date:\s*([^\n]+)", fm, re.M)
        if m:
            date_val = parse_date(m.group(1).strip())

    return draft, date_val


def parse_date(raw: str) -> datetime | None:
    s = raw.strip().strip('"').strip("'")
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_ready(draft: bool | None, date_val: datetime | None, now: datetime) -> bool:
    if draft is not False:
        return False
    if date_val is None:
        return False
    return date_val <= now


def image_refs(md_path: Path) -> set[str]:
    text = md_path.read_text(encoding="utf-8", errors="replace")
    names: set[str] = set()
    for m in re.finditer(r"!\[[^\]]*\]\(/images/([^)]+)\)", text):
        names.add(m.group(1))
    return names


def main() -> int:
    if not PRIVATE_POSTS.is_dir():
        print("No private content/post directory")
        return 0

    now = datetime.now(timezone.utc)
    migrated: list[Path] = []

    for src in sorted(PRIVATE_POSTS.glob("*.md")):
        if src.name == "_index.md":
            continue
        text = src.read_text(encoding="utf-8", errors="replace")
        draft, date_val = parse_front_matter(text)
        if not is_ready(draft, date_val, now):
            print(f"skip {src.name}: draft={draft} date={date_val}")
            continue

        dest = PUBLIC_POSTS / src.name
        PUBLIC_POSTS.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        print(f"copy post {src.name} -> {dest}")

        for img in image_refs(src):
            p_src = PRIVATE_IMAGES / img
            p_dest = PUBLIC_IMAGES / img
            if p_src.is_file():
                PUBLIC_IMAGES.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p_src, p_dest)
                print(f"copy image {img}")

        migrated.append(src.relative_to(PRIVATE))

    Path("/tmp/migrated-posts.txt").write_text(
        "\n".join(str(p) for p in migrated), encoding="utf-8"
    )
    print(f"ready to publish: {len(migrated)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
