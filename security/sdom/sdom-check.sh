#!/usr/bin/env bash
# Security Domain Object Model (SDOM) checker for the repository.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export ROOT

cd "$ROOT"

if [[ ! -f "$ROOT/security/sdom/sdom.config.json" ]]; then
  echo "sdom-check: missing security/sdom/sdom.config.json — run ./security/sdom/sdom-configure.sh first" >&2
  exit 2
fi

python3 <<'PY'
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
CONFIG = ROOT / "security/sdom/sdom.config.json"
REPORT = ROOT / "security/sdom/last-report.txt"

with CONFIG.open(encoding="utf-8") as f:
    cfg = json.load(f)

critical = []
high = []
medium = []
info = []


def add(severity: str, message: str) -> None:
    bucket = {"critical": critical, "high": high, "medium": medium, "info": info}[severity]
    bucket.append(message)


def git_tracked() -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]


def should_scan(path: str) -> bool:
    scan = cfg.get("scan", {})
    for prefix in scan.get("exclude_paths", []):
        if path.startswith(prefix) or fnmatch.fnmatch(path, prefix):
            return False
    ext = Path(path).suffix.lower()
    if ext in scan.get("exclude_extensions", []):
        return False
    return True


def is_allowlisted(line: str) -> bool:
    for item in cfg.get("allowlist_patterns", []):
        if re.search(item["pattern"], line):
            return True
    return False


files = git_tracked()

# 1) Forbidden tracked files
for pattern in cfg.get("forbidden_tracked_files", []):
    for path in files:
        if fnmatch.fnmatch(path, pattern) or path == pattern.lstrip("*"):
            add("critical", f"Forbidden tracked file: {path} (pattern {pattern})")

# 2) .gitignore requirements
gitignore = ROOT / ".gitignore"
gi_text = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
for entry in cfg.get("required_gitignore_entries", []):
    if entry not in gi_text:
        add("high", f".gitignore missing recommended entry: {entry}")

# 3) Secret pattern scan
for path in files:
    if not should_scan(path):
        continue
    full = ROOT / path
    if not full.is_file():
        continue
    try:
        text = full.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for line_no, line in enumerate(text.splitlines(), start=1):
        if is_allowlisted(line):
            continue
        for rule in cfg.get("secret_patterns", []):
            if re.search(rule["pattern"], line):
                sev = rule.get("severity", "high")
                add(
                    sev,
                    f"{path}:{line_no} [{rule['id']}] {rule['description']}",
                )

# 4) Admin / infrastructure exposure in git
admin_cfg = "static/admin/config.yml"
if admin_cfg in files:
    add(
        "critical",
        f"{admin_cfg} must not be tracked — use config.yml.example and CI secrets",
    )

infra_pattern = re.compile(r"workers\.dev|\.workers\.dev", re.I)
for path in files:
    if path.endswith(".example") or not should_scan(path):
        continue
    full = ROOT / path
    if not full.is_file():
        continue
    text = full.read_text(encoding="utf-8", errors="replace")
    if infra_pattern.search(text):
        add("high", f"{path} exposes OAuth proxy / Worker URL in repository")

admin = cfg.get("admin_security", {})
admin_path = ROOT / admin.get("config_file", "static/admin/config.yml")
if admin_path.exists() and admin_cfg not in files:
    admin_text = admin_path.read_text(encoding="utf-8")
    for key in admin.get("forbidden_keys", []):
        if key in admin_text:
            add("high", f"{admin_path.relative_to(ROOT)} contains forbidden setting: {key}")

# 5) Warnings
for rule in cfg.get("warn_patterns", []):
    targets = rule.get("files") or files
    for path in targets:
        if path not in files and not (ROOT / path).exists():
            continue
        full = ROOT / path
        if not full.is_file():
            continue
        text = full.read_text(encoding="utf-8", errors="replace")
        if re.search(rule["pattern"], text):
            add(rule.get("severity", "medium"), f"{path} [{rule['id']}] {rule['description']}")

# 6) Untracked sensitive paths (info)
for name in [".env", ".env.local", "secrets.json", "credentials.json"]:
    p = ROOT / name
    if p.exists() and name not in files:
        add("info", f"Local sensitive file exists but is not tracked (good): {name}")

# 7) Git history quick scan (tracked content only, shallow patterns)
try:
    history = subprocess.check_output(
        ["git", "log", "--all", "-p", "--no-color"],
        cwd=ROOT,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    for rule in cfg.get("secret_patterns", []):
        if rule.get("severity") != "critical":
            continue
        if re.search(rule["pattern"], history):
            add(
                "critical",
                f"Git history may contain [{rule['id']}] — rotate credential and purge history",
            )
except subprocess.CalledProcessError:
    add("info", "Git history scan skipped (not a git repo or shallow clone)")

# 8) Workers must not contain literal secrets
worker = ROOT / "workers/decap-oauth-worker.js"
if worker.exists():
    wtext = worker.read_text(encoding="utf-8", errors="replace")
    if re.search(r"GITHUB_CLIENT_SECRET\s*=\s*['\"][^'\"]+['\"]", wtext):
        add("critical", "workers/decap-oauth-worker.js contains hardcoded GITHUB_CLIENT_SECRET")

# Report
lines = [
    "SDOM Security Report",
    f"Project: {cfg.get('project', ROOT.name)}",
    f"Config generated_at: {cfg.get('generated_at', 'unknown')}",
    "",
]
for title, items in [
    ("CRITICAL", critical),
    ("HIGH", high),
    ("MEDIUM", medium),
    ("INFO", info),
]:
    lines.append(f"## {title} ({len(items)})")
    if items:
        lines.extend(f"- {m}" for m in items)
    else:
        lines.append("- none")
    lines.append("")

report = "\n".join(lines)
REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(report, encoding="utf-8")
print(report)
print(f"Report saved: {REPORT.relative_to(ROOT)}")

if critical or high:
    sys.exit(1)
sys.exit(0)
PY
