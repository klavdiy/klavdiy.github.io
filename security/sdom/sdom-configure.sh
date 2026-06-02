#!/usr/bin/env bash
# Regenerates security/sdom/sdom.config.json from repository state.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export ROOT

python3 <<'PY'
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
CONFIG = ROOT / "security/sdom/sdom.config.json"


def load_config():
    if CONFIG.exists():
        with CONFIG.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def git_tracked() -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]


def discover_exclude_paths(files: list[str]) -> list[str]:
    dirs = {
        "public/",
        "resources/_gen/",
        "themes/anatole/node_modules/",
        "themes/anatole/package-lock.json",
    }
    for p in files:
        parts = Path(p).parts
        if len(parts) > 2:
            dirs.add("/".join(parts[:2]) + "/")
    return sorted(dirs)


cfg = load_config()
files = git_tracked()

cfg["schema_version"] = 1
cfg["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
cfg["project"] = ROOT.name
cfg.setdefault("scan", {})
cfg["scan"]["git_tracked_only"] = True
cfg["scan"]["exclude_paths"] = discover_exclude_paths(files)
cfg["scan"]["exclude_extensions"] = sorted(
    set(cfg.get("scan", {}).get("exclude_extensions", []))
    | {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2"}
)
cfg["scan"]["tracked_file_count"] = len(files)

RULES = {
    "forbidden_tracked_files": [
        ".env",
        ".env.local",
        ".env.production",
        "secrets.json",
        "credentials.json",
        "static/admin/config.yml",
        "id_rsa",
        "*.pem",
        "*.p12",
        "*.pfx",
        "*.key",
    ],
    "required_gitignore_entries": [
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "secrets/",
        ".hugo_build.lock",
    ],
    "secret_patterns": [
        {
            "id": "github_pat",
            "severity": "critical",
            "pattern": "ghp_[A-Za-z0-9_]{20,}",
            "description": "GitHub personal access token",
        },
        {
            "id": "github_oauth",
            "severity": "critical",
            "pattern": "gho_[A-Za-z0-9_]{20,}",
            "description": "GitHub OAuth token",
        },
        {
            "id": "github_fine_pat",
            "severity": "critical",
            "pattern": "github_pat_[A-Za-z0-9_]{20,}",
            "description": "GitHub fine-grained PAT",
        },
        {
            "id": "aws_key",
            "severity": "critical",
            "pattern": "AKIA[0-9A-Z]{16}",
            "description": "AWS access key id",
        },
        {
            "id": "private_key_block",
            "severity": "critical",
            "pattern": "BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY",
            "description": "Private key material",
        },
        {
            "id": "client_secret_assignment",
            "severity": "high",
            "pattern": r"(client[_-]?secret|CLIENT_SECRET)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
            "description": "Hardcoded client secret",
        },
    ],
    "allowlist_patterns": [
        {
            "id": "oauth_placeholder",
            "pattern": r"YOUR-OAUTH-WORKER|YOUR_GITHUB_USER",
            "reason": "Example template placeholders only",
        },
        {
            "id": "gitalk_template",
            "pattern": r"clientSecret: '\{\{",
            "reason": "Hugo template placeholder in theme",
        },
    ],
    "warn_patterns": [
        {
            "id": "goldmark_unsafe",
            "severity": "medium",
            "files": ["config/_default/hugo.toml"],
            "pattern": r"unsafe\s*=\s*true",
            "description": "Hugo renders raw HTML from markdown",
        },
    ],
    "admin_security": {
        "config_file": "static/admin/config.yml",
        "example_file": "static/admin/config.yml.example",
        "forbidden_keys": ["local_backend: true"],
    },
}

for key, value in RULES.items():
    cfg[key] = value

CONFIG.parent.mkdir(parents=True, exist_ok=True)
with CONFIG.open("w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")

print(f"sdom-configure: updated {CONFIG.relative_to(ROOT)}")
print(f"  tracked files: {len(files)}")
print(f"  exclude paths: {len(cfg['scan']['exclude_paths'])}")
PY
