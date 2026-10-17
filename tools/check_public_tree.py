"""Bounded public-tree and workflow hygiene; not a replacement for Gitleaks."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, capture_output=True,
    )
    names = sorted(set(result.stdout.decode("utf-8").split("\0")) - {""})
    failures = []
    forbidden_names = {"SESSION.md", "TASK.md", ".env"}
    forbidden_suffixes = {".pem", ".key", ".sqlite", ".sqlite3", ".db", ".zip", ".whl"}
    patterns = {
        "private_key_material": re.compile(r"(?m)^-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        "github_token_literal": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}"),
        "private_machine_path": re.compile(r"(?i)(?:[CE]:[\\/]+(?:Users[\\/]+krivo|AI[\\/]+research-artifacts))"),
    }
    for name in names:
        path = root / name
        if path.name in forbidden_names or path.suffix in forbidden_suffixes:
            failures.append({"path": name, "reason": "private_or_generated_path"})
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 500_000:
            failures.append({"path": name, "reason": "non_regular_or_oversize"})
            continue
        text = path.read_text(encoding="utf-8")
        for reason, pattern in patterns.items():
            if pattern.search(text):
                failures.append({"path": name, "reason": reason})
        if name.startswith(".github/workflows/"):
            if "pull_request_target" in text:
                failures.append({"path": name, "reason": "unsafe_workflow_event"})
            for action in re.findall(r"(?m)^\s*(?:- )?uses:\s*(\S+)", text):
                if not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action):
                    failures.append({"path": name, "reason": "action_not_sha_pinned"})
            if "persist-credentials: false" not in text:
                failures.append({"path": name, "reason": "checkout_credentials"})
    print(json.dumps({"checked_files": len(names), "failures": failures,
                      "success": not failures, "full_secret_scan": False}))
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
