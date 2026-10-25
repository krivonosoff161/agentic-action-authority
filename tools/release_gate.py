"""Exact release-subject checks. Public metadata only; no credential handling."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import zipfile
from email.parser import Parser
from pathlib import Path

REPOSITORY = "krivonosoff161/agentic-action-authority"
VERSION = "0.4.0"
TAG = "v" + VERSION
WHEEL = "agentic_action_authority-" + VERSION + "-py3-none-any.whl"
LIMIT = 10_000_000


def require(value, reason):
    if not value:
        raise ValueError(reason)


def validate_run(run, *, sha, workflow, tag_push=False):
    require(run.get("repository", {}).get("full_name") == REPOSITORY, "wrong_repository")
    require(run.get("path") == ".github/workflows/" + workflow, "wrong_workflow")
    require(run.get("head_sha") == sha, "wrong_revision")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "run_not_successful")
    if tag_push:
        require(run.get("event") == "push" and run.get("head_branch") == TAG,
                "not_exact_tag_build")
    else:
        require(run.get("event") == "workflow_dispatch", "wrong_release_event")


def github_run(run_id):
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None, "invalid_run_id")
    return github_api(f"actions/runs/{run_id}")


def github_api(path):
    result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/{path}"],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def check_tag_secret_scan(sha):
    response = github_api(f"actions/workflows/gitleaks.yml/runs?head_sha={sha}&event=push&per_page=100")
    runs = [run for run in response["workflow_runs"] if run.get("head_branch") == TAG]
    require(bool(runs), "tag_secret_scan_missing")
    validate_run(max(runs, key=lambda run: run["id"]), sha=sha,
                 workflow="gitleaks.yml", tag_push=True)


def validate_environment(environment, policies):
    require(environment.get("deployment_branch_policy") == {
        "protected_branches": False, "custom_branch_policies": True,
    }, "release_environment_tag_policy")
    reviewers = [(reviewer.get("type"), reviewer.get("reviewer", {}).get("login"))
                 for rule in environment.get("protection_rules", [])
                 if rule.get("type") == "required_reviewers"
                 for reviewer in rule.get("reviewers", [])]
    require(reviewers == [("User", "krivonosoff161")], "release_owner_reviewer_required")
    require(sorted((item.get("type", ""), item.get("name", ""))
                   for item in policies.get("branch_policies", []))
            == [("tag", "v0.1.0"), ("tag", "v0.1.1"), ("tag", "v0.2.0"),
                ("tag", "v0.3.0"), ("tag", TAG)],
            "release_exact_tag_required")


def wheel_identity(folder):
    wheels = list(folder.glob("*.whl"))
    require(len(wheels) == 1 and wheels[0].name == WHEEL, "wheel_inventory")
    wheel = wheels[0]
    require(wheel.stat().st_size <= LIMIT, "wheel_oversize")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    require((folder / "wheel.sha256").read_text(encoding="ascii").strip() == digest,
            "wheel_digest")
    with zipfile.ZipFile(wheel) as archive:
        name = f"agentic_action_authority-{VERSION}.dist-info/METADATA"
        # Core Metadata is UTF-8. compat32 BytesParser assumes an unspecified
        # payload charset is ASCII and silently replaces non-ASCII README bytes.
        metadata = Parser().parsestr(archive.read(name).decode("utf-8"))
    require(metadata["Name"] == "agentic-action-authority" and metadata["Version"] == VERSION,
            "wheel_metadata")
    return wheel, digest, metadata.get_payload()


def validate_stage(receipt, *, sha, build_run, digest):
    require(receipt == {
        "schema": "action-authority-publication-v1",
        "mode": "publish",
        "target": "testpypi", "tag": TAG, "sha": sha,
        "build_run": build_run, "wheel_sha256": digest,
        "installed_platform_checks": "core-harness-and-agent-framework-windows-and-linux",
    }, "staging_subject_mismatch")


def validate_description(actual, expected):
    require(actual.replace("\r\n", "\n").rstrip()
            == expected.replace("\r\n", "\n").rstrip(), "index_description")


def download_index(folder, target, digest, description):
    host = "test.pypi.org" if target == "testpypi" else "pypi.org"
    with urllib.request.urlopen(
        f"https://{host}/pypi/agentic-action-authority/{VERSION}/json", timeout=30
    ) as response:
        raw = response.read(LIMIT + 1)
    require(len(raw) <= LIMIT, "index_metadata_oversize")
    metadata = json.loads(raw)
    require(metadata["info"]["version"] == VERSION, "index_version")
    validate_description(metadata["info"]["description"], description)
    subjects = [item for item in metadata["urls"] if item["filename"] == WHEEL]
    require(len(subjects) == 1 and not subjects[0]["yanked"], "index_subject")
    item = subjects[0]
    require(item["digests"]["sha256"] == digest, "index_digest")
    expected_host = "test-files.pythonhosted.org" if target == "testpypi" else "files.pythonhosted.org"
    require(item["url"].startswith("https://" + expected_host + "/"), "index_file_origin")
    with urllib.request.urlopen(item["url"], timeout=30) as response:
        require(response.url.startswith("https://" + expected_host + "/"), "download_redirect")
        data = response.read(LIMIT + 1)
    require(len(data) <= LIMIT and hashlib.sha256(data).hexdigest() == digest, "download_digest")
    folder.mkdir(exist_ok=False)
    (folder / WHEEL).write_bytes(data)


class GateTests(unittest.TestCase):
    def fixture_wheel(self, folder, description):
        raw = (f"Metadata-Version: 2.4\nName: agentic-action-authority\n"
               f"Version: {VERSION}\nDescription-Content-Type: text/markdown\n\n").encode()
        path = folder / WHEEL
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(f"agentic_action_authority-{VERSION}.dist-info/METADATA",
                             raw + description)
        (folder / "wheel.sha256").write_text(
            hashlib.sha256(path.read_bytes()).hexdigest(), encoding="ascii")

    def test_utf8_wheel_description_roundtrip(self):
        for description in ("ASCII", "prepare → review/sign → write", "Проверка №1 — 确认"):
            with self.subTest(description=description), tempfile.TemporaryDirectory() as tmp:
                folder = Path(tmp)
                self.fixture_wheel(folder, description.encode("utf-8"))
                self.assertEqual(wheel_identity(folder)[2], description)

    def test_invalid_utf8_metadata_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.fixture_wheel(folder, b"invalid\xff")
            with self.assertRaises(UnicodeDecodeError):
                wheel_identity(folder)

    def test_description_check_retains_exact_unicode(self):
        validate_description("prepare → write\r\n", "prepare → write\n")
        for altered in ("prepare � write", "prepare -> write", "prepare → overwrite"):
            with self.subTest(altered=altered), self.assertRaisesRegex(ValueError, "index_description"):
                validate_description(altered, "prepare → write")

    def sample(self):
        return {"repository": {"full_name": REPOSITORY},
                "path": ".github/workflows/checks.yml", "head_sha": "a" * 40,
                "status": "completed", "conclusion": "success", "event": "push",
                "head_branch": TAG}

    def check(self, run):
        validate_run(run, sha="a" * 40, workflow="checks.yml", tag_push=True)

    def test_exact_success(self):
        self.check(self.sample())

    def test_wrong_origin_and_revision(self):
        for key, value in (("repository", {"full_name": "other/repository"}),
                           ("head_sha", "b" * 40), ("path", ".github/workflows/other.yml")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check({**self.sample(), key: value})

    def test_failed_or_incomplete(self):
        for key, value in (("conclusion", "failure"), ("status", "in_progress")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check({**self.sample(), key: value})

    def test_branch_or_manual_build_cannot_publish(self):
        for key, value in (("head_branch", "main"), ("event", "workflow_dispatch")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check({**self.sample(), key: value})

    def test_staging_is_exact_subject(self):
        receipt = {"schema": "action-authority-publication-v1", "mode": "publish", "target": "testpypi",
                   "tag": TAG, "sha": "a" * 40, "build_run": "1", "wheel_sha256": "b" * 64,
                   "installed_platform_checks": "core-harness-and-agent-framework-windows-and-linux"}
        validate_stage(receipt, sha="a" * 40, build_run="1", digest="b" * 64)
        for key, value in (("target", "pypi"), ("build_run", "2"), ("wheel_sha256", "c" * 64),
                           ("mode", "verify"), ("schema", "action-authority-index-verification-v1"),
                           ("installed_platform_checks", "core-and-harness-windows-and-linux")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_stage({**receipt, key: value}, sha="a" * 40,
                               build_run="1", digest="b" * 64)

    def test_environment_requires_owner_and_exact_tag(self):
        environment = {"deployment_branch_policy": {
            "protected_branches": False, "custom_branch_policies": True,
        }, "protection_rules": [{"type": "required_reviewers", "reviewers": [
            {"type": "User", "reviewer": {"login": "krivonosoff161"}},
        ]}]}
        policies = {"branch_policies": [{"type": "tag", "name": "v0.1.0"},
                                       {"type": "tag", "name": "v0.1.1"},
                                       {"type": "tag", "name": "v0.2.0"},
                                       {"type": "tag", "name": "v0.3.0"},
                                       {"type": "tag", "name": TAG}]}
        validate_environment(environment, policies)
        for altered in ({**environment, "protection_rules": []},
                        {**environment, "deployment_branch_policy": None}):
            with self.assertRaises(ValueError):
                validate_environment(altered, policies)
        for altered in ({"branch_policies": [{"type": "branch", "name": TAG}]},
                        {"branch_policies": [{"type": "tag", "name": "*"}]},
                        {"branch_policies": policies["branch_policies"][:-1]},
                        {"branch_policies": policies["branch_policies"] + [
                            {"type": "tag", "name": "v0.5.0"}]},
                        {"branch_policies": policies["branch_policies"] + [
                            {"type": "branch", "name": TAG}]}):
            with self.assertRaises(ValueError):
                validate_environment(environment, altered)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("self-test", "check-build", "check-stage", "check-policy", "index", "receipt"))
    parser.add_argument("--sha")
    parser.add_argument("--build-run")
    parser.add_argument("--stage-run")
    parser.add_argument("--wheel-dir", type=Path)
    parser.add_argument("--stage-file", type=Path)
    parser.add_argument("--target", choices=("testpypi", "pypi"))
    parser.add_argument("--publication-mode", choices=("publish", "verify"))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.mode == "self-test":
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(GateTests))
        return 0 if result.wasSuccessful() and result.testsRun == 9 else 1
    require(args.sha is not None and re.fullmatch(r"[0-9a-f]{40}", args.sha), "invalid_sha")
    if args.mode == "check-build":
        validate_run(github_run(args.build_run), sha=args.sha, workflow="checks.yml", tag_push=True)
        check_tag_secret_scan(args.sha)
        return 0
    if args.mode == "check-policy":
        require(args.target in ("testpypi", "pypi"), "invalid_target")
        validate_environment(github_api(f"environments/{args.target}"),
                             github_api(f"environments/{args.target}/deployment-branch-policies"))
        return 0
    _, digest, description = wheel_identity(args.wheel_dir)
    if args.mode == "check-stage":
        validate_run(github_run(args.stage_run), sha=args.sha, workflow="release.yml")
        validate_stage(json.loads(args.stage_file.read_text(encoding="ascii")),
                       sha=args.sha, build_run=args.build_run, digest=digest)
    elif args.mode == "index":
        download_index(args.out, args.target, digest, description)
    else:
        # Only called by the final workflow job AFTER all installed index checks.
        require(args.publication_mode in ("publish", "verify"), "missing_publication_mode")
        schema = ("action-authority-publication-v1" if args.publication_mode == "publish"
                  else "action-authority-index-verification-v1")
        record = {"schema": schema, "mode": args.publication_mode, "target": args.target,
                  "tag": TAG, "sha": args.sha, "build_run": args.build_run,
                  "wheel_sha256": digest,
                  "installed_platform_checks": "core-harness-and-agent-framework-windows-and-linux"}
        with args.out.open("x", encoding="ascii") as stream:
            json.dump(record, stream, sort_keys=True, indent=2)
    print(json.dumps({"success": True, "mode": args.mode, "wheel_sha256": digest}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
