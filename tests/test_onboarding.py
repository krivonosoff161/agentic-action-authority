"""Synthetic trust-bootstrap checks for the public-document host setup."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority.engine import AuthorityError
from ash_action_authority.host import setup


def _public_key(seed: int) -> bytes:
    signer = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class HostOnboardingPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "new-task"
        self.public = self.root / "operator.hex"
        self.public_bytes = _public_key(17)
        self.public.write_text(self.public_bytes.hex() + "\n", encoding="ascii")
        self.fingerprint = hashlib.sha256(self.public_bytes).hexdigest()
        self.source = self.root / "source.txt"
        self.document = self.root / "proposal.txt"
        self.source.write_bytes(b"Declared synthetic public source.\n")
        self.document.write_bytes(b"Proposed synthetic public document.\n")

    def _setup(self, home: Path | None = None, **changes: object) -> dict:
        options: dict[str, object] = {
            "expected_key_fingerprint": self.fingerprint,
            "host_repository": "example/document-host",
            "host_revision": "a" * 40,
            "allow_local_source_use": True,
        }
        options.update(changes)
        return setup(home or self.home, self.public, self.source, self.document, **options)

    def _assert_no_effect(self, home: Path) -> None:
        self.assertFalse(home.exists())
        self.assertFalse((home / "output" / "document.md").exists())

    def test_valid_trusted_declaration_binds_profile_and_request(self) -> None:
        result = self._setup()
        self.assertEqual(result["state"], "PENDING_APPROVAL")
        self.assertFalse(result["effect_created"])
        config = json.loads((self.home / "host.json").read_text(encoding="ascii"))
        self.assertEqual(config["profile"]["repository_id"], "example/document-host")
        self.assertEqual(config["profile"]["project_id"], "document-host")
        request = json.loads((self.home / "request.json").read_text(encoding="ascii"))
        self.assertEqual(request["binding"]["operator_key_fingerprint"], self.fingerprint)
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_expected_fingerprint_and_host_repository_are_required_keywords(self) -> None:
        for missing in ("expected_key_fingerprint", "host_repository"):
            with self.subTest(missing=missing):
                home = self.root / f"missing-{missing}"
                options = {
                    "expected_key_fingerprint": self.fingerprint,
                    "host_repository": "example/document-host",
                    "host_revision": "a" * 40,
                    "allow_local_source_use": True,
                }
                del options[missing]
                with self.assertRaises(TypeError):
                    setup(home, self.public, self.source, self.document, **options)
                self._assert_no_effect(home)

    def test_malformed_expected_fingerprint_refuses_before_home_creation(self) -> None:
        bad_values = ("", "0" * 63, "g" * 64, "0x" + "0" * 64, "  " + self.fingerprint)
        for index, value in enumerate(bad_values):
            with self.subTest(value=value):
                home = self.root / f"malformed-fingerprint-{index}"
                with self.assertRaisesRegex(AuthorityError, "invalid_expected_key_fingerprint"):
                    self._setup(home, expected_key_fingerprint=value)
                self._assert_no_effect(home)

    def test_uppercase_and_non_string_fingerprints_refuse_before_home_creation(self) -> None:
        self.assertNotEqual(self.fingerprint.upper(), self.fingerprint)
        bad_values = (self.fingerprint.upper(), None, 7, self.fingerprint.encode("ascii"))
        for index, value in enumerate(bad_values):
            with self.subTest(value=type(value).__name__):
                home = self.root / f"wrong-type-fingerprint-{index}"
                with self.assertRaisesRegex(AuthorityError, "invalid_expected_key_fingerprint"):
                    self._setup(home, expected_key_fingerprint=value)
                self._assert_no_effect(home)

    def test_substituted_public_key_refuses_before_home_creation(self) -> None:
        substituted = _public_key(34)
        self.assertNotEqual(substituted, self.public_bytes)
        self.public.write_text(substituted.hex() + "\n", encoding="ascii")
        with self.assertRaisesRegex(AuthorityError, "operator_key_mismatch"):
            self._setup()
        self._assert_no_effect(self.home)

    def test_invalid_host_repository_refuses_before_home_creation(self) -> None:
        for index, repository in enumerate(("", "document-host", "owner//repo", "https://example/repo", None)):
            with self.subTest(repository=repository):
                home = self.root / f"invalid-repository-{index}"
                with self.assertRaisesRegex(AuthorityError, "invalid_host_provenance"):
                    self._setup(home, host_repository=repository)
                self._assert_no_effect(home)

    def test_invalid_host_revision_refuses_before_home_creation(self) -> None:
        for index, revision in enumerate(("", "not-a-commit", "a" * 39, None)):
            with self.subTest(revision=revision):
                home = self.root / f"invalid-revision-{index}"
                with self.assertRaisesRegex(AuthorityError, "invalid_host_provenance"):
                    self._setup(home, host_revision=revision)
                self._assert_no_effect(home)

    def test_local_source_use_still_requires_explicit_host_decision(self) -> None:
        with self.assertRaisesRegex(
            AuthorityError, "host_must_authorize_local_public_source_use"
        ):
            self._setup(allow_local_source_use=False)
        self._assert_no_effect(self.home)


if __name__ == "__main__":
    unittest.main()
