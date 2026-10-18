"""One persisted public-document host example; host CLI is NOT an agent tool.

The public key supplied at setup is a trust-enrollment decision by the host.
Do not take --public-key, source declarations or config from an agent message.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import importlib.util
import json
import re
import secrets
import sqlite3
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

if importlib.util.find_spec("agentic_security_harness") is None:
    raise SystemExit("The host CLI requires agentic-action-authority[harness].")

from agentic_security_harness.ancestry_store import AncestryError, AncestryStore, Checkpoint
from agentic_security_harness.companion_contracts import (
    CoverageExpectationProfileV1,
    TelemetryManifestV1,
    build_coverage_expectation_profile_v1,
)
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope
from agentic_security_harness.workspace_admission import (
    WorkspaceAdmission,
    WorkspaceAdmissionError,
    WorkspaceSource,
    WorkspaceSources,
)
from agentic_security_harness.workspace_capture import capture_workspace_sources
from agentic_security_harness.workspace_operation import WorkspaceOperationError
from agentic_security_harness.workspace_writer import WorkspacePolicy
from pydantic import ValidationError

from .engine import ActionGate, AuthorityBusy, AuthorityError, _directory
from .operator import OperatorError, _create_once, _read_bounded, _reject_constant, _unique_json
from .protocol import ProtocolError, canonical


def _json_file(path, limit=131072):
    return json.loads(
        _read_bounded(path, limit).decode("utf-8"),
        object_pairs_hook=_unique_json,
        parse_constant=_reject_constant,
    )


def _write_json(path, value):
    _create_once(
        path,
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii"),
    )


def setup(
    home: Path,
    public_key_path: Path,
    source_path: Path,
    document_path: Path,
    *,
    expected_key_fingerprint: str,
    host_repository: str,
    host_revision: str,
    valid_seconds: int = 3600,
    allow_local_source_use: bool = False,
):
    """Capture PUBLIC input after trusted enrollment and host provenance declarations.

    The fingerprint must come from an independent trusted operator channel, not
    be calculated from the received public-key file to make this check pass.
    Repository/revision is a host declaration, not remote provenance attestation.
    """
    home = home.absolute()
    _directory(home.parent)
    if home.exists() or home.is_symlink():
        raise AuthorityError("home_exists_use_new_directory")
    if type(valid_seconds) is not int or not 60 <= valid_seconds <= 86400:
        raise AuthorityError("valid_seconds_out_of_range")
    if allow_local_source_use is not True:
        raise AuthorityError("host_must_authorize_local_public_source_use")
    if type(expected_key_fingerprint) is not str or not re.fullmatch(
        r"[0-9a-f]{64}", expected_key_fingerprint
    ):
        raise AuthorityError("invalid_expected_key_fingerprint")
    source = _read_bounded(source_path, 65536)
    document = _read_bounded(document_path, 65536)
    if not source or not document:
        raise AuthorityError("empty_document_or_source")
    document.decode("utf-8")
    source.decode("utf-8")
    try:
        public_key = bytes.fromhex(_read_bounded(public_key_path, 128).decode("ascii").strip())
    except (ValueError, UnicodeError) as exc:
        raise AuthorityError("invalid_public_key") from exc
    if len(public_key) != 32:
        raise AuthorityError("invalid_public_key")
    if not hmac.compare_digest(hashlib.sha256(public_key).hexdigest(), expected_key_fingerprint):
        raise AuthorityError("operator_key_mismatch")
    now = int(time.time())
    origin = datetime.fromtimestamp(now, UTC)
    restrictions = DocumentSourceRestrictions.bind(
        source,
        DataEnvelope(
            # Harness 1.14.1's document admission has a closed local-model recipient.
            # This is a compatibility declaration for the explicitly authorized local
            # document workflow, not a network grant and not a model invocation.
            data_class="public",
            allowed_recipients=["local-model"],
            allowed_purpose=["document-generation"],
            can_store=True,
            can_forward=True,
            ttl_seconds=valid_seconds,
            requires_confirmation=False,
            classification_source="host",
            classification_mutable=False,
        ),
        created_at=origin,
    )
    sources = WorkspaceSources.bind(
        (WorkspaceSource("input", "declared-source", source, restrictions),)
    )
    operation_id = secrets.token_hex(32)
    # Bind the actual host declaration, not an invented Harness repository identity.
    # Structural validation cannot prove that a commit belongs to that repository.
    try:
        profile = build_coverage_expectation_profile_v1(
            project_id="document-host",
            repository_id=host_repository,
            repository_sha=host_revision,
            expected_channels=("input",),
            expected_event_count=1,
            expectation_source_sha256=hashlib.sha256(
                b"one host-declared captured public input"
            ).hexdigest(),
        )
    except (ValidationError, ValueError, TypeError) as exc:
        raise AuthorityError("invalid_host_provenance") from exc
    home.mkdir(mode=0o700)
    output = home / "output"
    output.mkdir()
    _create_once(home / "source.txt", source)
    _create_once(home / "document.txt", document)
    policy = sources.bind_policy(
        WorkspacePolicy(output, (("report", "document.md"),), data_class="public", max_proposals=1)
    )
    capture = capture_workspace_sources(
        home / "history.sqlite",
        home / "history.witness",
        sources=sources,
        policy=policy,
        expected_profile=profile,
        logical_operation_id=operation_id,
        context="local-public-document",
    )
    admission = capture.admission
    config = {
        "schema": "ash-action-host-v1",
        "operation_id": operation_id,
        "public_key_hex": public_key.hex(),
        "expires_at": now + valid_seconds,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "document_sha256": hashlib.sha256(document).hexdigest(),
        "restrictions": restrictions.record(),
        "profile": profile.model_dump(mode="json"),
        "checkpoint": asdict(admission.expected_checkpoint),
        "manifest": admission.manifest.model_dump(mode="json"),
        "manifest_sha256": admission.expected_manifest_sha256,
    }
    _write_json(home / "host.json", config)
    gate = _restore(home, create=True)
    _write_json(home / "request.json", gate.request())
    return {
        "state": "PENDING_APPROVAL",
        "request": str(home / "request.json"),
        "document": str(home / "document.txt"),
        "effect_created": False,
    }


def _restore(home: Path, *, create=False):
    home = home.absolute()
    _directory(home)
    config = _json_file(home / "host.json")
    if (
        type(config) is not dict
        or set(config)
        != {
            "schema",
            "operation_id",
            "public_key_hex",
            "expires_at",
            "source_sha256",
            "document_sha256",
            "restrictions",
            "profile",
            "checkpoint",
            "manifest",
            "manifest_sha256",
        }
        or config["schema"] != "ash-action-host-v1"
    ):
        raise AuthorityError("invalid_host_configuration")
    source = _read_bounded(home / "source.txt", 65536)
    document = _read_bounded(home / "document.txt", 65536)
    if (
        hashlib.sha256(source).hexdigest() != config["source_sha256"]
        or hashlib.sha256(document).hexdigest() != config["document_sha256"]
    ):
        raise AuthorityError("retained_input_changed")
    try:
        restrictions = DocumentSourceRestrictions.from_record(config["restrictions"])
    except (ValueError, TypeError, KeyError) as exc:
        raise AuthorityError("invalid_host_configuration") from exc
    sources = WorkspaceSources.bind(
        (WorkspaceSource("input", "declared-source", source, restrictions),)
    )
    policy = sources.bind_policy(
        WorkspacePolicy(
            home / "output", (("report", "document.md"),), data_class="public", max_proposals=1
        )
    )
    try:
        checkpoint = Checkpoint(**config["checkpoint"])
        profile = CoverageExpectationProfileV1.model_validate(config["profile"])
        manifest = TelemetryManifestV1.model_validate(config["manifest"])
        public_key = bytes.fromhex(config["public_key_hex"])
    except (ValueError, TypeError, KeyError) as exc:
        raise AuthorityError("invalid_host_configuration") from exc
    # Reconstruct the ORIGINAL host-bound context without treating current
    # source eligibility as a prerequisite for READBACK. authorize/deliver still
    # call admission.verify before any new effect. A corrupted store then blocks
    # execution; it must not turn a retained file receipt into a replay request.
    store = AncestryStore(
        home / "history.sqlite",
        home / "history.witness",
        checkpoint.context,
        checkpoint.root_digest,
    )
    admission = WorkspaceAdmission(
        sources,
        store,
        checkpoint,
        profile,
        config["operation_id"],
        policy.sha256,
        config["manifest_sha256"],
        "sealed",
        manifest,
    )
    if create:
        admission.verify(operation_id=config["operation_id"], policy=policy)
    method = ActionGate.create if create else ActionGate.open
    return method(
        home / "authority",
        policy,
        content=document.decode("utf-8"),
        operation_id=config["operation_id"],
        artifact="report",
        public_key=public_key,
        key_id="enrolled-operator",
        app_id="public-document-host",
        task_id="reviewed-document-publication",
        initiator="document-proposer",
        expires_at=config["expires_at"],
        dependencies={"declared-source": config["source_sha256"]},
        admission=admission,
    )


def apply(home, decision_path):
    detached = _json_file(decision_path, 32768)
    if type(detached) is not dict or set(detached) != {"message", "signature_base64"}:
        raise AuthorityError("invalid_detached_decision")
    try:
        signature = base64.b64decode(detached["signature_base64"], validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise AuthorityError("invalid_detached_decision") from exc
    gate = _restore(home)
    try:
        return gate.apply_decision(detached["message"], signature)
    except ProtocolError as exc:
        # The protocol deliberately groups expired and future-issued decisions.
        # Give an expired HOST request a useful route without asserting that the
        # supplied decision was authentic. No failed decision is acknowledged.
        if str(exc) == "decision_time_invalid" and int(time.time()) >= gate.request()["expires_at"]:
            raise AuthorityError("approval_expired") from exc
        raise


_PREFLIGHT_STEPS = {
    "approval_expired": "Preserve the old task and decision. Prepare a new task and obtain a fresh operator review; do not extend the old approval or replay it.",
    "operator_key_mismatch": "Stop enrollment. Verify the key and fingerprint with the operator through an independent trusted channel; do not replace the expected fingerprint just to proceed.",
    "invalid_expected_key_fingerprint": "Supply the operator's separately verified lowercase SHA-256 public-key fingerprint.",
    "invalid_public_key": "Obtain the operator's public key through the agreed trusted channel; never supply a private key.",
    "invalid_host_provenance": "Supply your trusted host application's owner/repository and exact Git revision together; these are declarations, not automatic provenance proof.",
    "host_must_authorize_local_public_source_use": "The host must explicitly authorize use of this public source before setup.",
    "valid_seconds_out_of_range": "Choose an approval lifetime between 60 and 86400 seconds before setup.",
    "empty_document_or_source": "Supply nonempty public UTF-8 source and proposed document files.",
    "retained_input_changed": "Stop using this task. Inspect the retained source/document and state; do not edit them to force a retry. A changed action needs a new task and new review.",
    "invalid_host_configuration": "Stop and inspect retained host configuration. Do not recreate or overwrite the task to force execution.",
}

_REFUSAL_STEPS = {
    "not_approved": "Obtain and apply an operator decision for the current request before submitting the unchanged document.",
    "object_changed": "Submit only the exact reviewed document. A different document needs a new task and new operator review.",
    "invalid_content": "Supply UTF-8 text within the declared bound, with no path or approval fields.",
    "expired": "Preserve this task. Prepare a new task with a new lifetime and obtain a new operator decision; do not renew or replay the old approval.",
    "already_consumed": "Run status --recover to inspect the existing attempt; do not submit it again.",
    "capacity": "Stop submitting to this task and inspect status --recover; a new action requires a new task and review.",
}


def _cli_error(command: str, reason: str, *, uncertain: bool = False) -> int:
    """Emit only fixed vocabulary, never an exception message or supplied bytes."""
    if reason in _PREFLIGHT_STEPS:
        next_step = _PREFLIGHT_STEPS[reason]
    elif reason == "busy_no_decision_acknowledged":
        next_step = (
            "No decision was acknowledged; inspect status after the active operation finishes."
        )
    elif uncertain:
        next_step = (
            "Run status --recover for this home; inspect the result; do not replay the action."
        )
    elif reason == "home_exists_use_new_directory":
        next_step = "Inspect the existing home and choose a new empty directory for setup."
    elif command == "setup":
        next_step = (
            "Check the public input paths, host repository/revision, and local-source "
            "authorization; use a new empty home."
        )
    elif command == "apply-decision":
        next_step = (
            "Check the detached decision and enrolled key; request a fresh "
            "operator review if needed."
        )
    elif command == "run":
        next_step = (
            "Inspect status --recover before deciding whether a new setup "
            "is needed; do not replay blindly."
        )
    else:
        next_step = (
            "Inspect the home and requested output path; use status --recover "
            "for an attempted action."
        )
    print(
        json.dumps(
            {"ok": False, "reason": reason, "next_step": next_step},
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 2 if uncertain else 1


def _cli_result(command: str, result: dict) -> int:
    """Preserve library results but make refusal/uncertainty visible to shell callers."""
    if command == "run":
        if result.get("status") == "UNKNOWN":
            result = {
                **result,
                "next_step": (
                    "Run status --recover for this home; inspect the result; "
                    "do not replay the action."
                ),
            }
            code = 2
        elif result.get("applied") is False:
            result = {
                **result,
                "next_step": _REFUSAL_STEPS.get(result.get("reason"), (
                    "Inspect status --recover before deciding whether a new setup "
                    "is needed; do not replay blindly."
                )),
            }
            code = 1
        else:
            code = 0
    elif command == "apply-decision" and result.get("accepted") is False:
        result = {
            **result,
            "next_step": (
                "Inspect status --recover; a late or in-flight decision cannot be applied again."
            ),
        }
        code = 1
    elif command == "status" and result.get("state", result.get("status")) == "UNKNOWN":
        result = {
            **result,
            "next_step": (
                "Inspect the output and retained state; do not replay or claim a verified effect."
            ),
        }
        code = 2
    else:
        code = 0
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m ash_action_authority.host")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser(
        "setup", help="PUBLIC documents only; host enrolls the supplied public key"
    )
    init.add_argument("--home", type=Path, required=True)
    init.add_argument("--public-key", type=Path, required=True)
    init.add_argument("--expected-key-fingerprint", required=True,
                      help="operator fingerprint received independently through a trusted channel")
    init.add_argument("--source", type=Path, required=True)
    init.add_argument("--document", type=Path, required=True)
    init.add_argument("--host-repository", required=True, help="trusted host application's owner/repository")
    init.add_argument("--host-revision", required=True, help="exact revision of that host repository; host-declared, not attested")
    init.add_argument("--valid-seconds", type=int, default=3600)
    init.add_argument(
        "--allow-local-source-use",
        action="store_true",
        help=(
            "host authorizes reuse of this public source inside the local "
            "workflow; no network grant"
        ),
    )
    for command in ("apply-decision", "run", "status", "request"):
        item = sub.add_parser(command)
        item.add_argument("--home", type=Path, required=True)
        if command == "apply-decision":
            item.add_argument("--decision", type=Path, required=True)
        elif command == "status":
            item.add_argument("--recover", action="store_true")
        elif command == "request":
            item.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "setup":
            result = setup(
                args.home,
                args.public_key,
                args.source,
                args.document,
                expected_key_fingerprint=args.expected_key_fingerprint,
                host_repository=args.host_repository,
                host_revision=args.host_revision,
                valid_seconds=args.valid_seconds,
                allow_local_source_use=args.allow_local_source_use,
            )
        elif args.command == "apply-decision":
            result = apply(args.home, args.decision)
        else:
            gate = _restore(args.home)
            if args.command == "run":
                result = gate.submit(gate.content)
            elif args.command == "status":
                result = gate.recover() if args.recover else gate.status()
            else:
                _create_once(args.out, canonical(gate.request()))
                result = {"request_created": str(args.out)}
    except AuthorityBusy:
        return _cli_error(args.command, "busy_no_decision_acknowledged", uncertain=True)
    except (sqlite3.Error, OSError):
        # A failed durable write may happen after the file effect. No no-effect claim.
        return _cli_error(args.command, "effect_outcome_unknown", uncertain=True)
    except (
        AuthorityError,
        OperatorError,
        ProtocolError,
        WorkspaceAdmissionError,
        WorkspaceOperationError,
        AncestryError,
        ValidationError,
        json.JSONDecodeError,
        UnicodeError,
        binascii.Error,
    ) as exc:
        if isinstance(exc, AuthorityError) and str(exc) == "home_exists_use_new_directory":
            reason = "home_exists_use_new_directory"
        elif isinstance(exc, AuthorityError) and str(exc) in _PREFLIGHT_STEPS:
            reason = str(exc)
        elif isinstance(exc, ProtocolError) and str(exc) == "decision_expired":
            reason = "approval_expired"
        elif args.command == "apply-decision":
            reason = "decision_invalid_or_unverified"
        else:
            reason = "input_or_state_refused"
        return _cli_error(args.command, reason)
    return _cli_result(args.command, result)


if __name__ == "__main__":
    raise SystemExit(main())
