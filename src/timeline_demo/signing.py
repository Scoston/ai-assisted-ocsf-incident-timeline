"""Detached Ed25519 manifest attestations with independently pinned signer policy.

No timestamp is asserted. A signature authenticates bytes under a configured key,
not the source system, collection completeness, clock accuracy or signer identity.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from timeline_demo.core.manifest import DIGEST, safe_member, verify_bundle
from timeline_demo.parsers.common import compact_json
from timeline_demo.parsers.readers import _strict_json

DOMAIN = b"timeline-manifest-signature-v1\x00"
KINDS = {"bundle", "ocsf-export"}
STATUSES = {"active", "verify_only", "revoked"}


def _read(path, limit=1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("signature/key/policy file must be a regular file without a symlink")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("signature/key/policy file exceeds its size limit")
    return value


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _atomic_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(temporary, path)  # Exclusive creation; never replace a key or trust policy.
        if os.name == "posix":
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        temporary.unlink()


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def _decode(value, size):
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError("invalid signature/key base64 encoding") from None
    if len(result) != size or _b64(result) != value:
        raise ValueError("invalid signature/key encoding or length")
    return result


def password_from_env(name):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,100}", name):
        raise ValueError("invalid passphrase environment variable name")
    value = os.environ.get(name, "").encode("utf-8")
    if not 16 <= len(value) <= 1023:
        raise ValueError("signing passphrase environment variable requires 16..1023 UTF-8 bytes")
    return value


def generate_keypair(output, password):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not isinstance(password, bytes) or not 16 <= len(password) <= 1023:
        raise ValueError("an encryption passphrase of 16..1023 bytes is required")
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("key directory already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    key_id = _sha(public.public_bytes_raw())
    with tempfile.TemporaryDirectory(prefix=".timeline-key-", dir=output.parent) as temporary:
        stage = Path(temporary) / "key"
        stage.mkdir(mode=0o700)
        _atomic_new(
            stage / "private.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password),
            ),
        )
        _atomic_new(
            stage / "public.pem",
            public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        )
        _atomic_new(
            stage / "key.json", (compact_json({"algorithm": "Ed25519", "key_id": key_id}) + "\n").encode()
        )
        # output is reserved by mkdir, then filled with exclusive links. A crash may leave
        # a partial key directory; preserve it and use a new output path for recovery.
        output.mkdir(mode=0o700)
        for file in stage.iterdir():
            _atomic_new(output / file.name, file.read_bytes())
    return {
        "key_id": key_id,
        "private_key": str(output / "private.pem"),
        "public_key": str(output / "public.pem"),
    }


def public_entry(path, allowed_kinds=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = serialization.load_pem_public_key(_read(path, 16384))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only Ed25519 public keys are supported")
    raw = key.public_bytes_raw()
    kinds = sorted(KINDS if allowed_kinds is None else set(allowed_kinds))
    if not kinds or not set(kinds) <= KINDS:
        raise ValueError("invalid permitted artifact kinds")
    return _sha(raw), {"public_key": _b64(raw), "status": "active", "allowed_kinds": kinds}


def load_trust(path, expected_sha256):
    if not isinstance(expected_sha256, str) or not DIGEST.fullmatch(expected_sha256):
        raise ValueError("an independently recorded trust-store SHA-256 is required")
    data = _read(path)
    if _sha(data) != expected_sha256:
        raise ValueError("trust store does not match its independent pin")
    value = _strict_json(data)
    if not isinstance(value, dict) or set(value) != {"version", "keys"} or value["version"] != "1.0":
        raise ValueError("unsupported signer trust policy")
    if not isinstance(value["keys"], dict) or not 1 <= len(value["keys"]) <= 100:
        raise ValueError("signer policy requires 1..100 keys")
    for key_id, entry in value["keys"].items():
        if (
            not DIGEST.fullmatch(key_id)
            or not isinstance(entry, dict)
            or set(entry) != {"public_key", "status", "allowed_kinds"}
        ):
            raise ValueError("invalid signer policy entry")
        if (
            _sha(_decode(entry["public_key"], 32)) != key_id
            or not isinstance(entry["status"], str)
            or entry["status"] not in STATUSES
        ):
            raise ValueError("signer fingerprint or status is invalid")
        kinds = entry["allowed_kinds"]
        if (
            not isinstance(kinds, list)
            or any(not isinstance(k, str) for k in kinds)
            or not kinds
            or not set(kinds) <= KINDS
            or len(set(kinds)) != len(kinds)
        ):
            raise ValueError("invalid signer artifact scope")
    return value


def write_trust(output, policy):
    data = (compact_json(policy) + "\n").encode()
    # Validate the generated policy before returning a usable pin.
    with tempfile.TemporaryDirectory() as directory:
        trial = Path(directory) / "policy.json"
        trial.write_bytes(data)
        load_trust(trial, _sha(data))
    _atomic_new(output, data)
    return {
        "trust_store": str(Path(output).absolute()),
        "trust_store_sha256": _sha(data),
        "keys": {k: v["status"] for k, v in policy["keys"].items()},
    }


def _artifact(directory, kind, expected_manifest_sha256=None, source_bundle=None):
    if kind not in KINDS:
        raise ValueError("unsupported signed artifact kind")
    root = Path(directory).resolve()
    name = "audit_manifest.json" if kind == "bundle" else "export_manifest.json"
    pin = _sha(_read(safe_member(root, name), 4 * 1024 * 1024))
    if expected_manifest_sha256 is not None and pin != expected_manifest_sha256:
        raise ValueError("manifest does not match the independent pin")
    if kind == "bundle":
        manifest = verify_bundle(root, pin)
        artifact_id = manifest["bundle_id"]
    else:
        from timeline_demo.ocsf import verify_export

        manifest = verify_export(root, manifest_sha256=pin, bundle=source_bundle)
        artifact_id = pin
    return manifest, artifact_id, pin


def _outside(directory, *paths):
    root = Path(directory).resolve()
    for path in paths:
        if Path(path).resolve().is_relative_to(root):
            raise ValueError("keys, signatures and signer trust must remain outside the artifact directory")


def _authorization(policy, key_id, kind, signing=False):
    entry = policy["keys"].get(key_id)
    if entry is None or entry["status"] == "revoked":
        raise ValueError("signer is unknown or revoked")
    if kind not in entry["allowed_kinds"]:
        raise ValueError("signer is not authorized for this artifact kind")
    if signing and entry["status"] != "active":
        raise ValueError("signing requires an active key; verify_only keys cannot sign")
    return entry


def sign_artifact(
    directory,
    private_key,
    password,
    output,
    trust_store,
    trust_store_sha256,
    *,
    kind="bundle",
    source_bundle=None,
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _outside(directory, private_key, output, trust_store)
    if not password:
        raise ValueError("an encrypted private key and passphrase are required")
    policy = load_trust(trust_store, trust_store_sha256)
    try:
        key = serialization.load_pem_private_key(_read(private_key, 16384), password=password)
    except (ValueError, TypeError):
        raise ValueError("private key could not be decrypted") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("only Ed25519 private keys are supported")
    key_id = _sha(key.public_key().public_bytes_raw())
    _authorization(policy, key_id, kind, signing=True)
    _, artifact_id, pin = _artifact(directory, kind, source_bundle=source_bundle)
    payload = {
        "signature_version": "1.0",
        "algorithm": "Ed25519",
        "kind": kind,
        "artifact_id": artifact_id,
        "manifest_sha256": pin,
        "key_id": key_id,
    }
    signature = {**payload, "signature": _b64(key.sign(DOMAIN + compact_json(payload).encode()))}
    _atomic_new(output, (compact_json(signature) + "\n").encode())
    return {
        "status": "signed",
        "signature": str(Path(output).absolute()),
        "key_id": key_id,
        "manifest_sha256": pin,
        "artifact_id": artifact_id,
        "kind": kind,
    }


def verify_signature(
    directory,
    signature,
    trust_store,
    trust_store_sha256,
    *,
    kind="bundle",
    expected_manifest_sha256=None,
    source_bundle=None,
):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _outside(directory, signature, trust_store)
    policy = load_trust(trust_store, trust_store_sha256)
    data = _read(signature, 8192)
    value = _strict_json(data)
    fields = {
        "signature_version",
        "algorithm",
        "kind",
        "artifact_id",
        "manifest_sha256",
        "key_id",
        "signature",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["signature_version"] != "1.0"
        or value["algorithm"] != "Ed25519"
        or value["kind"] != kind
    ):
        raise ValueError("unsupported or mismatched manifest signature")
    if any(
        not isinstance(value[k], str) or not DIGEST.fullmatch(value[k])
        for k in ("artifact_id", "manifest_sha256", "key_id")
    ):
        raise ValueError("invalid signature identity or digest")
    entry = _authorization(policy, value["key_id"], kind)
    payload = {k: v for k, v in value.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_decode(entry["public_key"], 32)).verify(
            _decode(value["signature"], 64), DOMAIN + compact_json(payload).encode()
        )
    except InvalidSignature:
        raise ValueError("manifest signature is invalid") from None
    _, artifact_id, pin = _artifact(directory, kind, expected_manifest_sha256, source_bundle)
    if value["artifact_id"] != artifact_id or value["manifest_sha256"] != pin:
        raise ValueError("signature belongs to a different artifact manifest")
    return {
        "status": "trusted_signature_verified",
        "kind": kind,
        "artifact_id": artifact_id,
        "manifest_sha256": pin,
        "key_id": value["key_id"],
        "key_status": entry["status"],
        "trust_store_sha256": trust_store_sha256,
        "signature_sha256": _sha(data),
        "trusted_timestamp": False,
        "source_authenticity_proven": False,
    }


def enforce_signature(
    directory,
    *,
    signature=None,
    trust_store=None,
    trust_store_sha256=None,
    require_signature=False,
    **options,
):
    if not require_signature and not any((signature, trust_store, trust_store_sha256)):
        return None
    if not all((signature, trust_store, trust_store_sha256)):
        raise ValueError("signature, trust store and independent trust-store SHA-256 are required")
    return verify_signature(directory, signature, trust_store, trust_store_sha256, **options)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create detached signatures and versioned signer trust policies"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen")
    keygen.add_argument("--output", required=True)
    keygen.add_argument("--passphrase-env", required=True)
    for name in ("trust-init", "trust-add", "trust-status"):
        command = commands.add_parser(name)
        command.add_argument("--output", required=True)
        if name != "trust-status":
            command.add_argument("--public-key", action="append", required=True)
            command.add_argument("--allow-kind", action="append", choices=sorted(KINDS))
        if name != "trust-init":
            command.add_argument("--trust-store", required=True)
            command.add_argument("--trust-store-sha256", required=True)
        if name == "trust-status":
            command.add_argument("--key-id", required=True)
            command.add_argument("--status", required=True, choices=sorted(STATUSES))
    sign = commands.add_parser("sign")
    sign.add_argument("directory")
    sign.add_argument("--kind", choices=sorted(KINDS), default="bundle")
    sign.add_argument("--source-bundle")
    for option in ("private-key", "passphrase-env", "output", "trust-store", "trust-store-sha256"):
        sign.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            result = generate_keypair(args.output, password_from_env(args.passphrase_env))
        elif args.command == "sign":
            result = sign_artifact(
                args.directory,
                args.private_key,
                password_from_env(args.passphrase_env),
                args.output,
                args.trust_store,
                args.trust_store_sha256,
                kind=args.kind,
                source_bundle=args.source_bundle,
            )
        else:
            policy = (
                {"version": "1.0", "keys": {}}
                if args.command == "trust-init"
                else load_trust(args.trust_store, args.trust_store_sha256)
            )
            if args.command == "trust-status":
                if args.key_id not in policy["keys"]:
                    raise ValueError("unknown key ID")
                if policy["keys"][args.key_id]["status"] == "revoked" and args.status != "revoked":
                    raise ValueError("revoked keys cannot be reactivated; generate a new key")
                policy["keys"][args.key_id]["status"] = args.status
            else:
                for path in args.public_key:
                    key_id, entry = public_entry(path, args.allow_kind)
                    if key_id in policy["keys"]:
                        raise ValueError("signer key is already present")
                    policy["keys"][key_id] = entry
            result = write_trust(args.output, policy)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, ImportError) as exc:
        parser.exit(2, f"timeline-sign: {exc}\n")


if __name__ == "__main__":
    main()
