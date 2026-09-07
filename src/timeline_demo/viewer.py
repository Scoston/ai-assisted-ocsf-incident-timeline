"""Shared-viewer authorization, independent of the OIDC transport."""

import hashlib
import logging
import time
from pathlib import Path

from timeline_demo.core.manifest import DIGEST, verify_bundle
from timeline_demo.core.storage import no_links
from timeline_demo.parsers.common import compact_json
from timeline_demo.parsers.readers import _strict_json
from timeline_demo.signing import enforce_signature


def load_access_policy(path, expected_sha256):
    path = no_links(path)
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if (
        not isinstance(expected_sha256, str)
        or not DIGEST.fullmatch(expected_sha256)
        or len(raw) > 1024 * 1024
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError("viewer policy does not match the deployed SHA-256")
    policy = _strict_json(raw)
    if (
        not isinstance(policy, dict)
        or set(policy) != {"version", "principals", "cases", "trust_store", "trust_store_sha256"}
        or policy["version"] != "1.0"
        or not isinstance(policy["cases"], dict)
        or not isinstance(policy["principals"], list)
    ):
        raise ValueError("invalid viewer access policy")
    if not isinstance(policy["trust_store_sha256"], str) or not DIGEST.fullmatch(
        policy["trust_store_sha256"]
    ):
        raise ValueError("pinned signer trust is required")
    if not isinstance(policy["trust_store"], str) or not Path(policy["trust_store"]).is_absolute():
        raise ValueError("absolute signer trust path is required")
    identities = set()
    for principal in policy["principals"]:
        if (
            not isinstance(principal, dict)
            or set(principal) != {"issuer", "subject", "cases"}
            or any(not isinstance(principal[k], str) or not principal[k] for k in ("issuer", "subject"))
            or not isinstance(principal["cases"], list)
            or any(not isinstance(k, str) or k not in policy["cases"] for k in principal["cases"])
        ):
            raise ValueError("invalid viewer principal")
        identity = (principal["issuer"], principal["subject"])
        if identity in identities:
            raise ValueError("duplicate viewer principal")
        identities.add(identity)
    for case, entry in policy["cases"].items():
        if (
            not case
            or not isinstance(entry, dict)
            or set(entry)
            not in (
                {"bundle", "manifest_sha256", "signature"},
                {"bundle", "manifest_sha256", "signature", "ai"},
            )
            or any(
                not isinstance(entry[k], str) or not Path(entry[k]).is_absolute()
                for k in ("bundle", "signature")
            )
            or not isinstance(entry["manifest_sha256"], str)
            or not DIGEST.fullmatch(entry["manifest_sha256"])
        ):
            raise ValueError("invalid viewer case")
        if "ai" in entry:
            ai = entry["ai"]
            if (
                not isinstance(ai, dict)
                or set(ai) != {"ledger", "review_policy", "review_policy_sha256"}
                or any(
                    not isinstance(ai[k], str) or not Path(ai[k]).is_absolute()
                    for k in ("ledger", "review_policy")
                )
                or not isinstance(ai["review_policy_sha256"], str)
                or not DIGEST.fullmatch(ai["review_policy_sha256"])
            ):
                raise ValueError("invalid viewer AI configuration")
    return policy


def authorized_cases(policy, claims, *, now=None):
    now = time.time() if now is None else now
    # Streamlit validates OIDC tokens. Authorization uses immutable issuer + subject,
    # never an email domain, display name, forwarded header or query parameter.
    if type(claims.get("exp")) not in (int, float) or not now < claims["exp"] < float("inf"):
        raise PermissionError("a current OIDC identity is required")
    for principal in policy["principals"]:
        if principal["issuer"] == claims.get("iss") and principal["subject"] == claims.get("sub"):
            return sorted(principal["cases"])
    raise PermissionError("identity is not authorized")


def open_case(policy, claims, case):
    if case not in authorized_cases(policy, claims):
        raise PermissionError("case access denied")
    entry = policy["cases"][case]
    attestation = enforce_signature(
        entry["bundle"],
        signature=entry["signature"],
        trust_store=policy["trust_store"],
        trust_store_sha256=policy["trust_store_sha256"],
        require_signature=True,
        expected_manifest_sha256=entry["manifest_sha256"],
    )
    manifest = verify_bundle(entry["bundle"], entry["manifest_sha256"])
    if manifest["case_id"] != case:
        raise ValueError("viewer case mapping does not match evidence")
    return Path(entry["bundle"]), manifest, attestation


def audit_access(claims, outcome, bundle_id=None):
    subject = hashlib.sha256(compact_json([claims.get("iss"), claims.get("sub")]).encode()).hexdigest()
    logging.getLogger("timeline.viewer.audit").warning(
        compact_json(
            {
                "event": "viewer_access",
                "subject_hash": subject,
                "outcome": outcome,
                "bundle_id": bundle_id,
                "time_unix": int(time.time()),
            }
        )
    )


def ai_settings(policy, claims, case):
    """AI storage paths come only from the pinned viewer deployment policy."""
    if case not in authorized_cases(policy, claims):
        raise PermissionError("AI case access denied")
    return policy["cases"][case].get("ai")


def oidc_principal(claims):
    return "oidc:" + hashlib.sha256(compact_json([claims["iss"], claims["sub"]]).encode()).hexdigest()


def ai_review_access(settings, claims, case):
    from timeline_demo.ai_audit import load_review_policy

    policy = load_review_policy(settings["review_policy"], settings["review_policy_sha256"])
    principal = oidc_principal(claims)
    return principal, any(r["principal"] == principal and case in r["cases"] for r in policy["reviewers"])
