"""Streamlit AI panels. Plain text/JSON only; no model HTML or executable actions."""

import sqlite3

from timeline_demo.ai import Harness
from timeline_demo.ai_audit import audit_records, check_call, load_review_policy, local_principal
from timeline_demo.ai_cli import review_template
from timeline_demo.parsers.readers import _strict_json
from timeline_demo.viewer import ai_settings, ai_review_access


def list_actions(harness, bundle):
    from timeline_demo.core.manifest import verify_bundle

    manifest = verify_bundle(bundle)
    harness._outside_bundle(bundle)
    if not harness.path.is_file():
        return []
    harness._initialize()
    actions = []
    with harness._db() as db:
        db.execute("BEGIN")
        for row in db.execute("SELECT * FROM calls WHERE case_id=? ORDER BY key", (manifest["case_id"],)):
            identity = _strict_json(row["request"])
            if identity.get("bundle_id") != manifest["bundle_id"]:
                continue
            check_call(db, row)
            history = audit_records(db, row["key"])
            decisions = [
                e["payload"]["decision"]["decision"] for e in history if e["event"] == "human_review"
            ]
            actions.append(
                {
                    "action_id": row["key"],
                    "task": identity["task"],
                    "status": decisions[-1]
                    if decisions
                    else "awaiting_review"
                    if row["status"] == "completed"
                    else row["status"],
                }
            )
    return actions


def display_ai(st, bundle, manifest, *, mode, viewer_policy=None, claims=None):
    st.subheader("AI evidence and human review")
    try:
        if mode == "oidc":
            settings = ai_settings(viewer_policy, claims, manifest["case_id"])
            if not settings:
                st.caption("AI review is not configured for this case.")
                return
            principal, can_review = ai_review_access(settings, claims, manifest["case_id"])
        else:
            ledger = st.sidebar.text_input("AI ledger path")
            policy_path = st.sidebar.text_input("Human-review policy path")
            policy_pin = st.sidebar.text_input("Human-review policy SHA-256")
            if not all((ledger, policy_path, policy_pin)):
                st.caption(
                    "Configure the AI ledger and pinned review policy to inspect or publish an analysis."
                )
                return
            settings = {"ledger": ledger, "review_policy": policy_path, "review_policy_sha256": policy_pin}
            policy = load_review_policy(policy_path, policy_pin)
            principal = local_principal()
            can_review = any(
                r["principal"] == principal and manifest["case_id"] in r["cases"] for r in policy["reviewers"]
            )
        harness = Harness(settings["ledger"])
        actions = list_actions(harness, bundle)
        if not actions:
            st.caption("No AI actions are recorded for this bundle.")
            return
        selected = st.selectbox(
            "AI action",
            range(len(actions)),
            format_func=lambda i: (
                f"{actions[i]['task']} · {actions[i]['status']} · {actions[i]['action_id'][:12]}"
            ),
        )
        action = actions[selected]["action_id"]
        options = {k: settings[k] for k in ("review_policy", "review_policy_sha256")}
        try:
            accepted = harness.approved(bundle, action, **options)
        except (ValueError, PermissionError):
            st.info("Accepted summary unavailable: evidence checks and current human approval are required.")
        else:
            st.success("Evidence fields checked; a human reviewer approved this version.")
            st.text(accepted["analysis"]["summary"])
            st.json(accepted["analysis"])
            with st.expander("Evidence and approval receipt"):
                st.json({k: accepted[k] for k in ("receipt", "verification", "human_review", "audit_head")})
        if not can_review or not st.checkbox("Open the human-review workspace", key="review-" + action):
            return
        draft = harness.inspect(bundle, action)
        result = draft["result"]
        st.warning(
            "Unapproved candidate. Hypotheses, alternatives and proposed steps require your assessment against the original records."
        )
        if result is None:
            st.error("This action has no reviewable candidate. Inspect its protected audit export.")
            return
        st.json(result["verification"])
        st.json(result["candidate"])
        st.json(draft["chunks"])
        st.caption(
            "Use the source provenance panel and timeline-ai chunk to inspect every supporting record. Chunk aliases resolve to full IDs above."
        )
        from timeline_demo.ai_export import inspect_chunk

        choices = [c["chunk_id"] for c in draft["chunks"].values()]
        if choices:
            chunk_id = st.selectbox("Inspect evidence chunk", choices)
            offset = st.number_input("Evidence record offset", min_value=0, value=0, step=100)
            st.json(inspect_chunk(harness, bundle, action, chunk_id, offset=int(offset), limit=100))
        decision = review_template(draft)
        with st.form("human-decision-" + action):
            decision["decision"] = st.selectbox("Decision", ["request_changes", "reject", "approve"])
            decision["reason"] = st.text_area("Reason and coverage assessment")
            decision["acknowledge_coverage"] = st.checkbox(
                "I reviewed coverage, omitted groups and quarantine."
            )
            for claim in result["verification"]["claims"]:
                claim_id = claim["claim_id"]
                st.text(claim_id + ": " + claim["kind"])
                checked = st.checkbox(
                    "I checked these cited records and all associated prose.", key=action + claim_id + "check"
                )
                rationale = st.text_area("Evidence assessment", key=action + claim_id + "rationale")
                judgment = decision["claims"][claim_id]
                judgment["rationale"] = rationale
                if checked:
                    judgment["verdict"] = (
                        "supported" if claim["kind"] == "observation" else "plausible_hypothesis"
                    )
            submitted = st.form_submit_button("Record human decision")
        if submitted:
            harness.review(bundle, action, decision, principal=principal, **options)
            st.success("Human decision recorded. Refresh the action to view its current publication status.")
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        st.error("AI evidence, audit or review validation failed. Contact the deployment administrator.")
