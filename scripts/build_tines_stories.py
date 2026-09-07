"""Rebuild importable Tines exports. Deployments supply their own resources and credentials."""

import json
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def guid(value):
    return uuid.uuid5(uuid.NAMESPACE_URL, "timeline/tines/" + value).hex


def action(name, kind, options):
    return {
        "name": name,
        "type": "Agents::" + kind + "Agent",
        "guid": guid(name),
        "disabled": True,
        "options": options,
        "description": "Configure tenant resources and enable after acceptance testing.",
        "monitoring": {
            "monitor_failures": True,
            "monitor_all_events": False,
            "monitor_no_events_emitted": None,
        },
    }


def rule(path, value, kind="regex"):
    return {"path": "<<" + path + ">>", "value": value, "type": kind}


def trigger(name, rules):
    return action(name, "Trigger", {"rules": rules, "must_match": len(rules)})


def message(name, payload):
    return action(name, "EventTransformation", {"mode": "message_only", "payload": payload})


def http(name, path, method="get", payload=None):
    options = {
        "url": "<<RESOURCE.databricks_host>>" + path,
        "method": method,
        "content_type": "json",
        "headers": {"Authorization": "Bearer <<CREDENTIAL.databricks_token>>"},
        "log_error_on_status": ["400-599"],
    }
    if payload is not None:
        options["payload"] = payload
    return action(name, "HTTPRequest", options)


def export(name, agents, links, exits):
    positions = {agent["guid"]: [150 + (i % 3) * 350, (i // 3) * 160] for i, agent in enumerate(agents)}
    return {
        "schema_version": 18,
        "standard_lib_version": 41,
        "action_runtime_version": 6,
        "name": name,
        "description": "AI incident timeline integration. Disabled until tenant credentials, paths and runbooks are configured. No containment or AI action is executed.",
        "guid": guid(name),
        "agents": agents,
        "links": [{"source": a, "receiver": b} for a, b in links],
        "diagram_notes": [],
        "diagram_layout": json.dumps(positions),
        "keep_events_for": 86400,
        "send_to_story_enabled": False,
        "synchronous_webhooks_enabled": False,
        "entry_agent_guid": agents[0]["guid"],
        "exit_agent_guids": [agents[i]["guid"] for i in exits],
        "tags": [],
        "resources": [],
        "credentials": [],
    }


def build():
    webhook = action(
        "Receive bundle",
        "Webhook",
        {
            "path": "timeline-bundle",
            "secret": "REPLACE_WITH_RANDOM_SECRET",
            "verbs": "post",
            "include_headers": True,
            "response_code": 202,
            "response": {"status": "received", "completion": "asynchronous"},
        },
    )
    agents = [
        webhook,
        trigger(
            "Validate contract",
            [
                rule("receive_bundle.body.contract_version", "^1\\.0$"),
                rule(
                    "receive_bundle.body.bundle_path",
                    r"^/Volumes/[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*/[A-Za-z0-9_./-]+$",
                ),
                rule("receive_bundle.body.manifest_sha256", "^[a-f0-9]{64}$"),
                rule("receive_bundle.body.idempotency_key", "^[a-f0-9]{64}$"),
            ],
        ),
        http(
            "Submit job",
            "/api/2.2/jobs/run-now",
            "post",
            {
                "job_id": "=RESOURCE.timeline_job_id",
                "idempotency_token": "<<receive_bundle.body.idempotency_key>>",
                "job_parameters": {
                    "bundle_path": "<<receive_bundle.body.bundle_path>>",
                    "manifest_sha256": "<<receive_bundle.body.manifest_sha256>>",
                },
            },
        ),
        trigger(
            "Submission accepted",
            [rule("submit_job.status", "^200$"), rule("submit_job.body.run_id", "^[0-9]+$")],
        ),
        message(
            "Initialize poll",
            {"run_id": "=submit_job.body.run_id", "polls": 0, "bundle": "=receive_bundle.body"},
        ),
        message("Poll context", "=DEFAULT(next_poll, initialize_poll)"),
        http("Get run", "/api/2.2/jobs/runs/get?run_id=<<poll_context.run_id>>"),
        trigger(
            "Run succeeded",
            [
                rule("get_run.status", "^200$"),
                rule("get_run.body.state.life_cycle_state", "^TERMINATED$"),
                rule("get_run.body.state.result_state", "^SUCCESS$"),
            ],
        ),
        message(
            "Review required",
            {
                "status": "published",
                "human_review_required": True,
                "run_id": "=poll_context.run_id",
                "bundle": "=poll_context.bundle",
                "run_url": "=get_run.body.run_page_url",
            },
        ),
        trigger(
            "Run pending",
            [
                rule("get_run.status", "^200$"),
                rule(
                    "get_run.body.state.life_cycle_state",
                    "^(PENDING|RUNNING|QUEUED|BLOCKED|WAITING_FOR_RETRY|TERMINATING)$",
                ),
                rule("poll_context.polls", "60", "field<value"),
            ],
        ),
        message(
            "Next poll",
            {
                "run_id": "=poll_context.run_id",
                "polls": "=poll_context.polls + 1",
                "bundle": "=poll_context.bundle",
            },
        ),
        action("Wait thirty seconds", "EventTransformation", {"mode": "delay", "seconds": 30}),
        trigger(
            "Run failed",
            [
                rule(
                    "get_run.body.state.result_state",
                    "^(FAILED|TIMEDOUT|CANCELED|MAXIMUM_CONCURRENT_RUNS_REACHED|UPSTREAM_FAILED|EXCLUDED|SUCCESS_WITH_FAILURES)$",
                )
            ],
        ),
        message(
            "Failure receipt",
            {
                "status": "failed",
                "run_id": "=poll_context.run_id",
                "state": "=get_run.body.state",
                "bundle": "=poll_context.bundle",
            },
        ),
        trigger(
            "Polling exhausted",
            [
                rule("poll_context.polls", "60", "field>=value"),
                rule(
                    "get_run.body.state.life_cycle_state",
                    "^(PENDING|RUNNING|QUEUED|BLOCKED|WAITING_FOR_RETRY|TERMINATING)$",
                ),
            ],
        ),
        message(
            "Timeout receipt",
            {
                "status": "poll_timeout",
                "run_id": "=poll_context.run_id",
                "bundle": "=poll_context.bundle",
                "instruction": "Inspect the existing Databricks run; do not submit a new job.",
            },
        ),
        trigger("Submission error", [rule("submit_job.status", "^[45][0-9]{2}$")]),
        message(
            "Submission failure",
            {
                "status": "submission_failed",
                "http_status": "=submit_job.status",
                "bundle": "=receive_bundle.body",
            },
        ),
        trigger("Polling error", [rule("get_run.status", "^[45][0-9]{2}$")]),
        message(
            "Polling failure",
            {
                "status": "poll_http_error",
                "run_id": "=poll_context.run_id",
                "http_status": "=get_run.status",
                "bundle": "=poll_context.bundle",
            },
        ),
        trigger(
            "Run internal error", [rule("get_run.body.state.life_cycle_state", "^(INTERNAL_ERROR|SKIPPED)$")]
        ),
    ]
    links = [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 8),
        (6, 9),
        (9, 10),
        (10, 11),
        (11, 5),
        (6, 12),
        (12, 13),
        (6, 14),
        (14, 15),
        (2, 16),
        (16, 17),
        (6, 18),
        (18, 19),
        (6, 20),
        (20, 13),
    ]
    monitor = export("Timeline - Publish and monitor Databricks", agents, links, [8, 13, 15, 17, 19])
    # Independent single-shot status story is useful after a timeout or an interrupted story run.
    agents2 = [
        action(
            "Receive run",
            "Webhook",
            {
                "path": "timeline-run-status",
                "secret": "REPLACE_WITH_RANDOM_SECRET",
                "verbs": "post",
                "include_headers": True,
            },
        ),
        trigger("Validate run", [rule("receive_run.body.run_id", "^[0-9]+$")]),
        http("Read existing run", "/api/2.2/jobs/runs/get?run_id=<<receive_run.body.run_id>>"),
        message(
            "Run status receipt",
            {
                "run_id": "=receive_run.body.run_id",
                "http_status": "=read_existing_run.status",
                "state": "=read_existing_run.body.state",
                "run_url": "=read_existing_run.body.run_page_url",
                "human_review_required": True,
            },
        ),
    ]
    status = export("Timeline - Inspect existing run", agents2, [(0, 1), (1, 2), (2, 3)], [3])
    for filename, story in [("publish_and_monitor.json", monitor), ("inspect_run.json", status)]:
        (ROOT / "integrations/tines/stories" / filename).write_text(json.dumps(story, indent=2) + "\n")


if __name__ == "__main__":
    build()
