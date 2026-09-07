"""Review, evidence inspection and publication; no command implicitly calls a model."""

import argparse
import json
import os
import sqlite3

from timeline_demo.ai import Harness, load_policy, prepare
from timeline_demo.ai_export import export_audit, inspect_chunk, verify_audit_export
from timeline_demo.core.storage import no_links
from timeline_demo.parsers.readers import _strict_json


def read_json(path):
    with no_links(path).open("rb") as stream:
        raw = stream.read(2 * 1024**2 + 1)
    if len(raw) > 2 * 1024**2:
        raise ValueError("AI input file exceeds 2 MiB")
    return _strict_json(raw)


def review_template(workspace):
    result = workspace["result"]
    if result is None:
        raise ValueError("no candidate available for review")
    return {
        "decision": "request_changes",
        "reason": "",
        "result_sha256": result["result_sha256"],
        "acknowledge_coverage": False,
        "claims": {
            c["claim_id"]: {
                "verdict": "needs_more_evidence",
                "rationale": "",
                "evidence_chunk_ids": sorted({w["chunk_id"] for w in c["witnesses"]}),
            }
            for c in result["verification"]["claims"]
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evidence-bound AI actions and human review")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "review-template", "review", "show", "chunk", "export", "request", "import"):
        command = commands.add_parser(name)
        command.add_argument("bundle")
        command.add_argument("--ledger", required=True)
        command.add_argument("--output")
        if name not in {"request", "import"}:
            command.add_argument("--action", required=True)
        if name in {"review", "show"}:
            command.add_argument("--review-policy", required=True)
            command.add_argument("--review-policy-sha256", required=True)
        if name in {"request", "import"}:
            command.add_argument("--task", choices=["summarize", "correlate", "review"], default="summarize")
            command.add_argument("--policy")
        if name in {"review", "import"}:
            command.add_argument("--input", required=True)
        if name == "chunk":
            command.add_argument("--chunk-id", required=True)
            command.add_argument("--offset", type=int, default=0)
            command.add_argument("--limit", type=int, default=100)
    command = commands.add_parser("verify-export")
    command.add_argument("directory")
    command.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-export":
            result = verify_audit_export(args.directory, args.manifest_sha256)
        else:
            if args.output and (
                no_links(args.output).exists()
                or no_links(args.output).is_relative_to(no_links(args.bundle))
                or no_links(args.output) == no_links(args.ledger)
            ):
                raise ValueError("AI output must be new and outside evidence and ledger")
            harness = Harness(args.ledger, policy=load_policy(getattr(args, "policy", None)))
            if args.command in {"inspect", "review-template"}:
                result = harness.inspect(args.bundle, args.action)
                if args.command == "review-template":
                    result = review_template(result)
            elif args.command == "review":
                result = harness.review(
                    args.bundle,
                    args.action,
                    read_json(args.input),
                    review_policy=args.review_policy,
                    review_policy_sha256=args.review_policy_sha256,
                )
            elif args.command == "show":
                result = harness.approved(
                    args.bundle,
                    args.action,
                    review_policy=args.review_policy,
                    review_policy_sha256=args.review_policy_sha256,
                )
            elif args.command == "chunk":
                result = inspect_chunk(
                    harness, args.bundle, args.action, args.chunk_id, offset=args.offset, limit=args.limit
                )
            elif args.command == "export":
                if not args.output:
                    raise ValueError("audit export requires --output")
                result = export_audit(harness, args.bundle, args.action, args.output)
            elif args.command == "request":
                result = harness.run(args.bundle, args.task)
                result["request"] = prepare(args.bundle, args.task, harness.policy)["request"]
            else:
                result = harness.import_external(args.bundle, read_json(args.input), args.task)
            if args.output and args.command != "export":
                target = no_links(args.output)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(result, stream, indent=2)
                    stream.write("\n")
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        # Neither source contents nor provider exception strings belong in terminal diagnostics.
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "AI action, evidence, review or storage validation failed; inspect the protected ledger.",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
