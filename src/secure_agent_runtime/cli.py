"""Command-line interface for local operation and verification."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence

from .api import create_server
from .config import PolicyConfig
from .evaluation import load_corpus, run_evaluation, save_report
from .factory import build_runtime
from .models import Message, RuntimeRequest
from .policy import PolicyEngine


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-agent",
        description="Policy-enforced runtime and red-team harness for tool-using AI agents.",
    )
    parser.add_argument("--policy", default="config/policy.toml")
    parser.add_argument("--audit", default="var/audit.jsonl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="classify one untrusted prompt")
    scan.add_argument("text")

    run = subparsers.add_parser("run", help="run one request through the secure agent loop")
    run.add_argument("text")
    run.add_argument(
        "--provider",
        choices=("offline", "openai-compatible"),
        default="offline",
    )

    serve = subparsers.add_parser("serve", help="start the JSON HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument(
        "--provider",
        choices=("offline", "openai-compatible"),
        default="offline",
    )

    evaluate = subparsers.add_parser("evaluate", help="run the red-team regression corpus")
    evaluate.add_argument("--corpus", default="evals/attack_corpus.jsonl")
    evaluate.add_argument("--report")

    subparsers.add_parser("verify-audit", help="verify the HMAC audit chain")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        policy = PolicyEngine(PolicyConfig.load(args.policy))
        policy_result = policy.evaluate_input((Message(role="user", content=args.text),))
        print(json.dumps(policy_result.to_dict(), indent=2, ensure_ascii=False))
        return 2 if policy_result.decision.value == "block" else 0

    if args.command == "evaluate":
        policy = PolicyEngine(PolicyConfig.load(args.policy))
        report = run_evaluation(policy, load_corpus(args.corpus))
        if args.report:
            save_report(report, args.report)
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        metrics = report["metrics"]
        assert isinstance(metrics, dict)
        return 0 if metrics["exact_decision_accuracy"] == 1.0 else 1

    runtime = build_runtime(
        policy_path=args.policy,
        audit_path=args.audit,
        provider_name=getattr(args, "provider", "offline"),
    )
    if args.command == "run":
        request = RuntimeRequest(messages=(Message(role="user", content=args.text),))
        response = runtime.run(request)
        print(json.dumps(response.to_dict(), indent=2, ensure_ascii=False))
        return 2 if response.decision.value == "block" else 0
    if args.command == "verify-audit":
        audit_result = runtime.audit.verify()
        print(json.dumps(audit_result.to_dict(), indent=2))
        return 0 if audit_result.valid else 1
    if args.command == "serve":
        server = create_server(
            runtime,
            host=args.host,
            port=args.port,
            api_token=os.environ.get("RUNTIME_API_TOKEN") or None,
        )
        print(f"secure-agent-runtime listening on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
