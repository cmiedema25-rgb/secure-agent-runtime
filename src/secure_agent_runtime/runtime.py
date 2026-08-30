"""Secure orchestration loop with policy gates around every trust boundary."""

from __future__ import annotations

import json

from .audit import HashChainAuditLog
from .models import (
    AgentPlan,
    Decision,
    Finding,
    JsonValue,
    Message,
    RuntimeRequest,
    RuntimeResponse,
    ToolExecution,
)
from .policy import PolicyEngine
from .prompts import SYSTEM_PROMPT, SYSTEM_PROMPT_VERSION, prompt_fingerprint
from .providers.base import AgentProvider
from .tools import ToolError, ToolRegistry


class SecureAgentRuntime:
    def __init__(
        self,
        *,
        provider: AgentProvider,
        policy: PolicyEngine,
        tools: ToolRegistry,
        audit: HashChainAuditLog,
    ) -> None:
        self.provider = provider
        self.policy = policy
        self.tools = tools
        self.audit = audit

    def run(self, request: RuntimeRequest) -> RuntimeResponse:
        self.audit.append(
            event="request.received",
            request_id=request.request_id,
            details={
                "message_count": len(request.messages),
                "prompt_version": SYSTEM_PROMPT_VERSION,
                "prompt_fingerprint": prompt_fingerprint(),
            },
            sensitive_payload=[message.to_dict() for message in request.messages],
        )

        input_result = self.policy.evaluate_input(request.messages)
        self._audit_policy("input.policy", request.request_id, input_result.to_dict())
        if input_result.decision is not Decision.ALLOW:
            return self._stopped_response(
                request,
                input_result.decision,
                input_result.score,
                input_result.reasons,
                input_result.findings,
            )

        conversation = (
            Message(role="system", content=SYSTEM_PROMPT),
            *request.messages,
        )
        executions: list[ToolExecution] = []
        peak_risk = input_result.score

        for round_number in range(1, self.policy.config.max_tool_rounds + 1):
            try:
                plan = self.provider.complete(conversation, self.tools.schemas())
            except Exception as exc:  # Provider implementations are an external boundary.
                self.audit.append(
                    event="provider.error",
                    request_id=request.request_id,
                    details={"error_type": type(exc).__name__, "round": round_number},
                )
                decision = Decision.BLOCK if self.policy.config.fail_closed else Decision.REVIEW
                return RuntimeResponse(
                    request_id=request.request_id,
                    decision=decision,
                    content="Provider failure stopped execution safely.",
                    risk_score=(
                        100 if decision is Decision.BLOCK else self.policy.config.review_score
                    ),
                    reasons=("provider operation failed",),
                    tool_executions=tuple(executions),
                )

            limit_result = self._check_plan_limits(plan)
            if limit_result is not None:
                self.audit.append(
                    event="plan.blocked",
                    request_id=request.request_id,
                    details={"reason": limit_result},
                )
                return RuntimeResponse(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    content="Agent plan exceeded the configured capability limit.",
                    risk_score=100,
                    reasons=(limit_result,),
                    tool_executions=tuple(executions),
                )

            if plan.content:
                output_result = self.policy.evaluate_output(plan.content)
                peak_risk = max(peak_risk, output_result.score)
                self._audit_policy(
                    "output.policy",
                    request.request_id,
                    output_result.to_dict(),
                )
                if output_result.decision is not Decision.ALLOW:
                    return RuntimeResponse(
                        request_id=request.request_id,
                        decision=Decision.BLOCK,
                        content="Model output was withheld by policy.",
                        risk_score=peak_risk,
                        reasons=output_result.reasons,
                        findings=output_result.findings,
                        tool_executions=tuple(executions),
                    )

            if not plan.tool_calls:
                content = plan.content or "The provider returned no content."
                self.audit.append(
                    event="request.completed",
                    request_id=request.request_id,
                    details={
                        "decision": Decision.ALLOW.value,
                        "tool_executions": len(executions),
                        "rounds": round_number,
                    },
                    sensitive_payload=content,
                )
                return RuntimeResponse(
                    request_id=request.request_id,
                    decision=Decision.ALLOW,
                    content=content,
                    risk_score=peak_risk,
                    tool_executions=tuple(executions),
                )

            conversation = (
                *conversation,
                Message(
                    role="assistant",
                    content=plan.content,
                    tool_calls=plan.tool_calls,
                ),
            )
            for call in plan.tool_calls:
                tool_result = self.policy.evaluate_tool_call(call)
                peak_risk = max(peak_risk, tool_result.score)
                self.audit.append(
                    event="tool.policy",
                    request_id=request.request_id,
                    details={
                        "tool": call.name,
                        "call_id": call.id,
                        "decision": tool_result.decision.value,
                        "score": tool_result.score,
                        "reasons": list(tool_result.reasons),
                    },
                    sensitive_payload=call.arguments,
                )
                if tool_result.decision is not Decision.ALLOW:
                    executions.append(
                        ToolExecution(
                            call=call,
                            decision=tool_result.decision,
                            error="execution stopped by policy",
                        )
                    )
                    return RuntimeResponse(
                        request_id=request.request_id,
                        decision=tool_result.decision,
                        content="A proposed tool call was stopped by policy.",
                        risk_score=peak_risk,
                        reasons=tool_result.reasons,
                        findings=tool_result.findings,
                        tool_executions=tuple(executions),
                    )

                try:
                    output = self.tools.execute(call)
                except ToolError as exc:
                    executions.append(
                        ToolExecution(
                            call=call,
                            decision=Decision.BLOCK,
                            error=str(exc),
                        )
                    )
                    self.audit.append(
                        event="tool.error",
                        request_id=request.request_id,
                        details={
                            "tool": call.name,
                            "call_id": call.id,
                            "error": str(exc),
                        },
                    )
                    return RuntimeResponse(
                        request_id=request.request_id,
                        decision=Decision.BLOCK,
                        content="Tool execution failed safely.",
                        risk_score=max(peak_risk, 80),
                        reasons=("tool rejected invalid or unsafe arguments",),
                        tool_executions=tuple(executions),
                    )
                except Exception as exc:
                    executions.append(
                        ToolExecution(
                            call=call,
                            decision=Decision.BLOCK,
                            error="unexpected tool failure",
                        )
                    )
                    self.audit.append(
                        event="tool.error",
                        request_id=request.request_id,
                        details={
                            "tool": call.name,
                            "call_id": call.id,
                            "error_type": type(exc).__name__,
                        },
                    )
                    return RuntimeResponse(
                        request_id=request.request_id,
                        decision=Decision.BLOCK,
                        content="Tool execution failed safely.",
                        risk_score=max(peak_risk, 100),
                        reasons=("unexpected tool failure",),
                        tool_executions=tuple(executions),
                    )

                tool_message = Message(
                    role="tool",
                    name=call.name,
                    tool_call_id=call.id,
                    content=json.dumps(output, ensure_ascii=False, sort_keys=True),
                )
                tool_output_result = self.policy.evaluate_input((tool_message,))
                peak_risk = max(peak_risk, tool_output_result.score)
                self.audit.append(
                    event="tool.completed",
                    request_id=request.request_id,
                    details={
                        "tool": call.name,
                        "call_id": call.id,
                        "output_decision": tool_output_result.decision.value,
                    },
                    sensitive_payload=output,
                )
                executions.append(ToolExecution(call=call, decision=Decision.ALLOW, output=output))
                if tool_output_result.decision is not Decision.ALLOW:
                    return RuntimeResponse(
                        request_id=request.request_id,
                        decision=tool_output_result.decision,
                        content="Untrusted tool output was stopped before model re-entry.",
                        risk_score=peak_risk,
                        reasons=("tool output violated input policy",),
                        findings=tool_output_result.findings,
                        tool_executions=tuple(executions),
                    )
                conversation = (*conversation, tool_message)

        self.audit.append(
            event="request.limit_reached",
            request_id=request.request_id,
            details={"max_tool_rounds": self.policy.config.max_tool_rounds},
        )
        return RuntimeResponse(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            content="Maximum tool rounds reached; execution stopped.",
            risk_score=max(peak_risk, 80),
            reasons=("tool-round limit reached",),
            tool_executions=tuple(executions),
        )

    def _check_plan_limits(self, plan: AgentPlan) -> str | None:
        if len(plan.tool_calls) > self.policy.config.max_tool_calls_per_round:
            return (
                "tool call count exceeds per-round limit of "
                f"{self.policy.config.max_tool_calls_per_round}"
            )
        call_ids = [call.id for call in plan.tool_calls]
        if len(set(call_ids)) != len(call_ids):
            return "provider returned duplicate tool call identifiers"
        return None

    def _audit_policy(
        self,
        event: str,
        request_id: str,
        result: dict[str, JsonValue],
    ) -> None:
        raw_findings = result.get("findings", [])
        findings = raw_findings if isinstance(raw_findings, list) else []
        categories: list[JsonValue] = [
            str(item.get("category")) for item in findings if isinstance(item, dict)
        ]
        self.audit.append(
            event=event,
            request_id=request_id,
            details={
                "decision": result.get("decision"),
                "score": result.get("score"),
                "reasons": result.get("reasons"),
                "categories": categories,
            },
        )

    def _stopped_response(
        self,
        request: RuntimeRequest,
        decision: Decision,
        score: int,
        reasons: tuple[str, ...],
        findings: tuple[Finding, ...],
    ) -> RuntimeResponse:
        self.audit.append(
            event="request.stopped",
            request_id=request.request_id,
            details={
                "decision": decision.value,
                "score": score,
                "reasons": list(reasons),
            },
        )
        content = (
            "Request blocked by security policy."
            if decision is Decision.BLOCK
            else "Request requires human security review."
        )
        return RuntimeResponse(
            request_id=request.request_id,
            decision=decision,
            content=content,
            risk_score=score,
            reasons=reasons,
            findings=findings,
        )
