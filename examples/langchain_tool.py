"""Money tools for an LLM agent, in the shape LangChain (and most frameworks) expect.

Each tool has a ``name``, a ``description`` for the model, a Pydantic
``args_schema`` and an ``invoke(args)`` method returning text, like LangChain's
``BaseTool``. Wrap them with your framework, for example::

    from langchain_core.tools import StructuredTool

    tools = [
        StructuredTool.from_function(
            func=lambda **kw: t.invoke(kw),
            name=t.name,
            description=t.description,
            args_schema=t.args_schema,
        )
        for t in money_tools(agent)
    ]

Agents get money tools only: nothing here can loosen a limit or move funds to
the owner. Limits are enforced by the co-signer and on-chain, not by the prompt,
so a prompt-injected model still cannot overspend.

    uv run python examples/langchain_tool.py
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agentbank import AgentBank, AgentBankError, SessionKey, x402_receipt


class NoArgs(BaseModel):
    """No arguments."""


class PayArgs(BaseModel):
    """Arguments of the ``pay`` tool."""

    to: str = Field(description="0x address or Agent Bank agent id (agt_...)")
    amount: str = Field(description='USDC amount as a decimal string, e.g. "2.50"')
    memo: str = Field(default="", description="What the payment is for")


class CheckSpendArgs(BaseModel):
    """Arguments of the ``check_spend`` tool."""

    to: str = Field(description="0x address or Agent Bank agent id (agt_...)")
    amount: str = Field(description='USDC amount as a decimal string, e.g. "2.50"')


class FetchArgs(BaseModel):
    """Arguments of the ``fetch_paid_resource`` tool."""

    url: str = Field(description="HTTPS URL of an x402 (pay-per-call) resource")


@dataclass(frozen=True)
class Tool:
    """A LangChain-style tool: name, description, argument schema and ``invoke``."""

    name: str
    description: str
    args_schema: type[BaseModel]
    func: Callable[[Any], str]

    def invoke(self, args: dict[str, Any]) -> str:
        """Validate arguments, run the tool, and return text for the model.

        Agent Bank errors (policy denials, limits, frozen agents) are returned as
        text so the model can explain them instead of crashing the agent loop.
        """
        try:
            return self.func(self.args_schema.model_validate(args))
        except AgentBankError as err:
            return f"error {err.code}: {err.detail}"


def money_tools(agent: AgentBank, *, max_x402_amount: str = "0.25") -> list[Tool]:
    """Build the money tools for an agent-authenticated client."""

    def get_balance(_: NoArgs) -> str:
        b = agent.accounts.balances()
        return (
            f"available {b.available} {b.asset}, reserved {b.reserved}, x402 float {b.spend_float}"
        )

    def check_spend(args: CheckSpendArgs) -> str:
        target = {"to_agent_id": args.to} if args.to.startswith("agt_") else {"to_address": args.to}
        decision = agent.policies.check(intent={"amount": args.amount, **target})
        rules = ", ".join(f"{h.rule}={h.effect}" for h in decision.rule_hits) or "none"
        return f"{decision.outcome} (rules: {rules})"

    def pay(args: PayArgs) -> str:
        payment = agent.pay(to=args.to, amount=args.amount, memo=args.memo or None)
        return f"payment {payment.id} is {payment.status}"

    def fetch_paid_resource(args: FetchArgs) -> str:
        response = agent.x402.fetch(args.url, max_amount=max_x402_amount)
        receipt = x402_receipt(response)
        paid = f" (paid via {receipt.payment.id})" if receipt else ""
        return f"HTTP {response.status_code}{paid}: {response.text[:2000]}"

    def list_transactions(_: NoArgs) -> str:
        page = agent.payments.list(account_id=agent.account_id, limit=10)
        return json.dumps(
            [
                {
                    "id": p.id,
                    "status": p.status,
                    "amount": p.amount.amount,
                    "to": p.counterparty.address,
                }
                for p in page.data
            ]
        )

    return [
        Tool("get_balance", "Get this agent's USDC balances.", NoArgs, get_balance),
        Tool(
            "check_spend",
            "Dry-run a payment against the spending policy without paying.",
            CheckSpendArgs,
            check_spend,
        ),
        Tool("pay", "Pay USDC to an address or another agent, within policy.", PayArgs, pay),
        Tool(
            "fetch_paid_resource",
            f"Fetch a pay-per-call (x402) URL, paying at most {max_x402_amount} USDC.",
            FetchArgs,
            fetch_paid_resource,
        ),
        Tool(
            "list_transactions",
            "List this agent's 10 most recent payments.",
            NoArgs,
            list_transactions,
        ),
    ]


def main() -> None:
    keys = Path(".agentbank")
    with AgentBank(
        session_key=SessionKey.load(keys / "session.json"),
        spend_key=SessionKey.load(keys / "spend.json"),
    ) as agent:
        tools = {tool.name: tool for tool in money_tools(agent)}
        for tool in tools.values():
            print(f"{tool.name}: {tool.description}")
            print(f"  schema: {json.dumps(tool.args_schema.model_json_schema()['properties'])}")
        # What a model's tool call looks like once your framework parses it:
        call = {"name": "get_balance", "args": {}}
        print(tools[call["name"]].invoke(call["args"]))  # type: ignore[index, arg-type]


if __name__ == "__main__":
    main()
