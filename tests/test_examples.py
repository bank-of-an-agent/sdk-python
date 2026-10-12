"""The examples import cleanly, and the LangChain-style toolkit works end to end."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
import respx

from agentbank import AgentBank
from tests.conftest import ACCOUNT_ID, AGENT_ID
from tests.factories import SCHEMAS, build

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
EXAMPLES = sorted(EXAMPLES_DIR.glob("*.py"))


def load(path: Path) -> ModuleType:
    """Import an example module without running its ``__main__`` block."""
    spec = importlib.util.spec_from_file_location(f"examples_{path.stem}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_example_imports_without_side_effects(path: Path) -> None:
    assert load(path).__doc__


def test_money_tools(agent: AgentBank, api: respx.MockRouter) -> None:
    toolkit = load(EXAMPLES_DIR / "langchain_tool.py")
    tools = {tool.name: tool for tool in toolkit.money_tools(agent)}
    assert set(tools) == {
        "get_balance",
        "check_spend",
        "pay",
        "fetch_paid_resource",
        "list_transactions",
    }

    api.get(f"/v1/accounts/{ACCOUNT_ID}/balances").respond(json=build(SCHEMAS["Balances"]))
    assert tools["get_balance"].invoke({}).startswith("available 1.00 USDC")

    check = api.post("/v1/policy/check").respond(json=build(SCHEMAS["PolicyDecision"], full=True))
    assert tools["check_spend"].invoke({"to": AGENT_ID, "amount": "2.50"}).startswith("allow")
    assert b'"to_agent_id"' in check.calls.last.request.content

    api.post("/v1/payments").respond(
        422, json={"code": "policy_denied", "detail": "Recipient not on the allowlist"}
    )
    denied = tools["pay"].invoke({"to": "0x" + "44" * 20, "amount": "2.50"})
    assert denied == "error policy_denied: Recipient not on the allowlist"

    api.get("/v1/payments").respond(json=build(SCHEMAS["ListPaymentsResponse"], full=True))
    assert '"status": "requires_approval"' in tools["list_transactions"].invoke({})

    with respx.mock(assert_all_called=False) as router:
        router.get("https://free.example/data").respond(200, text="free data")
        result = tools["fetch_paid_resource"].invoke({"url": "https://free.example/data"})
    assert result == "HTTP 200: free data"
