"""The examples import cleanly, and the LangChain-style toolkit works end to end."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
import respx

from agentbank import AgentBank, SessionKey, owner_payloads
from tests.conftest import ACCOUNT_ID, AGENT_ID, API_KEY, BASE_URL, ORG_ID, OWNER_KEY, SESSION_ID
from tests.factories import SCHEMAS, build, example
from tests.test_principal_flows import SMART_ACCOUNT, body_of, mock_setup_routes, verify
from tests.test_spend_key import fiat_token_permit_digest, recover

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


def test_principal_setup_example(
    api: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    routes = mock_setup_routes(api)
    api.get("/v1/orgs/me").respond(json=example("Org", id=ORG_ID))
    api.post("/v1/agents").respond(201, json=example("Agent", id=AGENT_ID))
    policy = api.put(f"/v1/agents/{AGENT_ID}/policy").respond(json=example("AgentPolicy"))
    monkeypatch.setenv("AGENTBANK_BASE_URL", BASE_URL)
    monkeypatch.setenv("AGENTBANK_API_KEY", API_KEY)
    monkeypatch.setenv("AGENTBANK_OWNER_KEY", OWNER_KEY)
    monkeypatch.chdir(tmp_path)

    load(EXAMPLES_DIR / "principal_setup.py").main()

    output = capsys.readouterr().out
    assert f"export AGENTBANK_ACCOUNT_ID={ACCOUNT_ID}" in output
    assert f"export AGENTBANK_SESSION_ID={SESSION_ID}" in output
    assert "(permit executed)" in output
    policy_body = body_of(policy)
    authorization = policy_body.pop("owner_authorization")
    verify(owner_payloads.policy_loosen(AGENT_ID, policy_body["policy"]), authorization)
    # The saved spend key (0600) signed the float-recovery permit for the smart account.
    key_file = tmp_path / ".agentbank" / "spend.json"
    assert key_file.stat().st_mode & 0o777 == 0o600
    spend_key = SessionKey.load(key_file)
    attach = body_of(routes["attach"])
    assert attach["spend_key_address"] == spend_key.address
    permit = attach["permit"]
    digest = fiat_token_permit_digest(
        owner=spend_key.address,
        spender=SMART_ACCOUNT,
        value=int(permit["value"]),
        nonce=0,
        deadline=int(permit["deadline"]),
    )
    assert recover(digest, permit["signature"]) == spend_key.address
    assert routes["sign"].calls.last.request.headers["idempotency-key"] == (
        f"setup-{AGENT_ID}.session.sign"
    )
