"""Every API operation, through its typed resource method (sync and async).

Each case mocks the operation's route with a contract-valid example response
(built from ``openapi.json``) and checks the request: method and path, the
credentials the operation accepts, the ``Idempotency-Key`` on idempotent
writes, and a JSON body when the operation takes one.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
import pytest
import respx

from agentbank import AgentBank, AsyncAgentBank
from agentbank._operations import OPERATIONS
from agentbank.models import AutoTopUpRule, Statement
from tests.conftest import (
    ACCOUNT_ID,
    AGENT_ID,
    OWNER_ADDRESS,
    SESSION_ADDRESS,
    SESSION_ID,
    SPEND_ADDRESS,
    verify_agent_request,
)
from tests.factories import SCHEMAS, build, id_for, response_schema

KEY_ID = id_for("key")
OOP_ID = id_for("oop")
MDT_ID = id_for("mdt")
PAY_ID = id_for("pay")
PREQ_ID = id_for("preq")
ESC_ID = id_for("esc")
STR_ID = id_for("str")
APR_ID = id_for("apr")
VLT_ID = id_for("vlt")
WHE_ID = id_for("whe")
SIGNATURE = "0x" + "11" * 65
AUTH = {"signer": OWNER_ADDRESS, "signature": SIGNATURE, "issued_at": 1, "expires_at": 600}
SCOPE = {"max_per_tx": "5.00", "max_per_day": "50.00", "expires_at": "2026-10-12T00:00:00Z"}
MANDATE = {
    "vct": "mandate.payment.open.1",
    "constraints": [{"type": "payment.budget", "currency": "USDC", "max": 1_000_000}],
    "iat": 1_790_000_000,
    "exp": 1_790_086_400,
    "agent_id": AGENT_ID,
}
REQUIREMENTS = {
    "scheme": "exact",
    "network": "eip155:84532",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "amount": "10000",
    "payTo": OWNER_ADDRESS,
    "maxTimeoutSeconds": 60,
    "extra": {"name": "USDC", "version": "2"},
}
PAYLOAD = {"x402Version": 2, "accepted": REQUIREMENTS, "payload": {"signature": SIGNATURE}}
EXPIRES = datetime(2026, 11, 1, tzinfo=timezone.utc)

Kind = Literal["principal", "agent"]


@dataclass(frozen=True)
class Case:
    operation_id: str
    kind: Kind
    call: Callable[[Any], Any]
    path_id: str | None = None


CASES: list[Case] = [
    # orgs
    Case(
        "createOrg",
        "principal",
        lambda c: c.orgs.create(
            legal_name="Acme",
            kind="company",
            country="US",
            contact_email="ops@acme.test",
            owner_address=OWNER_ADDRESS,
        ),
    ),
    Case("getCurrentOrg", "principal", lambda c: c.orgs.me()),
    Case("startKyb", "principal", lambda c: c.orgs.start_kyb()),
    Case("freezeOrg", "principal", lambda c: c.orgs.freeze(reason="incident")),
    Case(
        "unfreezeOrg",
        "principal",
        lambda c: c.orgs.unfreeze(reason="resolved", owner_authorization=AUTH),
    ),
    # treasury
    Case("createTreasuryAccount", "principal", lambda c: c.treasury.create_account()),
    Case(
        "setTreasury",
        "principal",
        lambda c: c.treasury.set_account(account_id=ACCOUNT_ID, owner_authorization=AUTH),
    ),
    Case("getAutoTopUp", "agent", lambda c: c.treasury.get_auto_topup(AGENT_ID), AGENT_ID),
    Case(
        "putAutoTopUp",
        "principal",
        lambda c: c.treasury.set_auto_topup(
            AGENT_ID,
            refill_to="50.00",
            when_below="10.00",
            max_per_day="100.00",
            owner_authorization=AUTH,
        ),
        AGENT_ID,
    ),
    Case("listFunds", "principal", lambda c: c.treasury.list_funds()),
    Case(
        "putSweepRule",
        "principal",
        lambda c: c.treasury.set_sweep_rule(
            ACCOUNT_ID,
            fund_id=id_for("fnd"),
            threshold="1000.00",
            max_share_bps=5000,
            floor="100.00",
            owner_authorization=AUTH,
        ),
        ACCOUNT_ID,
    ),
    # api keys and members
    Case("listApiKeys", "principal", lambda c: c.api_keys.list(limit=5)),
    Case("createApiKey", "principal", lambda c: c.api_keys.create(name="ci", scopes=["admin"])),
    Case("revokeApiKey", "principal", lambda c: c.api_keys.revoke(KEY_ID), KEY_ID),
    Case("listMembers", "principal", lambda c: c.members.list()),
    Case("createMember", "principal", lambda c: c.members.create(email="a@b.test", role="viewer")),
    # agents and accounts
    Case(
        "createAgent",
        "principal",
        lambda c: c.agents.create(name="bot", description="d", metadata={"team": "ops"}),
    ),
    Case("listAgents", "principal", lambda c: c.agents.list(status="active")),
    Case("getAgent", "agent", lambda c: c.agents.get(AGENT_ID), AGENT_ID),
    Case("freezeAgent", "principal", lambda c: c.agents.freeze(AGENT_ID, reason="x"), AGENT_ID),
    Case(
        "unfreezeAgent",
        "principal",
        lambda c: c.agents.unfreeze(AGENT_ID, reason="y", owner_authorization=AUTH),
        AGENT_ID,
    ),
    Case(
        "createAccount",
        "principal",
        lambda c: c.accounts.create(AGENT_ID, spend_key_address=SPEND_ADDRESS),
        AGENT_ID,
    ),
    Case("listAccounts", "agent", lambda c: c.accounts.list(agent_id=AGENT_ID)),
    Case("getAccount", "agent", lambda c: c.accounts.get(), ACCOUNT_ID),
    Case("getBalances", "agent", lambda c: c.accounts.balances(), ACCOUNT_ID),
    # sessions and owner operations
    Case(
        "createSession",
        "principal",
        lambda c: c.sessions.create(
            account_id=ACCOUNT_ID,
            public_key=SESSION_ADDRESS,
            scope=SCOPE,
            owner_authorization=AUTH,
        ),
    ),
    Case("getSession", "agent", lambda c: c.sessions.get(SESSION_ID), SESSION_ID),
    Case("revokeSession", "principal", lambda c: c.sessions.revoke(SESSION_ID), SESSION_ID),
    Case("installSession", "principal", lambda c: c.sessions.install(SESSION_ID), SESSION_ID),
    Case("getOwnerOperation", "principal", lambda c: c.owner_operations.get(OOP_ID), OOP_ID),
    Case(
        "submitOwnerSignature",
        "principal",
        lambda c: c.owner_operations.submit_signature(OOP_ID, signature=SIGNATURE),
        OOP_ID,
    ),
    # mandates and policies
    Case(
        "createMandate",
        "principal",
        lambda c: c.mandates.create(agent_id=AGENT_ID, mandate=MANDATE, owner_authorization=AUTH),
    ),
    Case("getMandate", "agent", lambda c: c.mandates.get(MDT_ID), MDT_ID),
    Case("revokeMandate", "principal", lambda c: c.mandates.revoke(MDT_ID), MDT_ID),
    Case("getPolicy", "agent", lambda c: c.policies.get(AGENT_ID), AGENT_ID),
    Case(
        "putPolicy",
        "principal",
        lambda c: c.policies.update(AGENT_ID, policy={"limits": {"per_day": "5.00"}}),
        AGENT_ID,
    ),
    Case(
        "checkPolicy",
        "agent",
        lambda c: c.policies.check(
            intent={"amount": {"amount": "1.00", "asset": "USDC"}, "to_agent_id": AGENT_ID}
        ),
    ),
    # payments
    Case("createPayment", "agent", lambda c: c.payments.create(amount="1.00", to=AGENT_ID)),
    Case("listPayments", "agent", lambda c: c.payments.list(status="settled")),
    Case("getPayment", "agent", lambda c: c.payments.get(PAY_ID), PAY_ID),
    Case(
        "submitPaymentSignature",
        "agent",
        lambda c: c.payments.submit_signature(PAY_ID, signature=SIGNATURE),
        PAY_ID,
    ),
    Case("cancelPayment", "agent", lambda c: c.payments.cancel(PAY_ID), PAY_ID),
    Case(
        "createPaymentRequest",
        "agent",
        lambda c: c.payment_requests.create(amount="2.00", reference="inv-1"),
    ),
    Case("getPaymentRequest", "agent", lambda c: c.payment_requests.get(PREQ_ID), PREQ_ID),
    # x402
    Case(
        "x402Pay",
        "agent",
        lambda c: c.x402.pay(
            resource={"url": "https://api.example-data.com/r"}, requirements=REQUIREMENTS
        ),
    ),
    Case(
        "x402Verify",
        "principal",
        lambda c: c.x402.verify(payment_payload=PAYLOAD, payment_requirements=REQUIREMENTS),
    ),
    Case(
        "x402Settle",
        "principal",
        lambda c: c.x402.settle(payment_payload=PAYLOAD, payment_requirements=REQUIREMENTS),
    ),
    Case("x402Supported", "principal", lambda c: c.x402.supported()),
    Case(
        "registerX402Payee",
        "principal",
        lambda c: c.x402.register_payee(account_id=ACCOUNT_ID, domains=["api.example-data.com"]),
    ),
    # escrows
    Case(
        "createEscrow",
        "agent",
        lambda c: c.escrows.create(
            payee=OWNER_ADDRESS, amount="5.00", expires_at=EXPIRES, terms="deliver a report"
        ),
    ),
    Case("getEscrow", "agent", lambda c: c.escrows.get(ESC_ID), ESC_ID),
    Case(
        "submitEscrowSignature",
        "agent",
        lambda c: c.escrows.submit_signature(ESC_ID, signature=SIGNATURE),
        ESC_ID,
    ),
    Case("releaseEscrow", "agent", lambda c: c.escrows.release(ESC_ID), ESC_ID),
    Case("refundEscrow", "agent", lambda c: c.escrows.refund(ESC_ID), ESC_ID),
    Case("disputeEscrow", "agent", lambda c: c.escrows.dispute(ESC_ID, reason="late"), ESC_ID),
    # streams
    Case(
        "createStream",
        "agent",
        lambda c: c.streams.create(
            payee=AGENT_ID, amount_per_interval="0.01", interval_seconds=1, deposit="10.00"
        ),
    ),
    Case("getStream", "agent", lambda c: c.streams.get(STR_ID), STR_ID),
    Case(
        "submitStreamSignature",
        "agent",
        lambda c: c.streams.submit_signature(STR_ID, signature=SIGNATURE),
        STR_ID,
    ),
    Case("cancelStream", "agent", lambda c: c.streams.cancel(STR_ID), STR_ID),
    # approvals
    Case("listApprovals", "principal", lambda c: c.approvals.list(status="pending")),
    Case("getApproval", "principal", lambda c: c.approvals.get(APR_ID), APR_ID),
    Case("decideApproval", "principal", lambda c: c.approvals.approve(APR_ID), APR_ID),
    # ledger
    Case("listEntries", "agent", lambda c: c.ledger.entries(limit=2), ACCOUNT_ID),
    Case("getStatement", "agent", lambda c: c.ledger.statement(period="2026-10")),
    # vaults
    Case(
        "createVault",
        "agent",
        lambda c: c.vaults.create(kind="locked", name="taxes", target="100.00", unlock_at=EXPIRES),
    ),
    Case("listVaults", "agent", lambda c: c.vaults.list(account_id=ACCOUNT_ID)),
    Case("getVault", "agent", lambda c: c.vaults.get(VLT_ID), VLT_ID),
    Case("depositVault", "agent", lambda c: c.vaults.deposit(VLT_ID, amount="1.00"), VLT_ID),
    Case("withdrawVault", "principal", lambda c: c.vaults.withdraw(VLT_ID, amount="1.00"), VLT_ID),
    # webhooks
    Case(
        "createWebhookEndpoint",
        "principal",
        lambda c: c.webhooks.create_endpoint(
            url="https://hooks.example.test/agentbank", events=["payment.settled"]
        ),
    ),
    Case("listWebhookEndpoints", "principal", lambda c: c.webhooks.list_endpoints()),
    Case(
        "deleteWebhookEndpoint", "principal", lambda c: c.webhooks.delete_endpoint(WHE_ID), WHE_ID
    ),
    Case("listEvents", "principal", lambda c: c.webhooks.list_events(type="payment.settled")),
    # billing and meta
    Case("listPlans", "principal", lambda c: c.billing.list_plans()),
    Case("getSubscription", "principal", lambda c: c.billing.get_subscription()),
    Case("changePlan", "principal", lambda c: c.billing.change_plan(plan="pro")),
    Case("getFees", "principal", lambda c: c.billing.get_fees(period="2026-10")),
    Case("health", "principal", lambda c: c.health()),
]

#: Operations deliberately without a typed method (reachable through ``client.call``).
UNWRAPPED = {"getRevenueReport"}


def _expected_path(case: Case) -> str:
    path = OPERATIONS[case.operation_id].path
    return path.replace("{id}", case.path_id) if case.path_id else path


def _mock(router: respx.MockRouter, case: Case) -> respx.Route:
    operation = OPERATIONS[case.operation_id]
    schema = response_schema(case.operation_id)
    assert schema is not None
    body = build(SCHEMAS[schema], full=True)
    return router.route(method=operation.method, path=_expected_path(case)).respond(
        operation.success_status, json=body
    )


def _check_request(case: Case, request: httpx.Request) -> None:
    operation = OPERATIONS[case.operation_id]
    public = operation.auth[0] in ("public", "seller")
    if public:
        assert "authorization" not in request.headers
        assert "signature" not in request.headers
    elif case.kind == "agent" and "agent" in operation.auth:
        verify_agent_request(request)
    else:
        assert request.headers["authorization"].startswith("Bearer abk_test_")
    assert ("idempotency-key" in request.headers) == operation.idempotent
    if operation.has_body:
        assert isinstance(json.loads(request.content), dict)
        assert request.headers["content-type"] == "application/json"
    else:
        assert not request.content


def test_every_operation_has_a_case() -> None:
    covered = {case.operation_id for case in CASES}
    assert covered | UNWRAPPED == set(OPERATIONS)
    assert len(CASES) == len(covered)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.operation_id)
def test_sync_operation(
    case: Case, api: respx.MockRouter, principal: AgentBank, agent: AgentBank
) -> None:
    route = _mock(api, case)
    client = principal if case.kind == "principal" else agent
    result = case.call(client)
    assert result is not None
    assert route.call_count == 1
    _check_request(case, route.calls.last.request)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.operation_id)
async def test_async_operation(
    case: Case,
    api: respx.MockRouter,
    async_principal: AsyncAgentBank,
    async_agent: AsyncAgentBank,
) -> None:
    route = _mock(api, case)
    client = async_principal if case.kind == "principal" else async_agent
    pending = case.call(client)
    assert inspect.isawaitable(pending)
    result = await pending
    assert result is not None
    assert route.call_count == 1
    _check_request(case, route.calls.last.request)


def test_typed_results(api: respx.MockRouter, agent: AgentBank) -> None:
    rule = build(SCHEMAS["AutoTopUpRule"])
    api.get(f"/v1/agents/{AGENT_ID}/auto-topup").mock(
        side_effect=[httpx.Response(200, json=rule), httpx.Response(200, json=None)]
    )
    assert isinstance(agent.treasury.get_auto_topup(AGENT_ID), AutoTopUpRule)
    assert agent.treasury.get_auto_topup(AGENT_ID) is None
    statement = api.get("/v1/statements").mock(
        side_effect=[
            httpx.Response(200, json=build(SCHEMAS["Statement"])),
            httpx.Response(200, text="date,amount\n2026-10-01,1.00\n"),
        ]
    )
    assert isinstance(agent.ledger.statement(period="2026-10"), Statement)
    assert agent.ledger.statement(period="2026-10", format="csv").startswith("date,amount")
    request = statement.calls.last.request
    assert request.headers["accept"] == "text/csv"
    assert request.url.params["format"] == "csv"
    assert request.url.params["account_id"] == ACCOUNT_ID


def _page(schema: str, cursor: str | None) -> dict[str, Any]:
    page: dict[str, Any] = build(SCHEMAS[schema], full=True)
    page["next_cursor"] = cursor
    return page


ITERATORS: list[tuple[str, str, Kind, Callable[[Any], Any], str | None]] = [
    ("listApiKeys", "ListApiKeysResponse", "principal", lambda c: c.api_keys.list_all(), None),
    ("listMembers", "ListMembersResponse", "principal", lambda c: c.members.list_all(), None),
    ("listAgents", "ListAgentsResponse", "principal", lambda c: c.agents.list_all(), None),
    ("listAccounts", "ListAccountsResponse", "agent", lambda c: c.accounts.list_all(), None),
    ("listPayments", "ListPaymentsResponse", "agent", lambda c: c.payments.list_all(), None),
    ("listApprovals", "ListApprovalsResponse", "principal", lambda c: c.approvals.list_all(), None),
    ("listEntries", "ListEntriesResponse", "agent", lambda c: c.ledger.entries_all(), ACCOUNT_ID),
    ("listVaults", "ListVaultsResponse", "agent", lambda c: c.vaults.list_all(), None),
    (
        "listWebhookEndpoints",
        "ListWebhookEndpointsResponse",
        "principal",
        lambda c: c.webhooks.list_endpoints_all(),
        None,
    ),
    (
        "listEvents",
        "ListEventsResponse",
        "principal",
        lambda c: c.webhooks.list_events_all(),
        None,
    ),
]


def _mock_pages(
    api: respx.MockRouter, operation_id: str, schema: str, path_id: str | None
) -> respx.Route:
    path = OPERATIONS[operation_id].path.replace("{id}", path_id or "")
    return api.get(path).mock(
        side_effect=[
            httpx.Response(200, json=_page(schema, "cursor-2")),
            httpx.Response(200, json=_page(schema, None)),
        ]
    )


@pytest.mark.parametrize(("operation_id", "schema", "kind", "call", "path_id"), ITERATORS)
def test_sync_auto_pagination(
    operation_id: str,
    schema: str,
    kind: Kind,
    call: Callable[[Any], Any],
    path_id: str | None,
    api: respx.MockRouter,
    principal: AgentBank,
    agent: AgentBank,
) -> None:
    route = _mock_pages(api, operation_id, schema, path_id)
    items = list(call(principal if kind == "principal" else agent))
    assert len(items) == 2
    assert route.call_count == 2
    assert "cursor" not in route.calls[0].request.url.params
    assert route.calls[1].request.url.params["cursor"] == "cursor-2"


@pytest.mark.parametrize(("operation_id", "schema", "kind", "call", "path_id"), ITERATORS)
async def test_async_auto_pagination(
    operation_id: str,
    schema: str,
    kind: Kind,
    call: Callable[[Any], Any],
    path_id: str | None,
    api: respx.MockRouter,
    async_principal: AsyncAgentBank,
    async_agent: AsyncAgentBank,
) -> None:
    route = _mock_pages(api, operation_id, schema, path_id)
    items = [item async for item in call(async_principal if kind == "principal" else async_agent)]
    assert len(items) == 2
    assert route.calls[1].request.url.params["cursor"] == "cursor-2"
