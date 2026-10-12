"""Client transport behaviour: credentials, idempotency, signing, retries, errors."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any

import httpx
import pytest
import respx

from agentbank import (
    AgentBank,
    AgentBankError,
    APIConnectionError,
    APITimeoutError,
    ConfigurationError,
    InternalServerError,
    MainnetLockedError,
    PolicyDeniedError,
    RateLimitError,
    ServiceUnavailableError,
)
from agentbank._base_client import retry_delay
from agentbank.http_signatures import parse_signature_input
from tests.conftest import (
    ACCOUNT_ID,
    AGENT_ID,
    API_KEY,
    BASE_URL,
    SESSION_ID,
    SESSION_KEY,
    verify_agent_request,
)
from tests.factories import example, id_for


def payment_json(**overrides: Any) -> dict[str, Any]:
    return example("Payment", id=id_for("pay"), account_id=ACCOUNT_ID, **overrides)


# --------------------------------------------------------------------- configuration


def test_environment_variables_configure_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTBANK_BASE_URL", "https://env.agentbank.test/")
    monkeypatch.setenv("AGENTBANK_API_KEY", API_KEY)
    monkeypatch.setenv("AGENTBANK_SESSION_ID", SESSION_ID)
    monkeypatch.setenv("AGENTBANK_SESSION_KEY", SESSION_KEY)
    monkeypatch.setenv("AGENTBANK_ACCOUNT_ID", ACCOUNT_ID)
    with AgentBank() as bank:
        assert bank.config.base_url == "https://env.agentbank.test"
        assert bank.config.facilitator_url == "https://env.agentbank.test"
        assert bank.config.api_key == API_KEY
        assert bank.session_id == SESSION_ID
        assert bank.account_id == ACCOUNT_ID
        assert bank.chain_id == 84532
        assert API_KEY not in repr(bank)
        assert SESSION_KEY not in repr(bank)
        assert "api_key" in repr(bank)


def test_defaults_to_local_development_server() -> None:
    with AgentBank() as bank:
        assert bank.config.base_url == "http://localhost:8080"
        assert bank.config.max_retries == 2
        assert "agentbank-python/" in bank.config.user_agent


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"session_id": SESSION_ID}, ConfigurationError),
        ({"session_key": SESSION_KEY}, ConfigurationError),
        ({"chain_id": 8453}, MainnetLockedError),
        ({"chain_id": 1}, MainnetLockedError),
        ({"base_url": "api.agentbank.test"}, ConfigurationError),
        ({"max_retries": -1}, ConfigurationError),
    ],
)
def test_invalid_configuration_is_rejected(
    kwargs: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        AgentBank(**kwargs)  # type: ignore[arg-type]


def test_missing_credentials_fail_before_sending(api: respx.MockRouter) -> None:
    route = api.post("/v1/payments")
    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as principal:
        with pytest.raises(ConfigurationError, match="agent session"):
            principal.payments.create(account_id=ACCOUNT_ID, amount="1.00", to=AGENT_ID)
    with AgentBank(session_id=SESSION_ID, session_key=SESSION_KEY, base_url=BASE_URL) as agent:
        with pytest.raises(ConfigurationError, match="org API key"):
            agent.agents.create(name="x")
        with pytest.raises(ConfigurationError, match="staff token"):
            agent.call("getRevenueReport", query={"period": "2026-10"})
        with pytest.raises(ConfigurationError, match="account_id"):
            agent.accounts.balances()
    assert not route.called


# --------------------------------------------------------------------- authentication


def test_principal_requests_use_bearer_tokens(principal: AgentBank, api: respx.MockRouter) -> None:
    route = api.get(f"/v1/agents/{AGENT_ID}").respond(json=example("Agent", id=AGENT_ID))
    agent = principal.agents.get(AGENT_ID)
    assert agent.id == AGENT_ID
    request = route.calls.last.request
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    assert "signature" not in request.headers
    assert request.headers["accept"] == "application/json"
    assert request.headers["user-agent"].startswith("agentbank-python/")


def test_agent_requests_are_signed_over_the_exact_bytes(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    route = api.post("/v1/payments").respond(201, json=payment_json(status="submitted"))
    agent.payments.create(amount="12.50", to="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", memo="ü")
    request = route.calls.last.request
    verified = verify_agent_request(request)
    assert verified.key_id == SESSION_ID
    assert verified.covered_components == (
        "@method",
        "@target-uri",
        "content-digest",
        "idempotency-key",
    )
    assert "authorization" not in request.headers
    body = json.loads(request.content)
    assert body == {
        "account_id": ACCOUNT_ID,
        "amount": {"amount": "12.50", "asset": "USDC"},
        "memo": "ü",
        "to": {"address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"},
    }
    # Canonical JSON body: sorted keys, no whitespace, UTF-8 (not \\u-escaped).
    assert (
        request.content
        == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )


def test_operations_accepting_both_prefer_the_api_order(api: respx.MockRouter) -> None:
    route = api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(json=example("Account", id=ACCOUNT_ID))
    with AgentBank(
        api_key=API_KEY, session_id=SESSION_ID, session_key=SESSION_KEY, base_url=BASE_URL
    ) as both:
        both.accounts.get(ACCOUNT_ID)  # x-agentbank-auth: [principal, agent]
        assert "authorization" in route.calls.last.request.headers
        preq = api.post("/v1/payment-requests").respond(201, json=example("PaymentRequest"))
        both.payment_requests.create(account_id=ACCOUNT_ID, amount="1.00")  # [agent, principal]
        assert "signature" in preq.calls.last.request.headers


def test_public_operations_send_no_credentials(principal: AgentBank, api: respx.MockRouter) -> None:
    plans = api.get("/v1/billing/plans").respond(json=example("ListPlansResponse"))
    health = api.get("/healthz").respond(json=example("HealthResponse"))
    org = api.post("/v1/orgs").respond(201, json=example("CreateOrgResponse", full=True))
    principal.billing.list_plans()
    principal.health()
    principal.orgs.create(
        legal_name="Acme",
        kind="company",
        country="US",
        contact_email="ops@acme.test",
        owner_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    )
    for route in (plans, health, org):
        assert "authorization" not in route.calls.last.request.headers
    assert "idempotency-key" in org.calls.last.request.headers


def test_facilitator_operations_use_the_facilitator_url(api: respx.MockRouter) -> None:
    with respx.mock(base_url="https://facilitator.agentbank.test") as facilitator:
        route = facilitator.get("/v1/x402/supported").respond(json=example("X402SupportedResponse"))
        with AgentBank(
            api_key=API_KEY,
            base_url=BASE_URL,
            facilitator_url="https://facilitator.agentbank.test",
        ) as bank:
            bank.x402.supported()
        assert route.called


# --------------------------------------------------------------------- idempotency


def test_idempotency_keys_are_automatic_and_overridable(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    route = api.post("/v1/agents").respond(201, json=example("Agent"))
    principal.agents.create(name="a")
    principal.agents.create(name="b")
    first, second = (call.request.headers["idempotency-key"] for call in route.calls)
    assert first != second
    uuid.UUID(first)
    principal.agents.create(name="c", idempotency_key="my-task-0001")
    assert route.calls.last.request.headers["idempotency-key"] == "my-task-0001"
    with pytest.raises(ValueError, match="8 to 255"):
        principal.agents.create(name="d", idempotency_key="short")


def test_reads_deletes_and_dry_runs_have_no_idempotency_key(
    agent: AgentBank, principal: AgentBank, api: respx.MockRouter
) -> None:
    get = api.get(f"/v1/accounts/{ACCOUNT_ID}/balances").respond(json=example("Balances"))
    check = api.post("/v1/policy/check").respond(json=example("PolicyDecision"))
    delete = api.delete(f"/v1/sessions/{SESSION_ID}").respond(json=example("Session"))
    agent.accounts.balances()
    agent.policies.check(intent={"kind": "transfer", "amount": {"amount": "1.00", "asset": "USDC"}})
    principal.sessions.revoke(SESSION_ID)
    for route in (get, check, delete):
        assert "idempotency-key" not in route.calls.last.request.headers
    assert verify_agent_request(check.calls.last.request).covered_components[-1] == "content-digest"


# --------------------------------------------------------------------- retries


def test_retries_reuse_the_idempotency_key_and_re_sign(
    agent: AgentBank, api: respx.MockRouter, sleeps: list[float]
) -> None:
    route = api.post("/v1/payments").mock(
        side_effect=[
            httpx.Response(503, json={"code": "cosigner_unavailable", "status": 503}),
            httpx.ConnectError("connection refused"),
            httpx.Response(201, json=payment_json(status="submitted")),
        ]
    )
    payment = agent.payments.create(amount="1.00", to=AGENT_ID)
    assert payment.status == "submitted"
    assert route.call_count == 3
    keys = {call.request.headers["idempotency-key"] for call in route.calls}
    nonces = {
        parse_signature_input(call.request.headers["signature-input"])[1].nonce
        for call in route.calls
    }
    assert len(keys) == 1
    assert len(nonces) == 3
    for call in route.calls:
        verify_agent_request(call.request)
    assert len(sleeps) == 2
    assert all(0 < delay <= 8 for delay in sleeps)


def test_retry_after_is_honored(
    principal: AgentBank, api: respx.MockRouter, sleeps: list[float]
) -> None:
    later = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    api.get("/v1/orgs/me").mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "2"}, json={"code": "rate_limited"}),
            httpx.Response(503, headers={"retry-after": later}),
            httpx.Response(200, json=example("Org")),
        ]
    )
    principal.orgs.me()
    assert sleeps[0] == 2.0
    assert 25 <= sleeps[1] <= 30


def test_retry_delay_bounds() -> None:
    assert 0.375 <= retry_delay(0) <= 0.5
    assert 6.0 <= retry_delay(10) <= 8.0
    request = httpx.Request("GET", BASE_URL)
    too_long = httpx.Response(429, headers={"retry-after": "3600"}, request=request)
    assert retry_delay(0, too_long) <= 0.5
    garbage = httpx.Response(429, headers={"retry-after": "soon"}, request=request)
    assert retry_delay(1, garbage) <= 1.0


def test_unsafe_operations_are_not_retried_after_ambiguous_failures(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    route = api.post("/v1/x402/settle").mock(
        side_effect=[httpx.Response(500, json={"code": "internal", "status": 500})]
    )
    with pytest.raises(InternalServerError):
        principal.x402.settle(payment_payload={}, payment_requirements={})
    assert route.call_count == 1

    route.reset()
    route.mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(APITimeoutError):
        principal.x402.settle(payment_payload={}, payment_requirements={})
    assert route.call_count == 1


def test_connection_errors_and_rate_limits_are_always_retried(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    route = api.post("/v1/x402/settle").mock(
        side_effect=[
            httpx.ConnectError("refused"),
            httpx.Response(429, json={"code": "rate_limited"}),
            httpx.Response(200, json=example("X402SettleResponse")),
        ]
    )
    principal.x402.settle(payment_payload={}, payment_requirements={})
    assert route.call_count == 3


def test_retries_are_bounded(principal: AgentBank, api: respx.MockRouter) -> None:
    route = api.get("/v1/orgs/me").respond(503, json={"code": "screening_unavailable"})
    with pytest.raises(ServiceUnavailableError) as excinfo:
        principal.orgs.me()
    assert excinfo.value.code == "screening_unavailable"
    assert route.call_count == 3
    with pytest.raises(ServiceUnavailableError):
        principal.orgs.me(request_options={"max_retries": 0})
    assert route.call_count == 4
    flaky = api.get("/v1/members").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(APITimeoutError):
        principal.members.list()
    assert flaky.call_count == 3
    broken = api.get("/v1/api-keys").mock(side_effect=httpx.RemoteProtocolError("reset"))
    with pytest.raises(APIConnectionError) as connection:
        principal.api_keys.list()
    assert connection.value.code == "connection_error"
    assert broken.call_count == 3


def test_client_errors_are_raised_immediately(agent: AgentBank, api: respx.MockRouter) -> None:
    problem = {
        "type": "urn:agentbank:problem:policy_denied",
        "title": "Payment denied by policy",
        "status": 422,
        "detail": "Daily limit of 50.00 USDC reached",
        "code": "policy_denied",
        "rule_hits": [{"rule": "limits.per_day", "effect": "deny", "detail": "50.00"}],
    }
    route = api.post("/v1/payments").respond(
        422, json=problem, headers={"content-type": "application/problem+json"}
    )
    with pytest.raises(PolicyDeniedError) as excinfo:
        agent.payments.create(amount="60.00", to=AGENT_ID)
    assert route.call_count == 1
    assert excinfo.value.detail == "Daily limit of 50.00 USDC reached"
    assert excinfo.value.extensions["rule_hits"][0]["rule"] == "limits.per_day"


# --------------------------------------------------------------------- request options


def test_request_options(principal: AgentBank, api: respx.MockRouter) -> None:
    route = api.get("/v1/agents").respond(json=example("ListAgentsResponse"))
    principal.agents.list(
        status="frozen",
        limit=10,
        request_options={
            "timeout": 5.0,
            "extra_headers": {"X-Trace": "abc", "Authorization": "Bearer forged"},
            "extra_query": {"debug": True},
        },
    )
    request = route.calls.last.request
    assert request.headers["x-trace"] == "abc"
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    assert request.url.params["status"] == "frozen"
    assert request.url.params["limit"] == "10"
    assert request.url.params["debug"] == "true"
    assert request.extensions["timeout"]["read"] == 5.0


def test_default_headers_and_custom_http_client(api: respx.MockRouter) -> None:
    route = api.get("/v1/orgs/me").respond(json=example("Org"))
    http = httpx.Client()
    with AgentBank(
        api_key=API_KEY,
        base_url=BASE_URL,
        default_headers={"X-Team": "ops"},
        http_client=http,
        timeout=httpx.Timeout(3.0),
    ) as bank:
        bank.orgs.me()
    assert route.calls.last.request.headers["x-team"] == "ops"
    assert not http.is_closed  # caller-owned clients are left open
    http.close()


def test_low_level_call(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get("/v1/billing/fees").respond(json={"object": "fee_summary", "total": "1.00"})
    data = principal.call("getFees", query={"period": "2026-10"})
    assert data["total"] == "1.00"
    with pytest.raises(ValueError, match="Unknown operation"):
        principal.call("printMoney")
    api.delete(f"/v1/api-keys/{id_for('key')}").respond(204)
    assert principal.call("revokeApiKey", path_params={"id": id_for("key")}) is None


def test_path_parameters_are_escaped_and_required(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    route = api.get(url__regex=r"/v1/agents/.+").respond(json=example("Agent"))
    principal.agents.get("agt_../../admin?x=1")
    assert route.calls.last.request.url.raw_path == b"/v1/agents/agt_..%2F..%2Fadmin%3Fx%3D1"
    with pytest.raises(ValueError, match="missing path parameter"):
        principal.agents.get("")


def test_errors_carry_the_response(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get("/v1/orgs/me").respond(401, json={"code": "unauthorized", "detail": "Bad key"})
    with pytest.raises(AgentBankError) as excinfo:
        principal.orgs.me()
    assert excinfo.value.status == 401
    assert excinfo.value.response is not None
    assert excinfo.value.response.status_code == 401


def test_rate_limit_error_after_exhaustion(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get("/v1/orgs/me").respond(429, json={"code": "rate_limited"})
    with pytest.raises(RateLimitError):
        principal.orgs.me()
