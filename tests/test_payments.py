"""The two-step payment flow, escrow/stream signing, and owner-signed helpers."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from eth_account import Account
from eth_account.messages import encode_defunct

from agentbank import (
    AgentBank,
    AgentBankError,
    AsyncAgentBank,
    BadRequestError,
    ConfigurationError,
    MainnetLockedError,
    PaymentDeniedError,
    PaymentError,
    PaymentFailedError,
    PolicyDeniedError,
    owner_payloads,
)
from agentbank.eip712 import verify_owner_authorization
from agentbank.models import Escrow, Payment, Stream
from tests.conftest import (
    ACCOUNT_ID,
    AGENT_ID,
    API_KEY,
    BASE_URL,
    ORG_ID,
    OWNER_ADDRESS,
    OWNER_KEY,
    PAYMENT_ID,
    SESSION_ADDRESS,
    SESSION_ID,
    verify_agent_request,
)
from tests.factories import SCHEMAS, build, example, id_for

HASH_1 = "0x" + "a1" * 32
HASH_2 = "0x" + "b2" * 32
PAY_TO = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
FUTURE = "2099-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"


class Clock:
    """A fake monotonic clock advanced by the (fake) sleeps."""

    def __init__(self) -> None:
        self.now = 0.0


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()

    def sleep(self: object, seconds: float) -> None:
        fake.now += seconds

    async def async_sleep(self: object, seconds: float) -> None:
        fake.now += seconds

    monkeypatch.setattr(AgentBank, "_sleep", sleep)
    monkeypatch.setattr(AsyncAgentBank, "_sleep", async_sleep)
    monkeypatch.setattr(AgentBank, "_monotonic", lambda self: fake.now)
    monkeypatch.setattr(AsyncAgentBank, "_monotonic", lambda self: fake.now)
    return fake


def signing_request(user_op_hash: str = HASH_1, **overrides: Any) -> dict[str, Any]:
    return {
        "session_id": SESSION_ID,
        "user_op_hash": user_op_hash,
        "chain_id": 84532,
        "expires_at": FUTURE,
        **overrides,
    }


def payment(
    status: str, *, amount: str = "1.00", to: str = PAY_TO, **overrides: Any
) -> dict[str, Any]:
    is_agent = to.startswith("agt_")
    counterparty = {
        "type": "agent" if is_agent else "address",
        "address": SESSION_ADDRESS if is_agent else to,
        "agent_id": to if is_agent else None,
        "x402_domain": None,
    }
    fields: dict[str, Any] = {
        "id": PAYMENT_ID,
        "account_id": ACCOUNT_ID,
        "status": status,
        "amount": {"amount": amount, "asset": "USDC"},
        "counterparty": counterparty,
        "signing_request": None,
        "owner_operation_id": None,
        "failure_reason": None,
        "decision": None,
    }
    fields.update(overrides)
    return example("Payment", **fields)


def recovered_signer(request: httpx.Request, user_op_hash: str) -> str:
    body = json.loads(request.content)
    message = encode_defunct(primitive=bytes.fromhex(user_op_hash[2:]))
    signer: str = Account.recover_message(message, signature=body["signature"])
    return signer


def sig_key(resource_id: str, user_op_hash: str) -> str:
    return f"sig_{resource_id}_{user_op_hash[2:18]}"


# --------------------------------------------------------------------- pay


def test_pay_creates_checks_signs_and_submits(agent: AgentBank, api: respx.MockRouter) -> None:
    create = api.post("/v1/payments").respond(
        201,
        json=payment("requires_signature", amount="12.50", signing_request=signing_request()),
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted", amount="12.50")
    )
    result = agent.pay(to=PAY_TO, amount="12.50", memo="dataset", idempotency_key="task-42-pay")
    assert result.status == "submitted"
    assert create.calls.last.request.headers["idempotency-key"] == "task-42-pay"
    request = submit.calls.last.request
    verify_agent_request(request)
    assert json.loads(request.content)["session_id"] == SESSION_ID
    # EIP-191 over the raw 32 bytes of user_op_hash, as the validator verifies.
    assert recovered_signer(request, HASH_1) == SESSION_ADDRESS
    assert request.headers["idempotency-key"] == sig_key(PAYMENT_ID, HASH_1)


@pytest.mark.parametrize(
    ("created", "detail"),
    [
        ({"amount": "99.00"}, "amount 99.00 != 12.50"),
        ({"to": "0x" + "55" * 20}, "counterparty address differs"),
    ],
)
def test_pay_refuses_to_sign_a_different_payment(
    agent: AgentBank, api: respx.MockRouter, created: dict[str, str], detail: str
) -> None:
    fields: dict[str, Any] = {"amount": "12.50", "to": PAY_TO, **created}
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request(), **fields)
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature")
    with pytest.raises(BadRequestError, match=detail) as excinfo:
        agent.pay(to=PAY_TO, amount="12.50")
    assert excinfo.value.code == "invalid_request"
    assert not submit.called


def test_pay_checks_agent_counterparties(agent: AgentBank, api: respx.MockRouter) -> None:
    other_agent = id_for("agt")[:-1] + "1"
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", to=other_agent, signing_request=signing_request())
    )
    with pytest.raises(BadRequestError, match="counterparty agent differs"):
        agent.pay(to=AGENT_ID, amount="1.00")


def test_pay_is_safe_to_rerun(agent: AgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted")
    )
    agent.payments.pay(to=PAY_TO, amount="1.00", idempotency_key="task-43-pay")
    agent.payments.pay(to=PAY_TO, amount="1.00", idempotency_key="task-43-pay")
    first, second = (call.request for call in submit.calls)
    assert first.headers["idempotency-key"] == second.headers["idempotency-key"]
    assert json.loads(first.content) == json.loads(second.content)


def test_pay_waits_for_settlement(agent: AgentBank, api: respx.MockRouter, clock: Clock) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(200, json=payment("submitted"))
    poll = api.get(f"/v1/payments/{PAYMENT_ID}").mock(
        side_effect=[
            httpx.Response(200, json=payment("submitted")),
            httpx.Response(200, json=payment("settled", tx_hash=HASH_2)),
        ]
    )
    settled = agent.pay(to=PAY_TO, amount="1.00", wait_for_settlement=True, poll_interval=3)
    assert settled.status == "settled"
    assert poll.call_count == 2
    assert clock.now == 3


def test_pay_through_human_approval(agent: AgentBank, api: respx.MockRouter, clock: Clock) -> None:
    api.post("/v1/payments").respond(201, json=payment("requires_approval", amount="500.00"))
    api.get(f"/v1/payments/{PAYMENT_ID}").mock(
        side_effect=[
            httpx.Response(200, json=payment("requires_approval", amount="500.00")),
            httpx.Response(
                200,
                json=payment(
                    "requires_signature", amount="500.00", signing_request=signing_request(HASH_2)
                ),
            ),
            httpx.Response(200, json=payment("settled", amount="500.00")),
        ]
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted", amount="500.00")
    )
    result = agent.pay(to=PAY_TO, amount="500.00", wait_for_approval=True, wait_for_settlement=True)
    assert result.status == "settled"
    assert recovered_signer(submit.calls.last.request, HASH_2) == SESSION_ADDRESS


def test_pending_approval_is_returned_unless_waited_for(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    api.post("/v1/payments").respond(201, json=payment("requires_approval", amount="500.00"))
    assert agent.pay(to=PAY_TO, amount="500.00").status == "requires_approval"
    # Waiting for settlement alone does not wait for a human.
    waited = agent.pay(to=PAY_TO, amount="500.00", wait_for_settlement=True)
    assert waited.status == "requires_approval"


def test_denials_raise_policy_denied(agent: AgentBank, api: respx.MockRouter) -> None:
    decision = build(SCHEMAS["PolicyDecision"], full=True)
    decision["outcome"] = "deny"
    decision["rule_hits"] = [
        {"rule": "limits.per_day", "effect": "deny", "detail": "50.00 left"},
        {"rule": "counterparties.cooldown", "effect": "info", "detail": "new payee"},
    ]
    api.post("/v1/payments").respond(201, json=payment("denied", decision=decision))
    with pytest.raises(PaymentDeniedError) as excinfo:
        agent.pay(to=PAY_TO, amount="1.00")
    error = excinfo.value
    assert isinstance(error, PolicyDeniedError)
    assert error.code == "policy_denied"
    assert "limits.per_day: 50.00 left" in error.detail
    assert "cooldown" not in error.detail
    assert error.payment.id == PAYMENT_ID
    assert error.resource is error.payment


def test_failures_raise_payment_errors(agent: AgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(201, json=payment("failed", failure_reason="reverted"))
    with pytest.raises(PaymentFailedError, match="reverted") as failed:
        agent.pay(to=PAY_TO, amount="1.00")
    assert failed.value.code == "chain_error"
    for status in ("canceled", "expired"):
        api.post("/v1/payments").respond(201, json=payment(status))
        with pytest.raises(PaymentError) as excinfo:
            agent.pay(to=PAY_TO, amount="1.00")
        assert excinfo.value.code == f"payment_{status}"
    api.post("/v1/payments").respond(
        201, json=payment("denied", failure_reason="screening: sanctioned address")
    )
    with pytest.raises(PaymentDeniedError, match="sanctioned"):
        agent.pay(to=PAY_TO, amount="1.00")


def test_cosigner_refusal_after_submission(agent: AgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(200, json=payment("denied"))
    with pytest.raises(PaymentDeniedError, match="denied"):
        agent.pay(to=PAY_TO, amount="1.00")


def test_require_owner_cannot_be_signed_by_the_agent(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", owner_operation_id=id_for("oop"))
    )
    with pytest.raises(PaymentError) as excinfo:
        agent.pay(to=PAY_TO, amount="1.00")
    assert excinfo.value.code == "requires_owner"
    api.post("/v1/payments").respond(201, json=payment("requires_signature"))
    with pytest.raises(AgentBankError) as nothing:
        agent.pay(to=PAY_TO, amount="1.00")
    assert nothing.value.code == "invalid_state"


def test_wait_for_settlement_polls_without_signing(
    agent: AgentBank, api: respx.MockRouter, clock: Clock
) -> None:
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("submitted"))
    with pytest.raises(PaymentError) as excinfo:
        agent.payments.wait_for_settlement(PAYMENT_ID, timeout=10, poll_interval=2)
    assert excinfo.value.code == "settlement_timeout"
    assert clock.now == 10
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("settled"))
    submitted = Payment.model_validate(payment("submitted"))
    assert agent.payments.wait_for_settlement(submitted).status == "settled"


def test_complete_resumes_an_existing_payment(agent: AgentBank, api: respx.MockRouter) -> None:
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(
        200, json=payment("requires_signature", signing_request=signing_request())
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted")
    )
    assert agent.payments.complete(PAYMENT_ID).status == "submitted"
    assert submit.call_count == 1


def test_same_operation_is_not_resubmitted(agent: AgentBank, api: respx.MockRouter) -> None:
    pending = payment("requires_signature", signing_request=signing_request())
    api.post("/v1/payments").respond(201, json=pending)
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(200, json=pending)
    assert agent.pay(to=PAY_TO, amount="1.00").status == "requires_signature"
    assert submit.call_count == 1


def test_signing_guards(agent: AgentBank, api: respx.MockRouter) -> None:
    other_session = payment(
        "requires_signature", signing_request=signing_request(session_id=id_for("ses")[:-1] + "1")
    )
    api.post("/v1/payments").respond(201, json=other_session)
    with pytest.raises(ConfigurationError, match="must be signed by session"):
        agent.pay(to=PAY_TO, amount="1.00")
    mainnet = payment("requires_signature", signing_request=signing_request(chain_id=8453))
    api.post("/v1/payments").respond(201, json=mainnet)
    with pytest.raises(MainnetLockedError):
        agent.pay(to=PAY_TO, amount="1.00")


def test_sign_helper(agent: AgentBank) -> None:
    pending = Payment.model_validate(
        payment("requires_signature", signing_request=signing_request())
    )
    message = encode_defunct(primitive=bytes.fromhex(HASH_1[2:]))
    signature = agent.payments.sign(pending)
    assert Account.recover_message(message, signature=signature) == SESSION_ADDRESS
    with pytest.raises(AgentBankError, match="nothing to sign"):
        agent.payments.sign(Payment.model_validate(payment("settled")))


def test_principal_clients_cannot_sign(api: respx.MockRouter) -> None:
    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as principal:
        pending = Payment.model_validate(
            payment("requires_signature", signing_request=signing_request())
        )
        with pytest.raises(ConfigurationError, match="agent credentials"):
            principal.payments.sign(pending)


@pytest.mark.parametrize(
    ("to", "expected"),
    [
        (PAY_TO, {"address": PAY_TO}),
        (AGENT_ID, {"agent_id": AGENT_ID}),
        (ACCOUNT_ID, {"account_id": ACCOUNT_ID}),
        ({"agent_id": AGENT_ID}, {"agent_id": AGENT_ID}),
    ],
)
def test_destinations(
    agent: AgentBank, api: respx.MockRouter, to: Any, expected: dict[str, str]
) -> None:
    route = api.post("/v1/payments").respond(201, json=payment("submitted"))
    agent.payments.create(amount="1.00", to=to)
    assert json.loads(route.calls.last.request.content)["to"] == expected


def test_invalid_destination_and_amounts(agent: AgentBank) -> None:
    with pytest.raises(ValueError, match="Payment destination"):
        agent.payments.create(amount="1.00", to="bob")
    with pytest.raises(AgentBankError, match="decimal strings"):
        agent.payments.create(amount=1.5, to=AGENT_ID)  # type: ignore[arg-type]


async def test_async_pay_flow(
    async_agent: AsyncAgentBank, api: respx.MockRouter, clock: Clock
) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", amount="2.00", signing_request=signing_request())
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted", amount="2.00")
    )
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("settled", amount="2.00"))
    result = await async_agent.pay(to=PAY_TO, amount="2.00", wait_for_settlement=True)
    assert result.status == "settled"
    assert recovered_signer(submit.calls.last.request, HASH_1) == SESSION_ADDRESS
    verify_agent_request(submit.calls.last.request)


async def test_async_failures(async_agent: AsyncAgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(201, json=payment("denied"))
    with pytest.raises(PaymentDeniedError):
        await async_agent.payments.pay(to=PAY_TO, amount="1.00")


# --------------------------------------------------------------------- escrows and streams

ESCROW_ID = id_for("esc")
STREAM_ID = id_for("str")


def escrow(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"id": ESCROW_ID, "status": "requires_signature"}
    fields.update(overrides)
    return example("Escrow", **fields)


def stream(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"id": STREAM_ID, "status": "requires_signature"}
    fields.update(overrides)
    return example("Stream", **fields)


def test_escrow_lock_signs_only_a_live_pending_action(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    api.post("/v1/escrows").respond(
        201, json=escrow(pending_action="lock", signing_request=signing_request())
    )
    submit = api.post(f"/v1/escrows/{ESCROW_ID}/signature").respond(
        200, json=escrow(status="locking", pending_action=None, signing_request=None)
    )
    locked = agent.escrows.lock(
        payee=AGENT_ID,
        amount="5.00",
        expires_at="2026-11-01T00:00:00Z",
        release="arbiter",
        arbiter=OWNER_ADDRESS,
    )
    assert locked.status == "locking"
    assert recovered_signer(submit.calls.last.request, HASH_1) == SESSION_ADDRESS
    assert submit.calls.last.request.headers["idempotency-key"] == sig_key(ESCROW_ID, HASH_1)

    for unsignable in (
        escrow(pending_action=None, signing_request=signing_request()),
        escrow(pending_action="lock", signing_request=signing_request(expires_at=PAST)),
        escrow(pending_action="lock", signing_request=None),
    ):
        api.post("/v1/escrows").respond(201, json=unsignable)
        assert agent.escrows.lock(payee=PAY_TO, amount="1.00", expires_at=FUTURE).id == ESCROW_ID
    assert submit.call_count == 1

    with pytest.raises(AgentBankError, match="nothing to sign"):
        agent.escrows.sign_and_submit(
            Escrow.model_validate(escrow(pending_action=None, signing_request=None))
        )
    expired = Escrow.model_validate(
        escrow(pending_action="release", signing_request=signing_request(expires_at=PAST))
    )
    with pytest.raises(AgentBankError, match=r"release operation .* expired") as excinfo:
        agent.escrows.sign_and_submit(expired)
    assert excinfo.value.code == "invalid_state"
    api.post("/v1/escrows").respond(201, json=escrow(status="failed"))
    with pytest.raises(PaymentFailedError):
        agent.escrows.lock(payee=PAY_TO, amount="1.00", expires_at=FUTURE)


def test_escrow_release_then_sign(agent: AgentBank, api: respx.MockRouter) -> None:
    api.post(f"/v1/escrows/{ESCROW_ID}/release").respond(
        200,
        json=escrow(
            status="locked", pending_action="release", signing_request=signing_request(HASH_2)
        ),
    )
    submit = api.post(f"/v1/escrows/{ESCROW_ID}/signature").respond(
        200, json=escrow(status="released", pending_action=None, signing_request=None)
    )
    pending = agent.escrows.release(ESCROW_ID)
    assert pending.pending_action == "release"
    assert agent.escrows.sign_and_submit(pending).status == "released"
    assert recovered_signer(submit.calls.last.request, HASH_2) == SESSION_ADDRESS


def test_stream_start_signs_only_a_live_pending_action(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    api.post("/v1/streams").respond(
        201, json=stream(pending_action="create", signing_request=signing_request())
    )
    submit = api.post(f"/v1/streams/{STREAM_ID}/signature").respond(
        200, json=stream(status="active", pending_action=None, signing_request=None)
    )
    started = agent.streams.start(
        payee=PAY_TO,
        amount_per_interval="0.001",
        interval_seconds=1,
        deposit="10.00",
        kind="streaming",
        settle_every_seconds=3600,
    )
    assert started.status == "active"
    body = json.loads(api.calls[0].request.content)
    assert body["payee"] == {"address": PAY_TO}
    assert body["deposit"] == {"amount": "10.00", "asset": "USDC"}
    assert recovered_signer(submit.calls.last.request, HASH_1) == SESSION_ADDRESS
    api.post("/v1/streams").respond(201, json=stream(pending_action=None, signing_request=None))
    unsigned = agent.streams.start(
        payee=AGENT_ID, amount_per_interval="1.00", interval_seconds=86_400, deposit="30.00"
    )
    assert unsigned.signing_request is None
    with pytest.raises(AgentBankError, match="nothing to sign"):
        agent.streams.sign_and_submit(Stream.model_validate(stream(pending_action=None)))
    # Example data defaults chain_id to 1 (Ethereum mainnet): the SDK refuses to sign it.
    mainnet_request = {**build(SCHEMAS["SigningRequest"]), "expires_at": FUTURE}
    mainnet = Stream.model_validate(
        stream(pending_action="cancel", signing_request=mainnet_request)
    )
    with pytest.raises(MainnetLockedError):
        agent.streams.sign_and_submit(mainnet)
    api.post("/v1/streams").respond(201, json=stream(status="failed"))
    with pytest.raises(PaymentFailedError):
        agent.streams.start(payee=PAY_TO, amount_per_interval="1", interval_seconds=1, deposit="1")


async def test_async_escrow_and_stream(async_agent: AsyncAgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/escrows").respond(
        201, json=escrow(pending_action="lock", signing_request=signing_request())
    )
    api.post(f"/v1/escrows/{ESCROW_ID}/signature").respond(200, json=escrow(status="locking"))
    api.post("/v1/streams").respond(
        201, json=stream(pending_action="create", signing_request=signing_request())
    )
    api.post(f"/v1/streams/{STREAM_ID}/signature").respond(200, json=stream(status="active"))
    locked = await async_agent.escrows.lock(payee=PAY_TO, amount="1.00", expires_at=FUTURE)
    assert locked.status == "locking"
    started = await async_agent.streams.start(
        payee=PAY_TO, amount_per_interval="0.01", interval_seconds=1, deposit="1.00"
    )
    assert started.id == STREAM_ID


# --------------------------------------------------------------------- owner-signed helpers


def mock_meta(api: respx.MockRouter, chain_id: int = 84532) -> respx.Route:
    meta = example("Meta", owner_authorization_chain_id=chain_id)
    return api.get("/v1/meta").respond(json=meta)


def _authorization(route: respx.Route) -> tuple[dict[str, Any], dict[str, Any]]:
    body = json.loads(route.calls.last.request.content)
    return body, body.pop("owner_authorization")


def _verify(
    request: owner_payloads.OwnerActionPayload,
    authorization: dict[str, Any],
    chain_id: int = 84532,
) -> None:
    verify_owner_authorization(
        owner=OWNER_ADDRESS,
        authorization=authorization,
        chain_id=chain_id,
        action=request.action,
        subject=request.subject,
        payload=request.payload,
    )


def test_owner_signed_session_grant_applies_defaults(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    meta = mock_meta(api)
    route = api.post("/v1/sessions").respond(201, json=example("Session"))
    scope = {"max_per_tx": "5.00", "max_per_day": "50.00", "expires_at": "2026-10-12T00:00:00Z"}
    principal.sessions.create(
        account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=scope, owner=OWNER_KEY
    )
    body, authorization = _authorization(route)
    # The scope's schema default (asset) is explicit: the server hashes the parsed body.
    assert body == {
        "account_id": ACCOUNT_ID,
        "public_key": SESSION_ADDRESS,
        "scope": {**scope, "asset": "USDC"},
    }
    grant = owner_payloads.session_grant(
        account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=scope
    )
    assert grant.subject == ACCOUNT_ID
    assert grant.payload == body
    _verify(grant, authorization)
    # The same normalized body is sent with a pre-signed authorization.
    principal.sessions.create(
        account_id=ACCOUNT_ID,
        public_key=SESSION_ADDRESS,
        scope=scope,
        owner_authorization=authorization,
    )
    resent = json.loads(route.calls.last.request.content)
    assert resent == {**body, "owner_authorization": authorization}
    assert meta.call_count == 1  # cached


def test_owner_chain_id_comes_from_meta(api: respx.MockRouter) -> None:
    meta = mock_meta(api, chain_id=31337)
    route = api.put(f"/v1/agents/{AGENT_ID}/policy").respond(json=example("AgentPolicy"))
    policy = {"limits": {"per_tx": "1.00"}}
    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as principal:
        assert principal.owner_authorization_chain_id() == 31337
        principal.policies.put(AGENT_ID, policy=policy, owner=OWNER_KEY)
    _, authorization = _authorization(route)
    _verify(owner_payloads.policy_loosen(AGENT_ID, policy), authorization, chain_id=31337)
    assert meta.call_count == 1
    with AgentBank(api_key=API_KEY, base_url=BASE_URL, chain_id=1337) as explicit:
        assert explicit.owner_authorization_chain_id() == 1337
    assert meta.call_count == 1
    mock_meta(api, chain_id=8453)
    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as bad:
        with pytest.raises(MainnetLockedError):
            bad.policies.put(AGENT_ID, policy={}, owner=OWNER_KEY)


def test_owner_signed_mandate_and_policy(principal: AgentBank, api: respx.MockRouter) -> None:
    mock_meta(api)
    mandate = {
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "agentbank.x402_domains", "allowed": ["api.example-data.com"]}],
        "iat": 1_790_000_000,
        "exp": 1_790_086_400,
        "agent_id": AGENT_ID,
    }
    mandates = api.post("/v1/mandates").respond(201, json=example("Mandate"))
    principal.mandates.create(agent_id=AGENT_ID, mandate=mandate, owner=OWNER_KEY)
    body, authorization = _authorization(mandates)
    _verify(owner_payloads.mandate_issue(AGENT_ID, mandate), authorization)
    assert body["mandate"] == mandate

    policy = {
        "limits": {"per_day": "500.00"},
        "time_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
    }
    policies = api.put(f"/v1/agents/{AGENT_ID}/policy").respond(json=example("AgentPolicy"))
    principal.policies.put(AGENT_ID, policy=policy, owner=OWNER_KEY)
    body, authorization = _authorization(policies)
    assert body["policy"] == {
        "asset": "USDC",
        "counterparties": {"mode": "open"},
        "limits": {"per_day": "500.00"},
        "time_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00", "timezone": "UTC"}],
    }
    _verify(owner_payloads.policy_loosen(AGENT_ID, policy), authorization)


def test_owner_signed_unfreeze_treasury_and_vault(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    mock_meta(api)
    api.get("/v1/orgs/me").respond(json=example("Org", id=ORG_ID))
    org_unfreeze = api.post("/v1/orgs/me/unfreeze").respond(json=example("Org"))
    principal.orgs.unfreeze(reason="resolved", owner=OWNER_KEY)
    _, authorization = _authorization(org_unfreeze)
    _verify(owner_payloads.org_unfreeze(ORG_ID, "resolved"), authorization)

    agent_unfreeze = api.post(f"/v1/agents/{AGENT_ID}/unfreeze").respond(json=example("Agent"))
    principal.agents.unfreeze(AGENT_ID, reason="fixed", owner=OWNER_KEY)
    _, authorization = _authorization(agent_unfreeze)
    _verify(owner_payloads.agent_unfreeze(AGENT_ID, "fixed"), authorization)

    treasury = api.put("/v1/orgs/me/treasury").respond(json=example("Org"))
    principal.treasury.set(account_id=ACCOUNT_ID, owner=OWNER_KEY)
    _, authorization = _authorization(treasury)
    _verify(owner_payloads.treasury_set(ORG_ID, ACCOUNT_ID), authorization)

    topup = api.put(f"/v1/agents/{AGENT_ID}/auto-topup").respond(json=example("AutoTopUpRule"))
    principal.treasury.put_auto_topup(
        AGENT_ID, refill_to="50.00", when_below="10.00", max_per_day="100.00", owner=OWNER_KEY
    )
    body, authorization = _authorization(topup)
    rule = owner_payloads.topup_set(
        AGENT_ID, refill_to="50.00", when_below="10.00", max_per_day="100.00"
    )
    assert body == rule.payload
    _verify(rule, authorization)

    sweep = api.put(f"/v1/accounts/{ACCOUNT_ID}/sweep-rule").respond(json=example("SweepRule"))
    fund = id_for("fnd")
    principal.treasury.put_sweep_rule(
        ACCOUNT_ID, fund_id=fund, threshold="1000.00", max_share_bps=2500, owner=OWNER_KEY
    )
    body, authorization = _authorization(sweep)
    sweep_rule = owner_payloads.sweep_set(
        ACCOUNT_ID, fund_id=fund, threshold="1000.00", max_share_bps=2500
    )
    assert body == sweep_rule.payload
    _verify(sweep_rule, authorization)

    # A vault that withdraws at once needs no owner signature; early withdrawals
    # from locked vaults answer the API's challenge (tests/test_early_withdrawal.py).
    vault_id = id_for("vlt")
    withdraw = api.post(f"/v1/vaults/{vault_id}/withdraw").respond(json=example("Vault"))
    principal.vaults.withdraw(vault_id, amount="5.00", owner=OWNER_KEY)
    assert json.loads(withdraw.calls.last.request.content) == {
        "amount": {"amount": "5.00", "asset": "USDC"}
    }


def test_owner_operation_sign_and_submit(principal: AgentBank, api: respx.MockRouter) -> None:
    operation_id = id_for("oop")
    pending = example(
        "OwnerOperation",
        id=operation_id,
        user_op_hash=HASH_2,
        status="requires_signature",
        chain_id=84532,
    )
    api.get(f"/v1/owner-operations/{operation_id}").respond(json=pending)
    submit = api.post(f"/v1/owner-operations/{operation_id}/signature").respond(
        json={**pending, "status": "submitted"}
    )
    result = principal.owner_operations.sign_and_submit(operation_id, owner=OWNER_KEY)
    assert result.status == "submitted"
    request = submit.calls.last.request
    assert recovered_signer(request, HASH_2) == OWNER_ADDRESS
    assert request.headers["idempotency-key"] == f"oop_sig_{operation_id}_{HASH_2[2:18]}"
    api.get(f"/v1/owner-operations/{operation_id}").respond(json={**pending, "status": "succeeded"})
    done = principal.owner_operations.sign_and_submit(operation_id, owner=OWNER_KEY)
    assert done.status == "succeeded"
    assert submit.call_count == 1
    api.get(f"/v1/owner-operations/{operation_id}").respond(json={**pending, "chain_id": 8453})
    with pytest.raises(MainnetLockedError):
        principal.owner_operations.sign_and_submit(operation_id, owner=OWNER_KEY)


def test_policy_check_accepts_models(agent: AgentBank, api: respx.MockRouter) -> None:
    from agentbank.models import PaymentIntent

    route = api.post("/v1/policy/check").respond(json=build(SCHEMAS["PolicyDecision"]))
    intent = PaymentIntent.model_validate(
        {
            "kind": "x402",
            "amount": {"amount": "0.01", "asset": "USDC"},
            "x402_domain": "api.example-data.com",
        }
    )
    agent.policies.check(intent=intent)
    assert json.loads(route.calls.last.request.content)["intent"] == {
        "amount": {"amount": "0.01", "asset": "USDC"},
        "kind": "x402",
        "x402_domain": "api.example-data.com",
    }
