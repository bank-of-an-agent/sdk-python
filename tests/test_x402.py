"""x402: protocol functions and the paying transport end to end.

The end-to-end tests run a mocked seller and a mocked Agent Bank API. The
seller verifies the payment header independently: it decodes the
``PaymentPayload`` and recovers the EIP-3009 signer from the typed data.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils.crypto import keccak

from agentbank import (
    AgentBank,
    AsyncAgentBank,
    ConfigurationError,
    X402Error,
    X402Transport,
    x402_receipt,
)
from agentbank.eip712 import transfer_with_authorization_typed_data
from agentbank.models import X402PayResponse
from agentbank.x402 import (
    PaymentRequired,
    SelectedRequirement,
    build_payment_header,
    decode_header,
    decode_payment_response,
    encode_header,
    parse_payment_required,
    select_requirement,
)
from tests.conftest import (
    ACCOUNT_ID,
    BASE_URL,
    SESSION_ID,
    SESSION_KEY,
    SPEND_ADDRESS,
    SPEND_KEY,
    verify_agent_request,
)
from tests.factories import example, id_for

USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PAY_TO = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
SELLER = "https://api.example-data.com"
RESOURCE_URL = f"{SELLER}/v1/report?ticker=ACME"
X402_PAYMENT_ID = id_for("pay")
NONCE = "0x" + keccak(text=X402_PAYMENT_ID).hex()
SPEND = Account.from_key(SPEND_KEY)

REQUIREMENT_V2: dict[str, Any] = {
    "scheme": "exact",
    "network": "eip155:84532",
    "asset": USDC,
    "amount": "10000",
    "payTo": PAY_TO,
    "maxTimeoutSeconds": 60,
    "extra": {"name": "USDC", "version": "2"},
}
REQUIREMENT_V1: dict[str, Any] = {
    "scheme": "exact",
    "network": "base-sepolia",
    "maxAmountRequired": "10000",
    "resource": RESOURCE_URL,
    "description": "Daily report",
    "mimeType": "application/json",
    "payTo": PAY_TO,
    "maxTimeoutSeconds": 60,
    "asset": USDC,
    "extra": {"name": "USDC", "version": "2"},
}
RESOURCE_INFO = {"url": RESOURCE_URL, "description": "Daily report", "mimeType": "application/json"}


def payment_required_v2(*accepts: dict[str, Any]) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": RESOURCE_INFO,
        "accepts": list(accepts or (REQUIREMENT_V2,)),
    }


def pay_response(**authorization_overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    authorization = {
        "from": SPEND_ADDRESS,
        "to": PAY_TO,
        "value": "10000",
        "validAfter": "0",
        "validBefore": str(now + 60),
        "nonce": NONCE,
        **authorization_overrides,
    }
    return {
        "object": "x402_authorization",
        "payment": example("Payment", id=X402_PAYMENT_ID, kind="x402", status="requires_signature"),
        "authorization": authorization,
        "eip712_domain": {
            "name": "USDC",
            "version": "2",
            "chainId": 84532,
            "verifyingContract": USDC,
        },
    }


def recover_payer(payload: dict[str, Any], domain: dict[str, Any]) -> str:
    inner = payload["payload"]
    typed = transfer_with_authorization_typed_data(domain, inner["authorization"])
    signer: str = Account.recover_message(
        encode_typed_data(full_message=typed), signature=inner["signature"]
    )
    return signer


DOMAIN = {"name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": USDC}


# --------------------------------------------------------------------- encoding and parsing


def test_header_encoding_round_trip() -> None:
    value = {"x402Version": 2, "note": "ü"}
    assert decode_header(encode_header(value)) == value
    urlsafe = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    assert decode_header(urlsafe) == value
    for garbage in (
        "not base64!!",
        base64.b64encode(b"[1,2]").decode(),
        base64.b64encode(b"{").decode(),
    ):
        with pytest.raises(X402Error) as excinfo:
            decode_header(garbage)
        assert excinfo.value.code == "x402_invalid_challenge"


def test_parse_v2_header_v1_body_and_v2_body() -> None:
    v2 = parse_payment_required({"Payment-Required": encode_header(payment_required_v2())}, b"")
    assert v2.x402_version == 2
    assert v2.accepts == (REQUIREMENT_V2,)
    assert v2.resource == RESOURCE_INFO
    assert v2.error is not None
    v1 = parse_payment_required(
        {},
        json.dumps(
            {"x402Version": 1, "error": "X-PAYMENT header is required", "accepts": [REQUIREMENT_V1]}
        ),
    )
    assert v1.x402_version == 1
    assert v1.resource is None
    body_v2 = parse_payment_required({}, json.dumps(payment_required_v2()).encode())
    assert body_v2.x402_version == 2


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<html>pay me</html>",
        b"[]",
        json.dumps({"x402Version": 3, "accepts": []}).encode(),
        json.dumps({"x402Version": True, "accepts": []}).encode(),
        json.dumps({"x402Version": 2, "accepts": "exact"}).encode(),
        json.dumps({"x402Version": 2, "accepts": ["exact"]}).encode(),
    ],
)
def test_invalid_challenges(body: bytes) -> None:
    with pytest.raises(X402Error) as excinfo:
        parse_payment_required({}, body)
    assert excinfo.value.code == "x402_invalid_challenge"


# --------------------------------------------------------------------- selection


def challenge(*accepts: dict[str, Any], version: int = 2) -> PaymentRequired:
    return PaymentRequired(
        x402_version=version,
        accepts=accepts,
        resource=RESOURCE_INFO if version == 2 else None,
    )


def test_selects_first_affordable_requirement() -> None:
    expensive = {**REQUIREMENT_V2, "amount": "5000000", "payTo": "0x" + "11" * 20}
    selected = select_requirement(
        challenge(expensive, REQUIREMENT_V2), request_url=RESOURCE_URL, max_amount=100_000
    )
    assert selected.amount == 10_000
    assert selected.pay_to == PAY_TO
    assert selected.accepted == REQUIREMENT_V2
    assert selected.requirements == {**REQUIREMENT_V2}
    assert selected.resource == RESOURCE_INFO
    assert selected.payload_resource == RESOURCE_INFO
    assert selected.chain.id == 84532


def test_resource_url_is_the_url_actually_requested() -> None:
    lying = PaymentRequired(
        x402_version=2,
        accepts=(REQUIREMENT_V2,),
        resource={"url": "https://allowlisted.example/report"},
    )
    selected = select_requirement(lying, request_url=RESOURCE_URL, max_amount=10_000)
    assert selected.resource["url"] == RESOURCE_URL
    assert selected.payload_resource == {"url": "https://allowlisted.example/report"}


def test_v1_requirements_are_normalized_to_v2() -> None:
    selected = select_requirement(
        challenge(REQUIREMENT_V1, version=1), request_url=RESOURCE_URL, max_amount=10_000
    )
    assert selected.requirements == {
        "scheme": "exact",
        "network": "eip155:84532",
        "asset": USDC,
        "amount": "10000",
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }
    assert selected.network == "base-sepolia"
    assert selected.resource == {
        "url": RESOURCE_URL,
        "description": "Daily report",
        "mimeType": "application/json",
    }


def test_amount_guard() -> None:
    with pytest.raises(X402Error) as excinfo:
        select_requirement(challenge(REQUIREMENT_V2), request_url=RESOURCE_URL, max_amount=9_999)
    assert excinfo.value.code == "x402_amount_exceeds_limit"
    assert "0.01 USDC" in excinfo.value.detail
    assert "0.009999 USDC" in excinfo.value.detail


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"scheme": "upto"}, "only 'exact'"),
        ({"network": "eip155:8453"}, "mainnet"),
        ({"network": "base"}, "mainnet"),
        ({"network": "solana-devnet"}, "Unknown network"),
        ({"network": None}, "missing network"),
        ({"asset": "0x" + "22" * 20}, "is not USDC"),
        ({"amount": "0"}, "invalid amount"),
        ({"amount": "1.5"}, "invalid amount"),
        ({"payTo": "nobody"}, "invalid payTo"),
        ({"maxTimeoutSeconds": 0}, "invalid maxTimeoutSeconds"),
        ({"maxTimeoutSeconds": True}, "invalid maxTimeoutSeconds"),
    ],
)
def test_unsupported_requirements(override: dict[str, Any], reason: str) -> None:
    with pytest.raises(X402Error, match=reason) as excinfo:
        select_requirement(
            challenge({**REQUIREMENT_V2, **override}), request_url=RESOURCE_URL, max_amount=10**12
        )
    assert excinfo.value.code == "x402_unsupported"


def test_empty_challenge_and_domain_allowlist() -> None:
    with pytest.raises(X402Error, match="no payment options"):
        select_requirement(challenge(), request_url=RESOURCE_URL, max_amount=1)
    with pytest.raises(X402Error) as excinfo:
        select_requirement(
            challenge(REQUIREMENT_V2),
            request_url=RESOURCE_URL,
            max_amount=10_000,
            allowed_domains=["other.example"],
        )
    assert excinfo.value.code == "x402_domain_not_allowed"
    allowed = select_requirement(
        challenge(REQUIREMENT_V2),
        request_url=RESOURCE_URL,
        max_amount=10_000,
        allowed_domains=["API.Example-Data.com"],
    )
    assert allowed.amount == 10_000


# --------------------------------------------------------------------- authorization checks


def selected_v2() -> SelectedRequirement:
    return select_requirement(
        challenge(REQUIREMENT_V2), request_url=RESOURCE_URL, max_amount=10_000
    )


def test_builds_and_signs_v2_payment_payload() -> None:
    header = build_payment_header(
        selected_v2(), X402PayResponse.model_validate(pay_response()), SPEND
    )
    assert header.name == "PAYMENT-SIGNATURE"
    payload = decode_header(header.value)
    assert payload == header.payload
    assert payload["x402Version"] == 2
    assert payload["resource"] == RESOURCE_INFO
    assert payload["accepted"] == REQUIREMENT_V2
    assert payload["payload"]["authorization"]["from"] == SPEND_ADDRESS
    assert payload["payload"]["authorization"]["value"] == "10000"
    assert recover_payer(payload, DOMAIN) == SPEND_ADDRESS


def test_builds_v1_payment_payload() -> None:
    selected = select_requirement(
        challenge(REQUIREMENT_V1, version=1), request_url=RESOURCE_URL, max_amount=10_000
    )
    header = build_payment_header(selected, X402PayResponse.model_validate(pay_response()), SPEND)
    assert header.name == "X-PAYMENT"
    payload = decode_header(header.value)
    assert set(payload) == {"x402Version", "scheme", "network", "payload"}
    assert payload["network"] == "base-sepolia"
    assert recover_payer(payload, DOMAIN) == SPEND_ADDRESS


def test_no_signature_without_an_authorization() -> None:
    response = pay_response()
    response["authorization"] = None
    response["payment"]["status"] = "requires_approval"
    with pytest.raises(X402Error) as excinfo:
        build_payment_header(selected_v2(), X402PayResponse.model_validate(response), SPEND)
    assert excinfo.value.code == "x402_not_authorized"
    assert excinfo.value.payment.status == "requires_approval"


@pytest.mark.parametrize(
    ("authorization", "domain", "reason"),
    [
        ({"from": PAY_TO}, {}, "spend key"),
        ({"to": SPEND_ADDRESS}, {}, "different address"),
        ({"value": "10001"}, {}, "amount differs"),
        ({}, {"verifyingContract": "0x" + "33" * 20}, "different token"),
        ({}, {"chainId": 31337}, "different chain"),
        ({}, {"name": "USD Coin"}, "EIP-712 name"),
        ({}, {"version": "1"}, "EIP-712 version"),
        ({"nonce": "0x1234"}, {}, "32 bytes"),
        ({"validBefore": "1000"}, {}, "expired"),
        ({"validBefore": str(int(time.time()) + 86_400)}, {}, "longer than"),
        ({"validAfter": str(int(time.time()) + 86_400)}, {}, "not valid yet"),
    ],
)
def test_mismatched_authorizations_are_never_signed(
    authorization: dict[str, Any], domain: dict[str, Any], reason: str
) -> None:
    response = pay_response()
    response["eip712_domain"].update(domain)
    model = X402PayResponse.model_validate(response)
    assert model.authorization is not None
    for key, value in authorization.items():
        # Assigned after validation: the client must not rely on response
        # validation alone before signing with the spend key.
        setattr(model.authorization, "from_" if key == "from" else key, value)
    with pytest.raises(X402Error, match=reason) as excinfo:
        build_payment_header(selected_v2(), model, SPEND)
    assert excinfo.value.code == "x402_authorization_mismatch"


def test_decode_payment_response() -> None:
    settlement = {"success": True, "transaction": "0x" + "ab" * 32, "network": "eip155:84532"}
    assert decode_payment_response({"PAYMENT-RESPONSE": encode_header(settlement)}) == settlement
    assert decode_payment_response({"x-payment-response": encode_header(settlement)}) == settlement
    assert decode_payment_response({"PAYMENT-RESPONSE": "%%%"}) is None
    assert decode_payment_response({}) is None
    assert x402_receipt(object()) is None


# --------------------------------------------------------------------- end to end


class Seller:
    """A mocked x402 seller that verifies payments like a facilitator would."""

    def __init__(self, version: int = 2) -> None:
        self.version = version
        self.payloads: list[dict[str, Any]] = []
        self.bodies: list[bytes] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(request.content)
        header = request.headers.get("payment-signature" if self.version == 2 else "x-payment")
        if header is None:
            if self.version == 2:
                return httpx.Response(
                    402, headers={"PAYMENT-REQUIRED": encode_header(payment_required_v2())}
                )
            return httpx.Response(
                402,
                json={
                    "x402Version": 1,
                    "error": "X-PAYMENT header is required",
                    "accepts": [REQUIREMENT_V1],
                },
            )
        payload = decode_header(header)
        self.payloads.append(payload)
        assert recover_payer(payload, DOMAIN) == SPEND_ADDRESS
        settlement = {
            "success": True,
            "transaction": "0x" + "cd" * 32,
            "network": "eip155:84532",
            "payer": SPEND_ADDRESS,
        }
        name = "PAYMENT-RESPONSE" if self.version == 2 else "X-PAYMENT-RESPONSE"
        return httpx.Response(200, json={"report": "ok"}, headers={name: encode_header(settlement)})


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as mock:
        yield mock


def mock_api(router: respx.MockRouter) -> respx.Route:
    def pay(request: httpx.Request) -> httpx.Response:
        verify_agent_request(request)
        body = json.loads(request.content)
        assert body["account_id"] == ACCOUNT_ID
        assert body["resource"]["url"] == RESOURCE_URL
        assert body["requirements"]["network"] == "eip155:84532"
        assert body["requirements"]["amount"] == "10000"
        return httpx.Response(200, json=pay_response())

    return router.post(f"{BASE_URL}/v1/x402/pay").mock(side_effect=pay)


@pytest.mark.parametrize("version", [2, 1])
def test_transport_pays_and_retries(
    router: respx.MockRouter, agent: AgentBank, version: int
) -> None:
    seller = Seller(version)
    resource = router.get(RESOURCE_URL).mock(side_effect=seller)
    api = mock_api(router)
    with agent.x402.client(max_amount="0.05") as http:
        response = http.get(RESOURCE_URL)
    assert response.status_code == 200
    assert response.json() == {"report": "ok"}
    assert resource.call_count == 2
    assert api.call_count == 1
    assert api.calls.last.request.headers["idempotency-key"]
    receipt = x402_receipt(response)
    assert receipt is not None
    assert receipt.payment.id == X402_PAYMENT_ID
    assert receipt.requirement.amount == 10_000
    assert receipt.settlement is not None
    assert receipt.settlement["success"] is True
    assert seller.payloads[0]["x402Version"] == version


def test_transport_replays_request_bodies(router: respx.MockRouter, agent: AgentBank) -> None:
    seller = Seller()
    router.post(RESOURCE_URL).mock(side_effect=seller)
    mock_api(router)
    with agent.x402.client(max_amount="0.05", headers={"X-Seller-Key": "k"}) as http:
        response = http.post(RESOURCE_URL, json={"query": "ACME"})
    assert response.status_code == 200
    assert seller.bodies[0] == seller.bodies[1] == b'{"query":"ACME"}'


def test_transport_passes_through_non_402(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(f"{SELLER}/free").respond(200, json={"free": True})
    api = mock_api(router)
    with agent.x402.client(max_amount="0.05") as http:
        response = http.get(f"{SELLER}/free")
    assert response.json() == {"free": True}
    assert x402_receipt(response) is None
    assert api.call_count == 0


def test_transport_never_pays_twice(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(RESOURCE_URL).respond(
        402, headers={"PAYMENT-REQUIRED": encode_header(payment_required_v2())}
    )
    api = mock_api(router)
    with agent.x402.client(max_amount="0.05") as http:
        response = http.get(RESOURCE_URL, headers={"PAYMENT-SIGNATURE": "already-paid"})
    assert response.status_code == 402
    assert api.call_count == 0


def test_guards_run_before_asking_agent_bank(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    api = mock_api(router)
    with agent.x402.client(max_amount="0.005") as http, pytest.raises(X402Error) as over:
        http.get(RESOURCE_URL)
    assert over.value.code == "x402_amount_exceeds_limit"
    with agent.x402.client(max_amount="1.00", allowed_domains=["trusted.example"]) as http:
        with pytest.raises(X402Error) as domain:
            http.get(RESOURCE_URL)
    assert domain.value.code == "x402_domain_not_allowed"
    assert api.call_count == 0


def test_policy_refusal_is_reported(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    refused = pay_response()
    refused["authorization"] = None
    refused["payment"]["status"] = "denied"
    router.post(f"{BASE_URL}/v1/x402/pay").respond(200, json=refused)
    with pytest.raises(X402Error) as excinfo:
        agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert excinfo.value.code == "x402_not_authorized"


def test_fetch_helper(router: respx.MockRouter, agent: AgentBank) -> None:
    seller = Seller()
    router.get(RESOURCE_URL).mock(side_effect=seller)
    mock_api(router)
    response = agent.x402.fetch(RESOURCE_URL, max_amount="0.05", mandate_id=id_for("mdt"))
    assert response.status_code == 200
    receipt = x402_receipt(response)
    assert receipt is not None
    assert receipt.header.name == "PAYMENT-SIGNATURE"


def test_transport_configuration_errors() -> None:
    with AgentBank(
        session_id=SESSION_ID, session_key=SESSION_KEY, account_id=ACCOUNT_ID, base_url=BASE_URL
    ) as no_spend_key:
        with pytest.raises(ConfigurationError, match="spend key"):
            no_spend_key.x402.transport(max_amount="0.10")
        transport = no_spend_key.x402.transport(max_amount="0.10", spend_key=SPEND_KEY)
        assert isinstance(transport, X402Transport)
    with AgentBank(
        session_id=SESSION_ID, session_key=SESSION_KEY, spend_key=SPEND_KEY, base_url=BASE_URL
    ) as no_account:
        with pytest.raises(ConfigurationError, match="account_id"):
            no_account.x402.transport(max_amount="0.10")
    with (
        AgentBank(
            session_id=SESSION_ID,
            session_key=SESSION_KEY,
            spend_key=SPEND_KEY,
            account_id=ACCOUNT_ID,
        ) as bank,
        pytest.raises(Exception, match="decimal strings"),
    ):
        bank.x402.transport(max_amount=0.1)  # type: ignore[arg-type]


async def test_async_transport_pays_and_retries(
    router: respx.MockRouter, async_agent: AsyncAgentBank
) -> None:
    seller = Seller()
    router.get(RESOURCE_URL).mock(side_effect=seller)
    api = mock_api(router)
    async with async_agent.x402.client(max_amount="0.05") as http:
        response = await http.get(RESOURCE_URL)
        free = router.get(f"{SELLER}/free").respond(200, json={})
        assert (await http.get(f"{SELLER}/free")).status_code == 200
        assert free.called
    assert response.status_code == 200
    assert api.call_count == 1
    receipt = x402_receipt(response)
    assert receipt is not None
    assert receipt.settlement is not None
    fetched = await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert fetched.status_code == 200
    assert api.call_count == 2


async def test_async_transport_guards(
    router: respx.MockRouter, async_agent: AsyncAgentBank
) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    api = mock_api(router)
    with pytest.raises(X402Error):
        await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.001")
    async with AsyncAgentBank(
        session_id=SESSION_ID, session_key=SESSION_KEY, base_url=BASE_URL
    ) as bank:
        with pytest.raises(ConfigurationError):
            bank.x402.transport(max_amount="1.00")
    assert api.call_count == 0
