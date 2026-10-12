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
    AgentBankError,
    AsyncAgentBank,
    ConfigurationError,
    MainnetLockedError,
    PaymentDeniedError,
    X402Error,
    X402Receipt,
    X402Transport,
    x402_receipt,
)
from agentbank.chains import USDC as USDC_REGISTRY
from agentbank.eip712 import transfer_with_authorization_typed_data
from agentbank.models import Meta, X402PayResponse
from agentbank.x402 import (
    PaymentRequired,
    SelectedRequirement,
    X402Settings,
    build_payment_header,
    decode_header,
    decode_payment_response,
    encode_header,
    parse_payment_required,
    rejection_reason,
    select_requirement,
    x402_settings_from_meta,
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
SIMULATED_USDC = "0x5dc0000000000000000000000000000000005dc0"
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
DOMAIN = {"name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": USDC}

#: A seller on the simulated chain the local sandbox runs (eip155:1337).
SIMULATED_REQUIREMENT = {**REQUIREMENT_V2, "network": "eip155:1337", "asset": SIMULATED_USDC}
SIMULATED_DOMAIN = {**DOMAIN, "chainId": 1337, "verifyingContract": SIMULATED_USDC}
#: A MockUSDC deployed on Anvil: not in the SDK's USDC registry.
ANVIL_USDC = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ANVIL_REQUIREMENT = {**REQUIREMENT_V2, "network": "eip155:31337", "asset": ANVIL_USDC}
ANVIL_DOMAIN = {**DOMAIN, "chainId": 31337, "verifyingContract": ANVIL_USDC}


def meta_response(
    *,
    chain: str = "base-sepolia",
    chain_id: int = 84532,
    caip2: str | None = None,
    usdc: str = USDC,
    name: str = "USDC",
    version: str = "2",
) -> dict[str, Any]:
    """``GET /v1/meta`` of a deployment."""
    return example(
        "Meta",
        chain=chain,
        chain_id=chain_id,
        caip2=caip2 or f"eip155:{chain_id}",
        owner_authorization_chain_id=chain_id,
        usdc={"address": usdc, "decimals": 6, "eip712_name": name, "eip712_version": version},
    )


SIMULATED_META = meta_response(chain="simulated", chain_id=1337, usdc=SIMULATED_USDC)


def payment_required_v2(*accepts: dict[str, Any]) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": RESOURCE_INFO,
        "accepts": list(accepts or (REQUIREMENT_V2,)),
    }


def pay_response(
    status: str = "requires_signature",
    *,
    domain: dict[str, Any] | None = None,
    **authorization_overrides: Any,
) -> dict[str, Any]:
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
        "payment": example(
            "Payment", id=X402_PAYMENT_ID, kind="x402", status=status, decision=None
        ),
        "authorization": authorization,
        "eip712_domain": dict(domain or DOMAIN),
    }


def recover_payer(payload: dict[str, Any], domain: dict[str, Any]) -> str:
    inner = payload["payload"]
    typed = transfer_with_authorization_typed_data(domain, inner["authorization"])
    signer: str = Account.recover_message(
        encode_typed_data(full_message=typed), signature=inner["signature"]
    )
    return signer


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
        assert excinfo.value.reason == "invalid_challenge"
        assert excinfo.value.code == "invalid_request"


def test_parse_v2_header_v1_body_and_v2_body() -> None:
    v2 = parse_payment_required({"Payment-Required": encode_header(payment_required_v2())}, b"")
    assert v2.x402_version == 2
    assert v2.accepts == (REQUIREMENT_V2,)
    assert v2.resource == RESOURCE_INFO
    assert v2.error is not None
    v1_body = {
        "x402Version": 1,
        "error": "X-PAYMENT header is required",
        "accepts": [REQUIREMENT_V1],
    }
    v1 = parse_payment_required({}, json.dumps(v1_body))
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
    assert excinfo.value.reason == "invalid_challenge"


# --------------------------------------------------------------------- selection


def challenge(*accepts: dict[str, Any], version: int = 2) -> PaymentRequired:
    return PaymentRequired(
        x402_version=version,
        accepts=accepts,
        resource=RESOURCE_INFO if version == 2 else None,
    )


def test_selects_the_cheapest_acceptable_requirement() -> None:
    expensive = {**REQUIREMENT_V2, "amount": "5000000", "payTo": "0x" + "11" * 20}
    cheaper = {**REQUIREMENT_V2, "amount": "9000", "payTo": "0x" + "22" * 20}
    tie = {**REQUIREMENT_V2, "amount": "9000", "payTo": "0x" + "33" * 20}
    selected = select_requirement(
        challenge(expensive, REQUIREMENT_V2, cheaper, tie),
        request_url=RESOURCE_URL,
        max_amount=100_000,
    )
    assert selected.amount == 9_000
    assert selected.pay_to == cheaper["payTo"]  # ties keep the seller's order
    assert selected.accepted == cheaper
    assert selected.requirements == cheaper
    assert selected.resource == RESOURCE_INFO
    assert selected.payload_resource == RESOURCE_INFO
    assert selected.chain.id == 84532


def test_resource_url_is_the_url_actually_requested() -> None:
    lying = PaymentRequired(
        x402_version=2,
        accepts=(REQUIREMENT_V2,),
        resource={"url": "https://allowlisted.example/report", "extra": "dropped"},
    )
    selected = select_requirement(lying, request_url=RESOURCE_URL, max_amount=10_000)
    assert selected.resource == {"url": RESOURCE_URL}
    assert selected.payload_resource == {
        "url": "https://allowlisted.example/report",
        "extra": "dropped",
    }


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
    assert selected.resource == RESOURCE_INFO


def test_amount_guard() -> None:
    with pytest.raises(X402Error) as excinfo:
        select_requirement(challenge(REQUIREMENT_V2), request_url=RESOURCE_URL, max_amount=9_999)
    assert excinfo.value.reason == "amount_exceeds_limit"
    assert excinfo.value.code == "policy_denied"
    assert "Price 0.01 USDC exceeds max_amount 0.009999 USDC" in excinfo.value.detail


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"scheme": "upto"}, "only 'exact'"),
        ({"network": "eip155:8453"}, "mainnet"),
        ({"network": "base"}, "mainnet"),
        ({"network": "eip155:31337"}, "is not eip155:84532"),
        ({"network": "solana-devnet"}, "Unknown network"),
        ({"network": None}, "missing network"),
        ({"asset": "0x" + "22" * 20}, "is not USDC"),
        ({"asset": None}, "asset None is not USDC"),
        ({"extra": {"assetTransferMethod": "permit2"}}, "transfer method"),
        ({"amount": "0"}, "invalid amount"),
        ({"amount": "1.5"}, "invalid amount"),
        ({"payTo": "nobody"}, "invalid payTo"),
        ({"maxTimeoutSeconds": 0}, "invalid maxTimeoutSeconds"),
        ({"maxTimeoutSeconds": True}, "invalid maxTimeoutSeconds"),
    ],
)
def test_unacceptable_requirements(override: dict[str, Any], reason: str) -> None:
    with pytest.raises(X402Error, match=reason) as excinfo:
        select_requirement(
            challenge({**REQUIREMENT_V2, **override}), request_url=RESOURCE_URL, max_amount=10**12
        )
    assert excinfo.value.reason == "no_acceptable_requirement"


def test_transfer_methods_and_other_networks() -> None:
    for method in ("eip3009", "default"):
        offered = {**REQUIREMENT_V2, "extra": {"assetTransferMethod": method}}
        selected = select_requirement(
            challenge(offered), request_url=RESOURCE_URL, max_amount=10**6
        )
        assert selected.amount == 10_000
    simulated = {**REQUIREMENT_V2, "network": "eip155:1337", "asset": SIMULATED_USDC}
    picked = select_requirement(
        challenge(REQUIREMENT_V2, simulated),
        request_url=RESOURCE_URL,
        max_amount=10**6,
        network="eip155:1337",
    )
    assert picked.chain.id == 1337
    assert picked.asset.address == SIMULATED_USDC
    with pytest.raises(MainnetLockedError):
        select_requirement(
            challenge(REQUIREMENT_V2), request_url=RESOURCE_URL, max_amount=1, network="eip155:8453"
        )


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
    assert excinfo.value.reason == "domain_not_allowed"
    assert excinfo.value.code == "policy_denied"
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


def test_payment_status_is_checked_before_signing() -> None:
    denied = pay_response("denied")
    denied["authorization"] = None
    denied["eip712_domain"] = None
    with pytest.raises(PaymentDeniedError) as refused:
        build_payment_header(selected_v2(), X402PayResponse.model_validate(denied), SPEND)
    assert refused.value.code == "policy_denied"
    approval = pay_response("requires_approval")
    approval["authorization"] = None
    with pytest.raises(X402Error) as needs_human:
        build_payment_header(selected_v2(), X402PayResponse.model_validate(approval), SPEND)
    assert needs_human.value.reason == "approval_required"
    assert needs_human.value.payment.status == "requires_approval"
    missing = pay_response()
    missing["authorization"] = None
    with pytest.raises(X402Error) as unexpected:
        build_payment_header(selected_v2(), X402PayResponse.model_validate(missing), SPEND)
    assert unexpected.value.reason == "unexpected_status"
    no_domain = pay_response()
    no_domain["eip712_domain"] = None
    with pytest.raises(X402Error, match="no authorization to sign"):
        build_payment_header(selected_v2(), X402PayResponse.model_validate(no_domain), SPEND)


@pytest.mark.parametrize(
    ("authorization", "domain", "problem"),
    [
        ({"from": PAY_TO}, {}, "from is not the spend key"),
        ({"to": SPEND_ADDRESS}, {}, "to differs from payTo"),
        ({"value": "10001"}, {}, "value differs from the price"),
        ({}, {"verifyingContract": "0x" + "33" * 20}, "verifyingContract differs"),
        ({}, {"chainId": 31337}, "chainId differs"),
        ({}, {"name": "USD Coin"}, "EIP-712 name differs"),
        ({}, {"version": "1"}, "EIP-712 version differs"),
        ({"nonce": "0x1234"}, {}, "nonce is not 32 bytes"),
        ({"validBefore": "1000"}, {}, "already expired"),
        ({"validBefore": str(int(time.time()) + 86_400)}, {}, "exceeds maxTimeoutSeconds"),
        ({"validAfter": str(int(time.time()) + 600)}, {}, "not valid yet"),
    ],
)
def test_mismatched_authorizations_are_never_signed(
    authorization: dict[str, Any], domain: dict[str, Any], problem: str
) -> None:
    response = pay_response()
    response["eip712_domain"].update(domain)
    model = X402PayResponse.model_validate(response)
    assert model.authorization is not None
    for key, value in authorization.items():
        # Assigned after validation: the client must not rely on response
        # validation alone before signing with the spend key.
        setattr(model.authorization, "from_" if key == "from" else key, value)
    with pytest.raises(X402Error, match=problem) as excinfo:
        build_payment_header(selected_v2(), model, SPEND)
    assert excinfo.value.reason == "authorization_mismatch"
    assert excinfo.value.code == "internal"
    assert excinfo.value.payment.id == X402_PAYMENT_ID


def test_all_problems_are_reported_together() -> None:
    model = X402PayResponse.model_validate(pay_response(to=SPEND_ADDRESS, value="1"))
    with pytest.raises(X402Error, match="to differs from payTo; value differs from the price"):
        build_payment_header(selected_v2(), model, SPEND)


def test_decode_payment_response_and_rejection_reasons() -> None:
    settlement = {"success": True, "transaction": "0x" + "ab" * 32, "network": "eip155:84532"}
    assert decode_payment_response({"PAYMENT-RESPONSE": encode_header(settlement)}) == settlement
    assert decode_payment_response({"x-payment-response": encode_header(settlement)}) == settlement
    assert decode_payment_response({"PAYMENT-RESPONSE": "%%%"}) is None
    assert decode_payment_response({}) is None
    assert x402_receipt(object()) is None
    failed = {
        "success": False,
        "errorReason": "insufficient_funds",
        "transaction": "",
        "network": "",
    }
    assert (
        rejection_reason({"PAYMENT-RESPONSE": encode_header(failed)}, b"") == "insufficient_funds"
    )
    challenge_again = {
        "PAYMENT-REQUIRED": encode_header({**payment_required_v2(), "error": "nonce used"})
    }
    assert rejection_reason(challenge_again, b"") == "nonce used"
    assert rejection_reason({}, b"nope") == "HTTP 402"
    assert (
        rejection_reason(
            {"PAYMENT-REQUIRED": encode_header({"x402Version": 2, "accepts": []})}, b""
        )
        == "HTTP 402"
    )


# --------------------------------------------------------------------- end to end


class Seller:
    """A mocked x402 seller that verifies payments like a facilitator would."""

    def __init__(
        self,
        version: int = 2,
        *,
        reject: bool = False,
        requirement: dict[str, Any] = REQUIREMENT_V2,
        domain: dict[str, Any] = DOMAIN,
    ) -> None:
        self.version = version
        self.reject = reject
        self.requirement = requirement
        self.domain = domain
        self.payloads: list[dict[str, Any]] = []
        self.bodies: list[bytes] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(request.content)
        header = request.headers.get("payment-signature" if self.version == 2 else "x-payment")
        if header is None:
            if self.version == 2:
                challenge = payment_required_v2(self.requirement)
                return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(challenge)})
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
        assert recover_payer(payload, self.domain) == SPEND_ADDRESS
        name = "PAYMENT-RESPONSE" if self.version == 2 else "X-PAYMENT-RESPONSE"
        if self.reject:
            failure = {
                "success": False,
                "errorReason": "authorization_used",
                "transaction": "",
                "network": self.requirement["network"],
            }
            return httpx.Response(402, headers={name: encode_header(failure)})
        settlement = {
            "success": True,
            "transaction": "0x" + "cd" * 32,
            "network": self.requirement["network"],
            "payer": SPEND_ADDRESS,
        }
        return httpx.Response(200, json={"report": "ok"}, headers={name: encode_header(settlement)})


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as mock:
        # The deployment transports pay on by default (GET /v1/meta): Base Sepolia.
        mock.get(f"{BASE_URL}/v1/meta", name="meta").respond(json=meta_response())
        yield mock


def mock_api(
    router: respx.MockRouter,
    response: dict[str, Any] | None = None,
    *,
    network: str = "eip155:84532",
) -> respx.Route:
    def pay(request: httpx.Request) -> httpx.Response:
        verify_agent_request(request)
        body = json.loads(request.content)
        assert body["account_id"] == ACCOUNT_ID
        assert body["resource"]["url"] == RESOURCE_URL
        assert body["requirements"]["network"] == network
        assert body["requirements"]["amount"] == "10000"
        return httpx.Response(200, json=response or pay_response())

    return router.post(f"{BASE_URL}/v1/x402/pay").mock(side_effect=pay)


@pytest.mark.parametrize("version", [2, 1])
def test_transport_pays_and_retries(
    router: respx.MockRouter, agent: AgentBank, version: int
) -> None:
    seller = Seller(version)
    resource = router.get(RESOURCE_URL).mock(side_effect=seller)
    api = mock_api(router)
    receipts: list[X402Receipt] = []
    with agent.x402.client(max_amount="0.05", on_payment=receipts.append) as http:
        response = http.get(RESOURCE_URL)
    assert response.status_code == 200
    assert response.json() == {"report": "ok"}
    assert resource.call_count == 2
    assert api.call_count == 1
    assert api.calls.last.request.headers["idempotency-key"]
    receipt = x402_receipt(response)
    assert receipt is not None
    assert receipts == [receipt]
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
    with agent.x402.client() as http:
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


def test_seller_rejection_is_reported(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller(reject=True))
    mock_api(router)
    receipts: list[X402Receipt] = []
    with agent.x402.client(max_amount="0.05", on_payment=receipts.append) as http:
        with pytest.raises(X402Error) as excinfo:
            http.get(RESOURCE_URL)
    error = excinfo.value
    assert error.reason == "payment_rejected"
    assert error.code == "conflict"
    assert "authorization_used" in error.detail
    assert error.payment.id == X402_PAYMENT_ID
    assert error.settlement is not None
    assert error.settlement["success"] is False
    assert error.response is not None
    assert error.response.status_code == 402
    assert receipts == []


def test_guards_run_before_asking_agent_bank(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    api = mock_api(router)
    with agent.x402.client(max_amount="0.005") as http, pytest.raises(X402Error) as over:
        http.get(RESOURCE_URL)
    assert over.value.reason == "amount_exceeds_limit"
    with agent.x402.client(max_amount="1.00", allowed_domains=["trusted.example"]) as http:
        with pytest.raises(X402Error) as domain:
            http.get(RESOURCE_URL)
    assert domain.value.reason == "domain_not_allowed"
    assert api.call_count == 0


def test_default_ceiling_is_one_usdc(router: respx.MockRouter, agent: AgentBank) -> None:
    pricey = {**REQUIREMENT_V2, "amount": "1000001"}
    router.get(RESOURCE_URL).respond(
        402, headers={"PAYMENT-REQUIRED": encode_header(payment_required_v2(pricey))}
    )
    api = mock_api(router)
    with pytest.raises(X402Error, match=r"exceeds max_amount 1\.00 USDC"):
        agent.x402.fetch(RESOURCE_URL)
    assert api.call_count == 0


def test_policy_denial_is_reported(router: respx.MockRouter, agent: AgentBank) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    refused = pay_response("denied")
    refused["authorization"] = None
    refused["eip712_domain"] = None
    mock_api(router, refused)
    with pytest.raises(PaymentDeniedError) as excinfo:
        agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert excinfo.value.code == "policy_denied"


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
        with pytest.raises(MainnetLockedError):
            no_spend_key.x402.transport(spend_key=SPEND_KEY, network="eip155:8453")
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
        pytest.raises(AgentBankError, match="decimal strings"),
    ):
        bank.x402.transport(max_amount=0.1)  # type: ignore[arg-type]


async def test_async_transport_pays_and_retries(
    router: respx.MockRouter, async_agent: AsyncAgentBank
) -> None:
    seller = Seller()
    router.get(RESOURCE_URL).mock(side_effect=seller)
    api = mock_api(router)
    receipts: list[X402Receipt] = []
    async with async_agent.x402.client(max_amount="0.05", on_payment=receipts.append) as http:
        response = await http.get(RESOURCE_URL)
        free = router.get(f"{SELLER}/free").respond(200, json={})
        assert (await http.get(f"{SELLER}/free")).status_code == 200
        assert free.called
    assert response.status_code == 200
    assert api.call_count == 1
    receipt = x402_receipt(response)
    assert receipt is not None
    assert receipts == [receipt]
    fetched = await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert fetched.status_code == 200
    assert api.call_count == 2


async def test_async_transport_guards_and_rejections(
    router: respx.MockRouter, async_agent: AsyncAgentBank
) -> None:
    router.get(RESOURCE_URL).mock(side_effect=Seller(reject=True))
    api = mock_api(router)
    with pytest.raises(X402Error) as rejected:
        await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert rejected.value.reason == "payment_rejected"
    with pytest.raises(X402Error) as over:
        await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.001")
    assert over.value.reason == "amount_exceeds_limit"
    async with AsyncAgentBank(
        session_id=SESSION_ID, session_key=SESSION_KEY, base_url=BASE_URL
    ) as bank:
        with pytest.raises(ConfigurationError):
            bank.x402.transport(max_amount="1.00")
    assert api.call_count == 1


# --------------------------------------------------------------------- network resolution


def test_settings_from_meta() -> None:
    settings = x402_settings_from_meta(Meta.model_validate(SIMULATED_META))
    assert isinstance(settings, X402Settings)
    assert settings.network == "eip155:1337"
    assert settings.chain.name == "simulated"
    assert settings.usdc.address.lower() == SIMULATED_USDC
    assert settings.usdc.address != SIMULATED_USDC  # checksummed
    assert (settings.usdc.eip712_name, settings.usdc.eip712_version) == ("USDC", "2")
    with pytest.raises(MainnetLockedError):
        x402_settings_from_meta(Meta.model_validate(meta_response(chain_id=8453)))
    inconsistent = Meta.model_validate(meta_response(chain_id=84532, caip2="eip155:1337"))
    with pytest.raises(AgentBankError, match="names network 'eip155:1337' but chain id 84532"):
        x402_settings_from_meta(inconsistent)


def test_select_requirement_with_the_deployment_usdc() -> None:
    anvil = x402_settings_from_meta(
        Meta.model_validate(meta_response(chain="anvil", chain_id=31337, usdc=ANVIL_USDC))
    )
    offered = challenge(ANVIL_REQUIREMENT, {**ANVIL_REQUIREMENT, "asset": "0x" + "77" * 20})
    picked = select_requirement(
        offered,
        request_url=RESOURCE_URL,
        max_amount=50_000,
        network=anvil.network,
        usdc=anvil.usdc,
    )
    assert picked.asset == anvil.usdc
    assert picked.requirements["network"] == "eip155:31337"
    # The registry knows no USDC on Anvil: without the deployment's, nothing is acceptable.
    with pytest.raises(X402Error, match="is not USDC on Local Anvil"):
        select_requirement(
            offered, request_url=RESOURCE_URL, max_amount=50_000, network="eip155:31337"
        )
    with pytest.raises(ConfigurationError, match="usdc is on chain 31337, not eip155:84532"):
        select_requirement(offered, request_url=RESOURCE_URL, max_amount=50_000, usdc=anvil.usdc)


def test_transport_pays_on_the_deployment_network(
    router: respx.MockRouter, agent: AgentBank
) -> None:
    router["meta"].respond(json=SIMULATED_META)
    router.get(RESOURCE_URL).mock(
        side_effect=Seller(requirement=SIMULATED_REQUIREMENT, domain=SIMULATED_DOMAIN)
    )
    api = mock_api(router, pay_response(domain=SIMULATED_DOMAIN), network="eip155:1337")
    with agent.x402.client(max_amount="0.05") as http:
        first = http.get(RESOURCE_URL)
        second = http.get(RESOURCE_URL)
    assert first.status_code == second.status_code == 200
    receipt = x402_receipt(first)
    assert receipt is not None
    assert receipt.requirement.chain.id == 1337
    assert receipt.requirement.asset.address.lower() == SIMULATED_USDC
    assert receipt.settlement is not None
    assert receipt.settlement["network"] == "eip155:1337"
    assert api.call_count == 2
    assert router["meta"].call_count == 1  # resolved once, cached on the client
    assert agent.x402.settings().network == "eip155:1337"
    assert router["meta"].call_count == 1


def test_explicit_network_wins_over_the_deployment(
    router: respx.MockRouter, agent: AgentBank
) -> None:
    router["meta"].respond(json=SIMULATED_META)
    router.get(RESOURCE_URL).mock(side_effect=Seller())  # a Base Sepolia seller
    api = mock_api(router)
    with pytest.raises(X402Error) as wrong_chain:
        agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert wrong_chain.value.reason == "no_acceptable_requirement"
    assert "is not eip155:1337" in wrong_chain.value.detail
    assert api.call_count == 0
    calls = router["meta"].call_count
    with agent.x402.client(max_amount="0.05", network="eip155:84532") as http:
        paid = http.get(RESOURCE_URL)
    assert paid.status_code == 200
    assert api.call_count == 1
    assert router["meta"].call_count == calls  # an explicit network needs no GET /v1/meta
    assert agent.x402.settings("base-sepolia").usdc == USDC_REGISTRY[84532]


def test_anvil_usdc_comes_from_the_deployment(router: respx.MockRouter, agent: AgentBank) -> None:
    router["meta"].respond(json=meta_response(chain="anvil", chain_id=31337, usdc=ANVIL_USDC))
    router.get(RESOURCE_URL).mock(
        side_effect=Seller(requirement=ANVIL_REQUIREMENT, domain=ANVIL_DOMAIN)
    )
    mock_api(router, pay_response(domain=ANVIL_DOMAIN), network="eip155:31337")
    assert agent.x402.fetch(RESOURCE_URL, max_amount="0.05").status_code == 200
    # Explicitly on Anvil: the registry has no USDC there, so the deployment's is used.
    explicit = agent.x402.fetch(RESOURCE_URL, max_amount="0.05", network="eip155:31337")
    assert explicit.status_code == 200
    assert agent.x402.settings("eip155:31337").usdc.address == ANVIL_USDC
    # Explicitly on Anvil while the deployment is elsewhere: no USDC is known.
    router["meta"].respond(json=SIMULATED_META)
    agent.meta(refresh=True)
    with pytest.raises(ConfigurationError, match="No USDC address is known for eip155:31337"):
        agent.x402.settings("eip155:31337")


def test_mainnet_deployments_are_refused(router: respx.MockRouter, agent: AgentBank) -> None:
    router["meta"].respond(json=meta_response(chain_id=8453))
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    api = mock_api(router)
    with pytest.raises(MainnetLockedError):
        agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert api.call_count == 0


def test_authorization_must_use_the_deployment_usdc_domain(
    router: respx.MockRouter, agent: AgentBank
) -> None:
    router["meta"].respond(json=meta_response(name="USD Coin"))
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    mock_api(router)  # Agent Bank answers with the domain name "USDC"
    with pytest.raises(X402Error, match="not the deployment's USDC domain") as excinfo:
        agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert excinfo.value.reason == "authorization_mismatch"


async def test_async_transport_pays_on_the_deployment_network(
    router: respx.MockRouter, async_agent: AsyncAgentBank
) -> None:
    router["meta"].respond(json=SIMULATED_META)
    router.get(RESOURCE_URL).mock(
        side_effect=Seller(requirement=SIMULATED_REQUIREMENT, domain=SIMULATED_DOMAIN)
    )
    api = mock_api(router, pay_response(domain=SIMULATED_DOMAIN), network="eip155:1337")
    async with async_agent.x402.client(max_amount="0.05") as http:
        response = await http.get(RESOURCE_URL)
    assert response.status_code == 200
    receipt = x402_receipt(response)
    assert receipt is not None
    assert receipt.requirement.chain.id == 1337
    assert api.call_count == 1
    assert (await async_agent.x402.settings()).network == "eip155:1337"
    assert router["meta"].call_count == 1

    # An explicit network still wins: a Base Sepolia seller is paid on Base Sepolia.
    router.get(RESOURCE_URL).mock(side_effect=Seller())
    mock_api(router)
    explicit = await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.05", network="eip155:84532")
    assert explicit.status_code == 200
    assert router["meta"].call_count == 1
    with pytest.raises(X402Error) as wrong_chain:
        await async_agent.x402.fetch(RESOURCE_URL, max_amount="0.05")
    assert wrong_chain.value.reason == "no_acceptable_requirement"


async def test_async_settings_resolution(
    router: respx.MockRouter, async_agent: AsyncAgentBank
) -> None:
    anvil_meta = meta_response(chain="anvil", chain_id=31337, usdc=ANVIL_USDC)
    router["meta"].respond(json=anvil_meta)
    assert (await async_agent.x402.settings("eip155:1337")).usdc == USDC_REGISTRY[1337]
    assert not router["meta"].called
    anvil = await async_agent.x402.settings("anvil")
    assert anvil.usdc.address == ANVIL_USDC
    assert anvil.usdc.chain_id == 31337
    router["meta"].respond(json=SIMULATED_META)
    await async_agent.meta(refresh=True)
    with pytest.raises(ConfigurationError, match="No USDC address is known"):
        await async_agent.x402.settings("eip155:31337")
    router["meta"].respond(json=meta_response(chain_id=8453))
    await async_agent.meta(refresh=True)
    with pytest.raises(MainnetLockedError):
        await async_agent.x402.settings()
