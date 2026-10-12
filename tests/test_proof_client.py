"""``bank.proofs`` and the proof transports against a mocked API, mocked sellers and a fake prover.

The sellers sit behind a real :class:`agentbank.proofs.ProofGate`'s challenges and check
each ``AGENT-PROOF`` header (gate nonce, request hash) without the pairing check; the
pairing check itself is covered by the vector tests. The prover is ``tests/fake_prover.py``
(or, when ``node`` and the monorepo checkout are available, the real ``agentbank-prove``).
"""

from __future__ import annotations

import json
import math
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from agentbank import (
    AgentBank,
    AgentBankError,
    AsyncAgentBank,
    ConfigurationError,
    MainnetLockedError,
    proofs,
    x402_receipt,
)
from agentbank.eip712 import verify_owner_authorization
from agentbank.errors import (
    ProofError,
    ProofHeaderError,
    ProofRefusedError,
    ProofRequestError,
    ProverError,
)
from agentbank.models import ProofPresentation
from agentbank.proofs import ProofReceipt, RootInfo, RootQuery, proof_receipt
from tests.conftest import (
    ACCOUNT_ID,
    AGENT_ID,
    API_KEY,
    BASE_URL,
    OWNER_ADDRESS,
    OWNER_KEY,
    SESSION_ID,
    SESSION_KEY,
    verify_agent_request,
)
from tests.factories import example, id_for
from tests.test_x402 import RESOURCE_URL, Seller, meta_response, mock_api

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "proof_vectors.json").read_text("utf-8")
)
PROOF = VECTORS["proof"]
REQUEST: dict[str, Any] = PROOF["request"]
WITNESS: dict[str, Any] = PROOF["witness"]
SECRET: str = PROOF["secret"]
NULLIFIER: str = PROOF["expected"]["nullifier"]
FAKE_PROVER = f"{sys.executable} {Path(__file__).parent / 'fake_prover.py'}"
SELLER_KEY = "seller-gate-key-for-tests-0123456789abcdef"
SELLER_HOST = "api.example-data.com"
WITNESS_URL = f"{BASE_URL}/v1/accounts/{ACCOUNT_ID}/proofs/witness"
RESERVATIONS_URL = f"{BASE_URL}/v1/accounts/{ACCOUNT_ID}/proofs/reservations"
PRV_ID = WITNESS["reservation_id"]
MONOREPO_PROOFS = Path(__file__).resolve().parents[2] / "agent-bank" / "packages" / "proofs"


class ProofSeller:
    """A resource behind a proof gate (and optionally an x402 paywall)."""

    def __init__(
        self,
        *,
        scope: str = SELLER_HOST,
        payments: Seller | None = None,
        consume_on_verify: bool = True,
        refuse: bool = False,
    ) -> None:
        self.gate = proofs.ProofGate(
            scope=scope,
            key=SELLER_KEY,
            require=[proofs.verified_company()],
            root_resolver=lambda query: None,
        )
        self.payments = payments
        self.consume_on_verify = consume_on_verify
        self.refuse = refuse
        self.used: set[str] = set()
        self.headers: list[str | None] = []

    def challenge(self, reason: proofs.ProofFailureReason | None) -> httpx.Response:
        challenge = self.gate.challenge(reason)
        return httpx.Response(challenge.status, headers=challenge.headers, json=challenge.body)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        header = request.headers.get("agent-proof")
        self.headers.append(header)
        if header is None:
            return self.challenge(None)
        envelope = proofs.decode_proof(header)
        assert envelope.request.nonce == proofs.gate_nonce(SELLER_KEY, envelope.request)
        assert envelope.presentation.request_hash == proofs.request_hash(envelope.request)
        if self.refuse:
            return self.challenge("invalid_proof")
        nonce = envelope.request.nonce
        if nonce in self.used:
            return self.challenge("nonce_reused")
        if self.consume_on_verify:
            self.used.add(nonce)
        if self.payments is None:
            response = httpx.Response(200, json={"data": "ok"})
        else:
            response = self.payments(request)
            if response.status_code != 200:
                return response
            self.used.add(nonce)
        response.headers["AGENT-PROOF-RESPONSE"] = proofs.encode_proof_response(NULLIFIER)
        return response


@pytest.fixture
def prover_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The fake prover and the vector's secret, from the environment."""
    monkeypatch.setenv("AGENTBANK_PROVER", FAKE_PROVER)
    monkeypatch.setenv("AGENTBANK_PROOF_SECRET", SECRET)
    monkeypatch.setenv("FAKE_PROVER_LOG", str(tmp_path))
    return tmp_path


def prover_calls(log: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text("utf-8")) for p in sorted(log.glob("call-*.json"))]


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE_URL}/v1/meta", name="meta").respond(json=meta_response())
        yield mock


def mock_witness(router: respx.MockRouter, witness: dict[str, Any] | None = None) -> respx.Route:
    def serve(request: httpx.Request) -> httpx.Response:
        verify_agent_request(request)
        return httpx.Response(200, json=witness or WITNESS)

    return router.get(WITNESS_URL).mock(side_effect=serve)


def reservation(**changes: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "id": PRV_ID,
        "status": "active",
        "amount": {"amount": "500.00", "asset": "USDC"},
        "scope_tag": str(proofs.scope_tag_of("api.seller.example")),
        "expires_at": "2030-01-01T00:00:00Z",
        "account_id": ACCOUNT_ID,
    }
    values.update(changes)
    return example("ProofReservation", **values)


def api_root(**changes: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "root": PROOF["root_info"]["root"],
        "epoch": "7",
        "snapshot_at": "2025-10-09T08:53:20Z",
        "published_at": "2025-10-09T08:53:32Z",
        "valid_until": "2025-10-09T10:53:20Z",
        "leaf_count": 20,
        "status": "published",
        "chain_id": 84532,
        "registry": PROOF["gate"]["registry"],
    }
    values.update(changes)
    return example("ProofRoot", **values)


# --------------------------------------------------------------------- settings and reservations


@pytest.fixture
def owner_client() -> Iterator[AgentBank]:
    with AgentBank(api_key=API_KEY, base_url=BASE_URL, chain_id=84532) as client:
        yield client


def settings(enabled: bool, disclose: list[str]) -> dict[str, Any]:
    return example("ProofSettings", agent_id=AGENT_ID, enabled=enabled, disclose=disclose)


def test_update_settings_signs_only_when_widening(
    owner_client: AgentBank, router: respx.MockRouter
) -> None:
    path = f"{BASE_URL}/v1/agents/{AGENT_ID}/proofs/settings"
    current = router.get(path).mock(
        side_effect=[
            httpx.Response(200, json=settings(False, [])),
            httpx.Response(200, json=settings(True, ["principal", "limits"])),
        ]
    )
    put = router.put(path).respond(json=settings(True, ["limits", "principal"]))
    owner_client.proofs.update_settings(
        AGENT_ID, enabled=True, disclose=["principal", "limits", "limits"], owner=OWNER_KEY
    )
    body = json.loads(put.calls.last.request.content)
    assert body["disclose"] == ["limits", "principal"]
    verify_owner_authorization(
        owner=OWNER_ADDRESS,
        authorization=body["owner_authorization"],
        chain_id=84532,
        action="proofs.disclose",
        subject=AGENT_ID,
        payload={"agent_id": AGENT_ID, "enabled": True, "disclose": ["limits", "principal"]},
    )
    owner_client.proofs.update_settings(
        AGENT_ID, enabled=True, disclose=["limits"], owner=OWNER_KEY
    )
    assert "owner_authorization" not in json.loads(put.calls.last.request.content)
    owner_client.proofs.update_settings(
        AGENT_ID, enabled=False, disclose=[], owner_authorization={"signature": "0x"}
    )
    assert json.loads(put.calls.last.request.content)["owner_authorization"] == {"signature": "0x"}
    assert current.call_count == 2
    with pytest.raises(ValueError, match="everything"):
        owner_client.proofs.update_settings(AGENT_ID, enabled=True, disclose=["everything"])


def test_release_reservation_signs_as_the_owner(
    owner_client: AgentBank, router: respx.MockRouter
) -> None:
    route = router.post(f"{BASE_URL}/v1/proofs/reservations/{PRV_ID}/release").respond(
        json=reservation(status="released")
    )
    released = owner_client.proofs.release_reservation(PRV_ID, owner=OWNER_KEY)
    assert released.status == "released"
    body = json.loads(route.calls.last.request.content)
    verify_owner_authorization(
        owner=OWNER_ADDRESS,
        authorization=body["owner_authorization"],
        chain_id=84532,
        action="proofs.reservation.release",
        subject=PRV_ID,
        payload={"reservation_id": PRV_ID},
    )
    with pytest.raises(ConfigurationError, match="owner"):
        owner_client.proofs.release_reservation(PRV_ID)


def test_reserve_bodies(agent: AgentBank, router: respx.MockRouter) -> None:
    route = router.post(RESERVATIONS_URL).respond(201, json=reservation())
    agent.proofs.reserve("500.00", scope="api.seller.example", expires_at=1_760_007_300)
    assert json.loads(route.calls.last.request.content) == {
        "amount": {"amount": "500.00", "asset": "USDC"},
        "scope": "api.seller.example",
        "expires_at": "2025-10-09T10:55:00.000Z",
    }
    agent.proofs.reserve("1", scope_tag=2421086520919343786, expires_at=1_760_007_300)
    sent = json.loads(route.calls.last.request.content)
    assert sent["scope_tag"] == "2421086520919343786"
    assert "scope" not in sent
    for kwargs in (
        {},
        {"scope": "a", "scope_tag": 1},
        {"scope_tag": 0},
        {"scope_tag": "-1"},
        {"scope_tag": 2**64},
        {"scope": "x" * 254},
    ):
        with pytest.raises(ValueError):  # noqa: PT011
            agent.proofs.reserve("1", expires_at=1, **kwargs)
    assert route.call_count == 2


def test_enroll_computes_the_commitment_with_the_prover(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commitment = VECTORS["poseidon"]["identity"]["identity_commitment"]
    route = router.put(f"{BASE_URL}/v1/accounts/{ACCOUNT_ID}/proofs/identity").respond(
        json=example("ProofIdentity", identity_commitment=commitment)
    )
    agent.proofs.enroll()
    assert json.loads(route.calls.last.request.content) == {"identity_commitment": commitment}
    verify_agent_request(route.calls.last.request)
    (call,) = prover_calls(prover_env)
    assert call["argv"] == ["identity"]
    assert json.loads(call["stdin"]) == {"secret": SECRET}
    agent.proofs.enroll(commitment)
    assert len(prover_calls(prover_env)) == 1
    with pytest.raises(ValueError, match="32-byte"):
        agent.proofs.enroll("0x1234")
    monkeypatch.delenv("AGENTBANK_PROOF_SECRET")
    with pytest.raises(ProverError) as missing:
        agent.proofs.enroll()
    assert missing.value.reason == "secret_missing"
    assert route.call_count == 2


# --------------------------------------------------------------------- proving


def test_prove_picks_the_matching_reservation(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    listing = router.get(RESERVATIONS_URL).respond(
        json={
            "data": [
                reservation(id=id_for("prv").replace("0", "1", 1), scope_tag="7"),
                reservation(),
            ],
            "next_cursor": None,
        }
    )
    witness = mock_witness(router)
    presentation = agent.proofs.prove(REQUEST)
    assert isinstance(presentation, ProofPresentation)
    assert presentation.request_hash == PROOF["request_hash"]
    assert listing.calls.last.request.url.params["status"] == "active"
    assert witness.calls.last.request.url.params["reservation_id"] == PRV_ID
    (call,) = prover_calls(prover_env)
    assert call["argv"] == ["prove"]
    assert SECRET not in " ".join(call["argv"])
    sent = json.loads(call["stdin"])
    assert sent["secret"] == SECRET
    assert sent["request"] == REQUEST
    agent.proofs.prove(REQUEST, reservation_id=PRV_ID, root=PROOF["root_info"]["root"])
    assert listing.call_count == 1
    assert witness.calls.last.request.url.params["root"] == PROOF["root_info"]["root"]


def test_prove_reports_a_pending_reservation(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    router.get(RESERVATIONS_URL, params={"status": "active"}).respond(
        json={"data": [], "next_cursor": None}
    )
    router.get(RESERVATIONS_URL, params={"status": "pending"}).respond(
        json={"data": [reservation(status="pending")], "next_cursor": None}
    )
    witness = mock_witness(router)
    with pytest.raises(ProofRefusedError, match="next root") as pending:
        agent.proofs.prove(REQUEST)
    assert pending.value.reason == "reservation_pending"
    assert pending.value.code == "proof_refused"
    assert not witness.called
    assert prover_calls(prover_env) == []


def test_prove_refusals(agent: AgentBank, router: respx.MockRouter, prover_env: Path) -> None:
    router.get(RESERVATIONS_URL).respond(json={"data": [], "next_cursor": None})
    witness = mock_witness(router, {**WITNESS, "disclosure_mask": 1})
    with pytest.raises(ProofRefusedError, match="No active reservation") as none:
        agent.proofs.prove(REQUEST)
    assert none.value.reason == "reservation_required"
    assert not witness.called
    with pytest.raises(ProofRefusedError) as undisclosed:
        agent.proofs.prove(REQUEST, reservation_id=PRV_ID)
    assert undisclosed.value.reason == "undisclosed"
    assert prover_calls(prover_env) == []
    with pytest.raises(ProofRequestError):
        agent.proofs.prove({**REQUEST, "nonce": "0x1"})
    with pytest.raises(MainnetLockedError):
        agent.proofs.prove({**REQUEST, "chain_id": 8453})


def test_prove_needs_a_secret_and_a_prover(
    agent: AgentBank, router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    witness = mock_witness(router)
    with pytest.raises(ProverError) as no_secret:
        agent.proofs.prove(REQUEST, reservation_id=PRV_ID)
    assert no_secret.value.reason == "secret_missing"
    with pytest.raises(ProverError) as no_prover:
        agent.proofs.prove(REQUEST, secret=SECRET, reservation_id=PRV_ID)
    assert no_prover.value.reason == "prover_not_configured"
    assert not witness.called
    monkeypatch.setenv("FAKE_PROVER", "wrong-hash")
    with pytest.raises(ProverError, match="another request"):
        agent.proofs.prove(REQUEST, secret=SECRET, reservation_id=PRV_ID, prover=FAKE_PROVER)


def limited_agent(limit: float) -> AgentBank:
    return AgentBank(
        session_id=SESSION_ID,
        session_key=SESSION_KEY,
        account_id=ACCOUNT_ID,
        base_url=BASE_URL,
        max_presentations_per_scope_per_hour=limit,
    )


def test_prove_probing_guard(router: respx.MockRouter, prover_env: Path) -> None:
    witness = mock_witness(router)
    with limited_agent(1) as client:
        assert client.config.max_presentations_per_scope_per_hour == 1
        assert client.proofs.limiter.max_per_hour == 1
        # A refusal or an error gives the slot back.
        router.get(WITNESS_URL).respond(200, json={**WITNESS, "disclosure_mask": 1})
        with pytest.raises(ProofRefusedError) as undisclosed:
            client.proofs.prove(REQUEST, reservation_id=PRV_ID)
        assert undisclosed.value.reason == "undisclosed"
        witness = mock_witness(router)
        client.proofs.prove(REQUEST, reservation_id=PRV_ID)
        fetched = witness.call_count
        with pytest.raises(ProofRefusedError, match="max_presentations") as limited:
            client.proofs.prove(REQUEST, reservation_id=PRV_ID)
        assert limited.value.reason == "rate_limited"
        assert limited.value.code == "rate_limited"
        assert limited.value.retry_after_seconds is not None
        assert 3_500 < limited.value.retry_after_seconds <= 3_600
        assert limited.value.extensions["retry_after_seconds"] == limited.value.retry_after_seconds
        assert witness.call_count == fetched  # refused before fetching a witness
        # Another scope has its own budget.
        other = proofs.create_proof_request("other.example", require=[proofs.verified_company()])
        client.proofs.prove(other)
    assert len(prover_calls(prover_env)) == 2
    with limited_agent(0) as closed:
        with pytest.raises(ProofRefusedError) as refused:
            closed.proofs.prove(REQUEST, reservation_id=PRV_ID)
        assert refused.value.reason == "rate_limited"
        assert refused.value.retry_after_seconds is None
    with limited_agent(math.inf) as open_:
        for _ in range(3):
            open_.proofs.prove(REQUEST, reservation_id=PRV_ID)
    for bad in (-1, 1.5, True, "30"):
        with pytest.raises(ConfigurationError, match="max_presentations"):
            limited_agent(bad)  # type: ignore[arg-type]


def test_presentation_limiter_window() -> None:
    clock = [1_000.0]
    limiter = proofs.PresentationLimiter(2, clock=lambda: clock[0])
    release = limiter.take("a.example")
    limiter.take("a.example")
    with pytest.raises(ProofRefusedError) as full:
        limiter.take("a.example")
    assert full.value.retry_after_seconds == 3_600
    release()
    release()  # idempotent
    limiter.take("a.example")
    clock[0] += 3_600.5  # the window slides: both slots free again
    limiter.take("a.example")
    limiter.take("a.example")
    with pytest.raises(ProofRefusedError):
        limiter.take("a.example")
    # One budget per scope, however an on-chain scope id is spelled.
    scope_id = proofs.onchain_scope_id(84532, "0x" + "ab" * 20, "0x" + "cd" * 32)
    limiter.take(scope_id)
    limiter.take(scope_id.replace("0xab", "0xAB"))
    with pytest.raises(ProofRefusedError):
        limiter.take(scope_id.upper().replace("EIP155", "eip155").replace("0X", "0x"))
    assert proofs.PresentationLimiter().max_per_hour == 30
    with pytest.raises(ValueError, match="non-negative"):
        proofs.PresentationLimiter(-1)


def test_prove_on_chain_scopes(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    consumer = "0x00000000000000000000000000000000000a11ce"
    context = "0x" + "42" * 32
    mock_witness(router)
    request = proofs.create_proof_request(
        proofs.onchain_scope_id(84532, consumer, context), require=[proofs.verified_company()]
    )
    assert agent.proofs.prove(request).request_hash == proofs.request_hash(request)
    on_mainnet = proofs.create_proof_request(
        proofs.onchain_scope_id(8453, consumer, context), require=[proofs.verified_company()]
    )
    with pytest.raises(MainnetLockedError, match="contract on chain 8453"):
        agent.proofs.prove(on_mainnet)
    assert len(prover_calls(prover_env)) == 1


async def test_async_prove(
    async_agent: AsyncAgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    router.get(RESERVATIONS_URL).respond(json={"data": [reservation()], "next_cursor": None})
    mock_witness(router)
    presentation = await async_agent.proofs.prove(REQUEST, prover=proofs.AsyncProver(FAKE_PROVER))
    assert presentation.nullifier == PROOF["presentation"]["nullifier"]
    commitment = VECTORS["poseidon"]["identity"]["identity_commitment"]
    router.put(f"{BASE_URL}/v1/accounts/{ACCOUNT_ID}/proofs/identity").respond(
        json=example("ProofIdentity", identity_commitment=commitment)
    )
    identity = await async_agent.proofs.enroll(secret=SECRET)
    assert identity.identity_commitment == commitment


# --------------------------------------------------------------------- root resolution and gates


def test_root_resolver(router: respx.MockRouter) -> None:
    root = PROOF["root_info"]["root"]
    route = router.get(f"{BASE_URL}/v1/proofs/roots/{root}")
    with AgentBank(base_url=BASE_URL) as bank:
        resolve = bank.proofs.root_resolver()
        query = RootQuery(root, 84532, PROOF["gate"]["registry"].lower())
        route.respond(json=api_root())
        info = resolve(query)
        assert info == RootInfo(
            7, 1_760_000_000, 1_760_000_012, 1_760_007_200, 20, False, "published"
        )
        assert "authorization" not in route.calls.last.request.headers
        assert resolve(RootQuery(root, 84532, None)) == info
        route.respond(json=api_root(chain_id=31337))
        assert resolve(query) is None
        route.respond(json=api_root(registry=None))
        assert resolve(query) is None
        route.respond(404, json={"code": "not_found", "title": "Not found", "status": 404})
        assert resolve(query) is None
        route.respond(json=api_root(root="0x" + "11" * 32))
        with pytest.raises(AgentBankError, match="another root"):
            resolve(query)
        route.respond(500, json={"code": "internal", "title": "Internal", "status": 500})
        with pytest.raises(AgentBankError):
            bank.proofs.root_resolver()(query)


def test_gate_through_the_api(router: respx.MockRouter) -> None:
    router.get(f"{BASE_URL}/v1/proofs/roots/{PROOF['root_info']['root']}").respond(json=api_root())
    with AgentBank(base_url=BASE_URL) as bank:
        gate = bank.proofs.gate(
            scope=PROOF["gate"]["scope"],
            key=PROOF["gate"]["key_utf8"],
            require=[
                proofs.verified_company(),
                proofs.can_pay_per_tx("5.00"),
                proofs.reserved_for("500.00", for_seconds=3_600),
                proofs.reputation(disputes_lost_at_most=0),
                proofs.account_older_than(90),
            ],
            registry=PROOF["gate"]["registry"],
            now=lambda: PROOF["gate"]["now"],
        )
        result = gate.check({"AGENT-PROOF": PROOF["agent_proof_header"]})
    assert result.kind == "verified"
    assert result.nullifier == NULLIFIER


async def test_async_gate_through_the_api(router: respx.MockRouter) -> None:
    router.get(f"{BASE_URL}/v1/proofs/roots/{PROOF['root_info']['root']}").respond(
        json=api_root(leaf_count=3)
    )
    async with AsyncAgentBank(base_url=BASE_URL) as bank:
        gate = bank.proofs.gate(
            scope=PROOF["gate"]["scope"],
            key=PROOF["gate"]["key_utf8"],
            require=[
                proofs.verified_company(),
                proofs.can_pay_per_tx("5.00"),
                proofs.reserved_for("500.00", for_seconds=3_600),
                proofs.reputation(disputes_lost_at_most=0),
                proofs.account_older_than(90),
            ],
            registry=PROOF["gate"]["registry"],
            now=lambda: PROOF["gate"]["now"],
        )
        result = await gate.check({"AGENT-PROOF": PROOF["agent_proof_header"]})
        assert result.kind == "proof-required"
        assert result.reason == "anonymity_set_too_small"
        missing = "0x" + "00" * 32
        router.get(f"{BASE_URL}/v1/proofs/roots/{missing}").respond(
            404, json={"code": "not_found", "title": "Not found", "status": 404}
        )
        assert (await bank.proofs.root_resolver()(RootQuery(missing, 84532, None))) is None


# --------------------------------------------------------------------- the proof transport


def test_proof_client_answers_a_challenge(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    seller = ProofSeller()
    resource = router.get(RESOURCE_URL).mock(side_effect=seller)
    mock_witness(router)
    receipts: list[ProofReceipt] = []
    with agent.proofs.client(on_proof=receipts.append) as http:
        response = http.get(RESOURCE_URL)
        passthrough = router.get(f"https://{SELLER_HOST}/free").respond(200, json={})
        assert http.get(f"https://{SELLER_HOST}/free").status_code == 200
        bare = router.get(f"https://{SELLER_HOST}/login").respond(401)
        assert http.get(f"https://{SELLER_HOST}/login").status_code == 401
    assert response.status_code == 200
    assert response.json() == {"data": "ok"}
    assert resource.call_count == 2
    assert passthrough.called
    assert bare.called
    receipt = proof_receipt(response)
    assert receipt is not None
    assert receipts == [receipt]
    assert receipt.nullifier == NULLIFIER
    assert receipt.request.scope == SELLER_HOST
    assert seller.headers == [None, receipt.header]
    assert len(prover_calls(prover_env)) == 1


def test_proof_transport_refusals(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    mock_witness(router)
    resource = router.get(RESOURCE_URL)
    resource.mock(side_effect=ProofSeller(scope="other.example"))
    with pytest.raises(ProofError, match=r"other\.example") as foreign:
        agent.proofs.client().get(RESOURCE_URL)
    assert foreign.value.reason == "scope_not_allowed"
    with agent.proofs.client(allowed_scopes=["OTHER.example"]) as http:
        assert http.get(RESOURCE_URL).status_code == 200
    resource.mock(side_effect=ProofSeller(refuse=True))
    with pytest.raises(ProofError, match="invalid_proof") as rejected:
        agent.proofs.client().get(RESOURCE_URL)
    assert rejected.value.reason == "proof_rejected"
    assert rejected.value.response is not None
    assert rejected.value.response.status_code == 401
    resource.respond(401, headers={"AGENT-PROOF-REQUIRED": "garbage"})
    with pytest.raises(ProofHeaderError):
        agent.proofs.client().get(RESOURCE_URL)
    resource.mock(
        side_effect=[
            ProofSeller().challenge(None),
            httpx.Response(401, headers={"AGENT-PROOF-REQUIRED": "x"}, text="nope"),
        ]
    )
    with pytest.raises(ProofError, match="no reason given"):
        agent.proofs.client().get(RESOURCE_URL)


def test_proof_transport_never_answers_on_chain_scopes(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    scope = proofs.onchain_scope_id(84532, "0x" + "77" * 20, "0x" + "01" * 32)
    mock_witness(router)
    router.get(RESOURCE_URL).mock(side_effect=ProofSeller(scope=scope))
    with agent.proofs.client(allowed_scopes=[scope]) as http:
        with pytest.raises(ProofError, match="on-chain scope") as refused:
            http.get(RESOURCE_URL)
    assert refused.value.reason == "scope_not_allowed"
    assert prover_calls(prover_env) == []


def test_proof_transport_applies_the_probing_guard(
    router: respx.MockRouter, prover_env: Path
) -> None:
    mock_witness(router)
    router.get(RESOURCE_URL).mock(side_effect=ProofSeller())
    with limited_agent(1) as client, client.proofs.client() as http:
        assert http.get(RESOURCE_URL).status_code == 200
        with pytest.raises(ProofRefusedError) as limited:
            http.get(RESOURCE_URL)  # a fresh challenge: a second proof to the same scope
    assert limited.value.reason == "rate_limited"
    assert len(prover_calls(prover_env)) == 1


@pytest.mark.parametrize("consume_on_verify", [False, True], ids=["lenient", "consuming"])
def test_x402_client_answers_a_proof_then_a_payment(
    agent: AgentBank, router: respx.MockRouter, prover_env: Path, consume_on_verify: bool
) -> None:
    seller = ProofSeller(payments=Seller(), consume_on_verify=consume_on_verify)
    resource = router.get(RESOURCE_URL).mock(side_effect=seller)
    mock_witness(router)
    api = mock_api(router)
    with agent.x402.client(max_amount="0.05") as http:  # proofs: AGENTBANK_PROOF_SECRET is set
        response = http.get(RESOURCE_URL)
    assert response.status_code == 200
    assert api.call_count == 1  # paid once
    receipt = x402_receipt(response)
    assert receipt is not None
    proved = proof_receipt(response)
    assert proved is not None
    paid_request = resource.calls.last.request
    assert paid_request.headers["payment-signature"] == receipt.header.value
    assert paid_request.headers["agent-proof"] == proved.header
    if consume_on_verify:
        # The gate consumed the first proof's nonce when the paywall answered 402: the
        # paid retry is challenged again and answered with a fresh proof and the payment.
        assert resource.call_count == 4
        assert len(prover_calls(prover_env)) == 2
        assert seller.headers[1] == seller.headers[2] != seller.headers[3]
    else:
        assert resource.call_count == 3
        assert len(prover_calls(prover_env)) == 1
        assert seller.headers[1] == seller.headers[2] == proved.header


def test_x402_client_proofs_are_opt_in(
    agent: AgentBank, router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    router.get(RESOURCE_URL).mock(side_effect=ProofSeller(payments=Seller()))
    with agent.x402.client() as http:
        assert http.get(RESOURCE_URL).status_code == 401  # no proof secret configured
    monkeypatch.setenv("AGENTBANK_PROOF_SECRET", SECRET)
    with agent.x402.client(proofs=False) as http:
        assert http.get(RESOURCE_URL).status_code == 401
    with pytest.raises(ProverError) as raised:
        agent.x402.fetch(RESOURCE_URL)
    assert raised.value.reason == "prover_not_configured"
    proof_transport = agent.proofs.transport(prover=FAKE_PROVER)
    x402_transport = agent.x402.transport(proofs=True, transport=proof_transport)
    assert x402_transport._transport is proof_transport


async def test_async_proof_and_payment(
    async_agent: AsyncAgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    seller = ProofSeller(payments=Seller())
    router.get(RESOURCE_URL).mock(side_effect=seller)
    mock_witness(router)
    api = mock_api(router)
    response = await async_agent.x402.fetch(
        RESOURCE_URL, max_amount="0.05", proofs=True, proof_secret=SECRET
    )
    assert response.status_code == 200
    assert api.call_count == 1
    assert proof_receipt(response) is not None
    router.get(f"https://{SELLER_HOST}/data").mock(side_effect=ProofSeller())
    async with async_agent.proofs.client() as http:
        proved = await http.get(f"https://{SELLER_HOST}/data")
    assert proved.status_code == 200
    assert "AsyncProofTransport(prover=AsyncProver(" in repr(async_agent.proofs.transport())


async def test_async_proof_transport_refusals(
    async_agent: AsyncAgentBank, router: respx.MockRouter, prover_env: Path
) -> None:
    mock_witness(router)
    resource = router.get(RESOURCE_URL)
    resource.mock(side_effect=ProofSeller(scope="other.example"))
    async with async_agent.proofs.client() as http:
        with pytest.raises(ProofError) as foreign:
            await http.get(RESOURCE_URL)
        assert foreign.value.reason == "scope_not_allowed"
        resource.mock(side_effect=ProofSeller(refuse=True))
        with pytest.raises(ProofError) as rejected:
            await http.get(RESOURCE_URL)
        assert rejected.value.reason == "proof_rejected"
        resource.respond(200, headers={"AGENT-PROOF-RESPONSE": "garbage"})
        assert proof_receipt(await http.get(RESOURCE_URL)) is None
        onchain = proofs.onchain_scope_id(84532, "0x" + "77" * 20, "0x" + "01" * 32)
        resource.mock(side_effect=ProofSeller(scope=onchain))
        with pytest.raises(ProofError, match="on-chain scope"):
            await http.get(RESOURCE_URL)


async def test_async_prove_probing_guard(router: respx.MockRouter, prover_env: Path) -> None:
    async with AsyncAgentBank(
        session_id=SESSION_ID,
        session_key=SESSION_KEY,
        account_id=ACCOUNT_ID,
        base_url=BASE_URL,
        max_presentations_per_scope_per_hour=1,
    ) as client:
        router.get(WITNESS_URL).respond(200, json={**WITNESS, "disclosure_mask": 1})
        with pytest.raises(ProofRefusedError) as undisclosed:
            await client.proofs.prove(REQUEST, reservation_id=PRV_ID)
        assert undisclosed.value.reason == "undisclosed"
        mock_witness(router)
        await client.proofs.prove(REQUEST, reservation_id=PRV_ID)
        with pytest.raises(ProofRefusedError) as limited:
            await client.proofs.prove(REQUEST, reservation_id=PRV_ID)
        assert limited.value.reason == "rate_limited"
    assert len(prover_calls(prover_env)) == 1


# --------------------------------------------------------------------- the real prover


def _real_prover() -> str | None:
    node = shutil.which("node")
    cli = MONOREPO_PROOFS / "bin" / "agentbank-prove.mjs"
    if node is None or not cli.exists() or not (MONOREPO_PROOFS / "node_modules").exists():
        return None
    return f"{node} {cli}"


@pytest.mark.skipif(_real_prover() is None, reason="needs node and the agent-bank checkout")
def test_real_prover_end_to_end(agent: AgentBank, router: respx.MockRouter) -> None:
    command = _real_prover()
    assert command is not None
    prover = proofs.Prover(command)
    identity = prover.identity(SECRET)
    assert identity.identity_commitment == VECTORS["poseidon"]["identity"]["identity_commitment"]
    mock_witness(router)
    presentation = agent.proofs.prove(REQUEST, secret=SECRET, reservation_id=PRV_ID, prover=prover)
    assert presentation.nullifier == NULLIFIER
    assert presentation.request_hash == PROOF["request_hash"]
    info = PROOF["root_info"]
    gate = proofs.ProofGate(
        scope=PROOF["gate"]["scope"],
        key=PROOF["gate"]["key_utf8"],
        require=[
            proofs.verified_company(),
            proofs.can_pay_per_tx("5.00"),
            proofs.reserved_for("500.00", for_seconds=3_600),
            proofs.reputation(disputes_lost_at_most=0),
            proofs.account_older_than(90),
        ],
        registry=PROOF["gate"]["registry"],
        now=lambda: PROOF["gate"]["now"],
        root_resolver=lambda query: RootInfo(
            7, info["snapshot_at"], info["published_at"], info["valid_until"], 20, False
        ),
    )
    result = gate.check({"AGENT-PROOF": proofs.encode_proof(REQUEST, presentation)})
    assert result.kind == "verified"
    assert result.nullifier == NULLIFIER
    with pytest.raises(ProofRefusedError) as refused:
        prover.prove(secret="0x" + "00" * 31 + "07", witness=WITNESS, request=REQUEST)
    assert refused.value.reason == "witness_mismatch"
