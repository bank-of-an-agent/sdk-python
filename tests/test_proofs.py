"""Private proofs: builders, validation, headers, replay caches, gates and the prover."""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentbank import AgentBankError, MainnetLockedError, proofs
from agentbank.errors import (
    ProofError,
    ProofHeaderError,
    ProofRefusedError,
    ProofRequestError,
    ProverError,
)
from agentbank.models import ProofPresentation, ProofRequest, ProofReservation, ProofWitness
from agentbank.proofs import (
    AsyncProver,
    MemoryReplayCache,
    ProofGate,
    ProofGateResult,
    ProofRequired,
    Prover,
    RootInfo,
)
from tests.factories import example

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "proof_vectors.json").read_text("utf-8")
)
PROOF = VECTORS["proof"]
REQUEST: dict[str, Any] = PROOF["request"]
PRESENTATION: dict[str, Any] = PROOF["presentation"]
WITNESS: dict[str, Any] = PROOF["witness"]
SECRET: str = PROOF["secret"]
NOW = 1_760_000_100
KEY = "agentbank-test-gate-key-0123456789abcdef"
OTHER_KEY = "another-test-gate-key-0123456789abcdef"
FAKE_PROVER = f"{sys.executable} {Path(__file__).parent / 'fake_prover.py'}"
INFO = RootInfo(
    epoch=7,
    snapshot_at=1_760_000_000,
    published_at=1_760_000_012,
    valid_until=1_760_007_200,
    leaf_count=20,
    revoked=False,
)


def request_with(**changes: Any) -> dict[str, Any]:
    return {**REQUEST, **changes}


def refusal(result: ProofGateResult) -> proofs.ProofFailureReason | None:
    assert isinstance(result, ProofRequired)
    return result.reason


# --------------------------------------------------------------------- fields and scopes


def test_bytes32_round_trip_and_errors() -> None:
    assert proofs.to_bytes32(255) == "0x" + "0" * 62 + "ff"
    assert proofs.from_bytes32("0x" + "AB" * 32) == int("ab" * 32, 16)
    for bad in (-1, 1 << 256, True):
        with pytest.raises(ValueError, match="32 bytes"):
            proofs.to_bytes32(bad)
    for text in ("0x12", "ab" * 32, "0x" + "ab" * 32 + "\n"):
        with pytest.raises(ValueError, match="32-byte hex"):
            proofs.from_bytes32(text)


def test_scope_lengths_count_utf16_code_units() -> None:
    assert proofs.scope_field("x" * 253) > 0
    for bad in ("", "x" * 254, "\U0001f600" * 127):
        with pytest.raises(ValueError, match="1 to 253"):
            proofs.scope_field(bad)
    # TextEncoder turns a lone surrogate into U+FFFD; so does the SDK.
    assert proofs.scope_field("a\ud800b") == proofs.scope_field("a�b")
    # A surrogate pair is the character it encodes.
    assert proofs.scope_field("😀") == proofs.scope_field("\U0001f600")


def test_onchain_scope_errors() -> None:
    consumer = "0x1111111111111111111111111111111111111111"
    with pytest.raises(ValueError, match="context"):
        proofs.onchain_scope(84532, consumer, "0x12")
    with pytest.raises(ValueError, match="consumer"):
        proofs.onchain_scope(84532, "11" * 20, "0x" + "00" * 32)
    # Like viem's getAddress (strict: false), any casing is accepted and normalized.
    lower = proofs.onchain_scope(
        84532, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x" + "00" * 32
    )
    mixed = proofs.onchain_scope(
        84532, "0x70997970c51812dc3A010C7d01b50e0d17dc79C8", "0x" + "00" * 32
    )
    assert lower == mixed
    with pytest.raises(ValueError, match="uint256"):
        proofs.onchain_scope(-1, consumer, "0x" + "00" * 32)


def test_onchain_scope_ids() -> None:
    consumer = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    context = "0x" + "AB" * 32
    scope_id = proofs.onchain_scope_id(84532, consumer, context)
    assert scope_id == f"eip155:84532:{consumer.lower()}:{context.lower()}"
    assert proofs.scope_field(scope_id) == proofs.onchain_scope(84532, consumer, context)
    assert proofs.scope_field(scope_id.upper().replace("EIP155", "eip155").replace("0X", "0x")) == (
        proofs.scope_field(scope_id)
    )
    assert proofs.parse_onchain_scope_id(scope_id) == proofs.OnchainScopeRef(
        84532, consumer, context.lower()
    )
    assert proofs.parse_onchain_scope_id(42) is None  # type: ignore[arg-type]
    assert not proofs.is_onchain_scope_id("api.seller.example")
    request = proofs.create_proof_request(
        scope_id, require=[proofs.reserved_for("1.00", for_seconds=600)], now=NOW
    )
    tag = str(proofs.scope_tag(proofs.onchain_scope(84532, consumer, context)))
    assert request.constraints["reserved_for"].model_dump(exclude_none=True) == {
        "min": tag,
        "max": tag,
    }
    longest = proofs.onchain_scope_id(10**32 - 1, consumer, context)
    assert len(longest) == 7 + 32 + 1 + 42 + 1 + 66 <= proofs.MAX_SCOPE_LENGTH
    data = {**proofs.request_data(request), "scope": longest}
    assert proofs.parse_proof_request(data).scope == longest
    for bad in (0, -1, 10**32, True, 1.0):
        with pytest.raises(ValueError, match="chain_id"):
            proofs.onchain_scope_id(bad, consumer, context)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="consumer"):
        proofs.onchain_scope_id(1, "0x1234", context)
    with pytest.raises(ValueError, match="context"):
        proofs.onchain_scope_id(1, consumer, "0x00")


def test_nonces() -> None:
    nonce = proofs.random_nonce()
    assert len(nonce) == 64
    assert proofs.nonce_field(nonce) < proofs.SNARK_SCALAR_FIELD
    with pytest.raises(ValueError, match="31 bytes"):
        proofs.nonce_field("0x" + "ab" * 32)


def test_disclosure_masks_and_classes() -> None:
    assert proofs.is_attribute("balance")
    assert not proofs.is_attribute("shoe_size")
    assert proofs.is_disclosed(8, "balance")
    assert not proofs.is_disclosed(7, "balance")
    with pytest.raises(ValueError, match="unknown disclosure class"):
        proofs.disclosure_mask(["everything"])
    for bad in (-1, 8192, True):
        with pytest.raises(ValueError, match="13-bit"):
            proofs.classes_from_mask(bad)
    with pytest.raises(ValueError, match="part of a class"):
        proofs.classes_from_mask(2)  # per_tx_limit without per_day_limit


# --------------------------------------------------------------------- requirements


def test_builders_normalize_money() -> None:
    assert proofs.can_pay_per_tx(Decimal("5")) == {"per_tx_limit": {"min": "5"}}
    merged = proofs.merge_constraints(
        [proofs.can_pay_per_tx("5"), proofs.balance_at_least(Decimal("1E+3"))]
    )
    assert merged == {"per_tx_limit": {"min": "5.00"}, "balance": {"min": "1000.00"}}
    assert proofs.spending_capped_at(per_day="10") == {"per_day_limit": {"max": "10"}}
    assert proofs.reputation(counterparties="3") == {"counterparties": {"min": "3"}}
    assert proofs.format_bound_value("payments_settled", 7) == "7"
    assert proofs.format_bound_value("balance", 1) == "0.000001"


@pytest.mark.parametrize(
    "build",
    [
        lambda: proofs.can_pay_per_tx(5.0),  # type: ignore[arg-type]
        lambda: proofs.can_pay_per_tx(Decimal("-1")),
        lambda: proofs.can_pay_per_tx(Decimal("NaN")),
        lambda: proofs.can_pay_per_day("5.0000001"),
        proofs.spending_capped_at,
        proofs.reputation,
        lambda: proofs.reputation(payments_settled=-1),
        lambda: proofs.reputation(escrows_completed="01"),
        lambda: proofs.reputation(disputes_lost_at_most=2**64),
        lambda: proofs.reputation(payments_settled=True),
        lambda: proofs.reserved_for("1.00"),
        lambda: proofs.reserved_for("1.00", until=1, for_seconds=1),
        lambda: proofs.reserved_for("1.00", until=datetime(2026, 1, 1)),
        lambda: proofs.reserved_for("1.00", for_seconds=-5),
        lambda: proofs.account_older_than(-1),
        lambda: proofs.account_older_than(1.5),  # type: ignore[arg-type]
    ],
)
def test_builder_errors(build: Callable[[], Any]) -> None:
    with pytest.raises(ProofRequestError):
        build()


def test_relative_requirements() -> None:
    context = proofs.RequirementContext(scope="api.seller.example", now=1_000_000, expires_at=0)
    until = datetime.fromtimestamp(2_000_000, tz=timezone.utc)
    reserved = proofs.reserved_for("1", until=until, scope="tools.example.com")(context)
    assert reserved["reserved_until"] == {"min": "2000000"}
    assert reserved["reserved_for"]["min"] == str(proofs.scope_tag_of("tools.example.com"))
    assert reserved["reserved_amount"] == {"min": "1"}
    relative = proofs.reserved_for("1", for_seconds=60)(context)
    assert relative["reserved_until"] == {"min": "1000060"}
    with pytest.raises(ProofRequestError, match="reserved_for"):
        proofs.reserved_for("1", for_seconds=1, scope="")(context)
    fixed = proofs.account_older_than(1, now=datetime.fromtimestamp(86_400 * 3, tz=timezone.utc))
    assert fixed(context) == {"account_created_on": {"max": str(86_400 * 2)}}
    with pytest.raises(ProofRequestError, match="1970"):
        proofs.account_older_than(365)(proofs.RequirementContext("a", 10, 20))


def test_merge_conflicts() -> None:
    with pytest.raises(ProofRequestError, match="cannot all hold") as err:
        proofs.merge_constraints(
            [proofs.verified_company(), {"principal_verification": {"max": "1"}}]
        )
    assert err.value.attribute == "principal_verification"
    assert err.value.reason == "invalid_request"
    assert err.value.code == "invalid_request"


def test_create_proof_request_defaults_and_errors() -> None:
    request = proofs.create_proof_request("api.seller.example", require=[proofs.verified_company()])
    assert isinstance(request, ProofRequest)
    assert request.expires_at - request.issued_at == proofs.DEFAULT_TTL_SECONDS
    assert request.registry is None
    assert len(request.request_id) == 32
    data = proofs.request_data(request)
    assert data["registry"] is None
    assert data["constraints"] == {"principal_verification": {"min": "2", "max": "2"}}
    assert proofs.parse_proof_request(request) == request
    with pytest.raises(ProofRequestError, match="ttl_seconds"):
        proofs.create_proof_request("a", ttl_seconds=0)
    with pytest.raises(ProofRequestError, match="scope"):
        proofs.create_proof_request("")
    with pytest.raises(ProofRequestError, match="registry"):
        proofs.create_proof_request("a", registry="0x1234")
    with pytest.raises(ProofRequestError, match="request_id"):
        proofs.create_proof_request("a", request_id="ABC")
    with pytest.raises(MainnetLockedError):
        proofs.create_proof_request("a", chain_id=8453)
    with pytest.raises(ProofRequestError, match="unix seconds"):
        proofs.create_proof_request("a", now=-1)


# --------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    ("constraints", "match"),
    [
        ([], "must be an object"),
        ({"balance": "1"}, "must be an object"),
        ({"balance": {"min": 1}}, "must be strings"),
        ({"balance": {"min": None}}, "must be strings"),
        ({"balance": {"min": "2", "max": "1"}}, "min is greater"),
        ({"shoe_size": {}}, "unknown attribute"),
        ({"balance": {"atleast": "1"}}, "unknown keys"),
    ],
)
def test_bounds_errors(constraints: Any, match: str) -> None:
    with pytest.raises(ProofRequestError, match=match):
        proofs.bounds({"constraints": constraints})


def test_bounds_of_empty_bounds_and_models() -> None:
    b = proofs.bounds({"constraints": {"balance": {}}})
    assert b.mins == (0,) * 13
    assert b.maxs == (proofs.MAX_U64,) * 13
    with pytest.raises(ProofRequestError):
        proofs.bounds(42)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"issued_at": "1760000100"},
        {"issued_at": True},
        {"issued_at": -1},
        {"expires_at": 1_760_000_100},
        {"chain_id": 2**53},
        {"nonce": REQUEST["nonce"] + "\n"},
        {"nonce": REQUEST["nonce"].upper()},
        {"request_id": "9042E173147DFED2E7948EBECF5C321B"},
        {"registry": "0x1234"},
        {"scope": ""},
        {"scope": 5},
        {"type": "agentbank.proof_request.v2"},
        {"constraints": {"balance": {"min": "1.0000001"}}},
        {"constraints": {"balance": {"min": "1\n"}}},
        {"constraints": {"balance": {"min": None}}},
        {"constraints": {"balance": None}},
        {"constraints": []},
        {"extra": 1},
    ],
)
def test_malformed_requests(changes: dict[str, Any]) -> None:
    with pytest.raises(ProofRequestError):
        proofs.parse_proof_request(request_with(**changes))
    result = proofs.verify_presentation(
        request_with(**changes), PRESENTATION, root_info=INFO, now=NOW
    )
    assert result.reason == "malformed"
    assert result.request is None


def test_requests_missing_fields_and_wrong_types() -> None:
    missing = {k: v for k, v in REQUEST.items() if k != "registry"}
    with pytest.raises(ProofRequestError, match="registry: required"):
        proofs.parse_proof_request(missing)
    with pytest.raises(ProofRequestError):
        proofs.parse_proof_request(["not", "a", "request"])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        proofs.request_data(42)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        proofs.presentation_data(42)  # type: ignore[arg-type]


def test_integral_floats_are_integers_as_in_javascript() -> None:
    floats = request_with(issued_at=1_760_000_100.0, expires_at=1_760_000_400.0)
    parsed = proofs.parse_proof_request(floats)
    assert proofs.request_hash(parsed) == PROOF["request_hash"]
    assert proofs.verify_presentation(floats, PRESENTATION, root_info=None, now=NOW).reason == (
        "unknown_root"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"root": "0x" + "ff" * 32},
        {"nullifier": "0x" + "ff" * 32},
        {"request_hash": "0x12"},
        {"type": "agentbank.proof.v2"},
        {"proof": {**PRESENTATION["proof"], "pi_a": ["1", "2"]}},
        {"proof": {**PRESENTATION["proof"], "pi_b": [["1", "2"], ["1", "2"], ["1"]]}},
        {"proof": {**PRESENTATION["proof"], "pi_c": ["1", "2", "01"]}},
        {"proof": {**PRESENTATION["proof"], "curve": "bls12381"}},
        {"proof": "nope"},
        {"extra": True},
    ],
)
def test_malformed_presentations(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        proofs.parse_presentation({**PRESENTATION, **changes})
    result = proofs.verify_presentation(
        REQUEST, {**PRESENTATION, **changes}, root_info=INFO, now=NOW
    )
    assert result.reason == "malformed"
    assert result.request is not None


def test_parse_presentation_models_and_garbage() -> None:
    model = proofs.parse_presentation(PRESENTATION)
    assert isinstance(model, ProofPresentation)
    assert proofs.parse_presentation(model) == model
    assert proofs.presentation_data(model) == PRESENTATION
    with pytest.raises(ValueError, match="presentation"):
        proofs.parse_presentation(42)  # type: ignore[arg-type]


# --------------------------------------------------------------------- witnesses


def test_check_witness_and_assert_provable() -> None:
    witness = ProofWitness.model_validate(WITNESS)
    proofs.assert_provable(witness, REQUEST)
    assert proofs.check_witness(WITNESS, REQUEST) == proofs.check_witness(witness, REQUEST)
    narrow = witness.model_copy(update={"disclosure_mask": proofs.disclosure_mask(["principal"])})
    with pytest.raises(ProofRefusedError) as undisclosed:
        proofs.assert_provable(narrow, REQUEST)
    assert undisclosed.value.reason == "undisclosed"
    assert undisclosed.value.code == "proof_refused"
    assert set(undisclosed.value.undisclosed_classes) == {
        "limits",
        "reservations",
        "account_age",
        "reputation",
    }
    rich = request_with(constraints={"balance": {"min": "2000.00"}})
    with pytest.raises(ProofRefusedError) as unsatisfiable:
        proofs.assert_provable(witness, rich)
    assert unsatisfiable.value.reason == "unsatisfiable"
    assert unsatisfiable.value.attributes == ("balance",)
    with pytest.raises(ProofRefusedError, match="chain") as chain:
        proofs.assert_provable(witness.model_copy(update={"chain_id": 31337}), REQUEST)
    assert chain.value.reason == "chain_mismatch"
    with pytest.raises(ProofRefusedError, match="registry"):
        proofs.assert_provable(witness.model_copy(update={"registry": None}), REQUEST)
    proofs.assert_provable(
        witness.model_copy(update={"registry": None}), request_with(registry=None)
    )
    garbled = {**WITNESS, "attributes": {**WITNESS["attributes"], "balance": "x"}}
    assert "balance" in proofs.check_witness(garbled, rich).out_of_bounds


def reservation(**changes: Any) -> ProofReservation:
    values: dict[str, Any] = {
        "status": "active",
        "amount": {"amount": "500.00", "asset": "USDC"},
        "scope_tag": str(proofs.scope_tag_of("api.seller.example")),
        "expires_at": "2025-10-09T10:55:00Z",
    }
    values.update(changes)
    return ProofReservation.model_validate(example("ProofReservation", **values))


def test_select_reservation() -> None:
    assert proofs.needs_reservation(REQUEST)
    assert not proofs.needs_reservation(request_with(constraints={}))
    best = reservation(id="prv_01JABCDEFGHJKMNPQRSTVWXYZ1")
    candidates = [
        reservation(
            id="prv_01JABCDEFGHJKMNPQRSTVWXYZ2", amount={"amount": "900.00", "asset": "USDC"}
        ),
        best,
        reservation(id="prv_01JABCDEFGHJKMNPQRSTVWXYZ3", status="pending"),
        reservation(
            id="prv_01JABCDEFGHJKMNPQRSTVWXYZ4", amount={"amount": "100.00", "asset": "USDC"}
        ),
        reservation(id="prv_01JABCDEFGHJKMNPQRSTVWXYZ5", scope_tag="1"),
        reservation(id="prv_01JABCDEFGHJKMNPQRSTVWXYZ6", expires_at="2025-10-09T09:00:00Z"),
    ]
    assert proofs.select_reservation(REQUEST, candidates, now=NOW) == best
    assert proofs.select_reservation(REQUEST, candidates[2:], now=NOW) is None
    assert proofs.select_reservation(REQUEST, [best], now=1_900_000_000) is None
    assert proofs.select_reservation(REQUEST, []) is None
    # The latest expiry wins over a smaller amount or a lower id, as in the TypeScript SDK.
    later = reservation(
        id="prv_01JABCDEFGHJKMNPQRSTVWXYZ9",
        amount={"amount": "800.00", "asset": "USDC"},
        expires_at="2025-10-09T11:00:00Z",
    )
    assert proofs.select_reservation(REQUEST, [*candidates, later], now=NOW) == later
    pending = reservation(id="prv_01JABCDEFGHJKMNPQRSTVWXYZ8", status="pending")
    assert proofs.select_reservation(REQUEST, [pending], now=NOW) is None
    assert proofs.select_reservation(REQUEST, [pending], now=NOW, status="pending") == pending


# --------------------------------------------------------------------- roots


def test_roots_status_and_checks() -> None:
    api_root = example(
        "ProofRoot",
        root=PROOF["root_info"]["root"],
        epoch="7",
        snapshot_at="2025-10-09T08:53:20Z",
        published_at="2025-10-09T08:53:32Z",
        valid_until="2025-10-09T10:53:20Z",
        leaf_count=20,
        status="published",
    )
    from agentbank.models import ProofRoot

    info = proofs.root_info_from_api(ProofRoot.model_validate(api_root))
    assert info == RootInfo(7, 1_760_000_000, 1_760_000_012, 1_760_007_200, 20, False, "published")
    pending = ProofRoot.model_validate({**api_root, "published_at": None, "status": "publishing"})
    assert proofs.root_info_from_api(pending).published_at is None
    assert proofs.root_status_of(None, NOW) is None
    assert proofs.root_status_of(info, NOW) == "published"
    assert proofs.root_status_of(info, 1_760_007_201) == "expired"
    assert proofs.root_status_of(RootInfo(1, 0, 1, 9, 1, True), NOW) == "revoked"
    assert proofs.root_status_of(RootInfo(1, 0, None, 9, 1, False), 0) == "publishing"
    assert proofs.root_status_of(RootInfo(1, 0, 1, 9, 1, False, "failed"), 0) == "failed"
    assert proofs.root_status_of(RootInfo(1, 0, 1, 9, 1, False, "expired"), 0) == "expired"
    assert proofs.check_root(info, REQUEST, NOW) is None
    assert (
        proofs.check_root(RootInfo(1, 0, 1, 9, 99, False, "failed"), REQUEST, 0) == "unknown_root"
    )
    assert (
        proofs.check_root(RootInfo(1, 0, 1, 9, 99, False, "revoked"), REQUEST, 0) == "root_revoked"
    )
    assert (
        proofs.check_root(RootInfo(1, 0, 1, 9, 99, False, "expired"), REQUEST, 0) == "root_expired"
    )


def test_verify_presentation_needs_a_root_source() -> None:
    with pytest.raises(TypeError, match="root_info or root_resolver"):
        proofs.verify_presentation(REQUEST, PRESENTATION)
    resolved = proofs.verify_presentation(
        REQUEST, PRESENTATION, root_resolver=lambda query: None, now=NOW
    )
    assert resolved.reason == "unknown_root"
    assert resolved.root == PRESENTATION["root"]
    assert resolved.request is not None
    nonce = proofs.verify_presentation(
        REQUEST, PRESENTATION, root_info=INFO, now=NOW, check_nonce=lambda r: "nonce_invalid"
    )
    assert nonce.reason == "nonce_invalid"
    expired = proofs.verify_presentation(REQUEST, PRESENTATION, root_info=INFO)
    assert expired.reason == "request_expired"


async def test_averify_presentation() -> None:
    with pytest.raises(TypeError):
        await proofs.averify_presentation(REQUEST, PRESENTATION)

    async def resolve(query: proofs.RootQuery) -> RootInfo | None:
        return None

    unknown = await proofs.averify_presentation(
        REQUEST, PRESENTATION, root_resolver=resolve, now=NOW
    )
    assert unknown.reason == "unknown_root"
    for check in (lambda r: "nonce_reused", None):
        result = await proofs.averify_presentation(
            "garbage" if check is None else REQUEST,  # type: ignore[arg-type]
            PRESENTATION,
            root_info=INFO,
            now=NOW,
            check_nonce=check,
        )
        assert result.reason == ("malformed" if check is None else "nonce_reused")
    mismatch = await proofs.averify_presentation(
        request_with(request_id="ab" * 16), PRESENTATION, root_info=INFO, now=NOW
    )
    assert mismatch.reason == "request_hash_mismatch"
    tooold = await proofs.averify_presentation(
        REQUEST, PRESENTATION, root_info=RootInfo(7, 0, 1, NOW + 9, 20, False), now=NOW
    )
    assert tooold.reason == "root_too_old"
    swapped = {**PRESENTATION, "nullifier": "0x" + "00" * 31 + "01"}
    invalid = await proofs.averify_presentation(REQUEST, swapped, root_info=INFO, now=NOW)
    assert invalid.reason == "invalid_proof"


# --------------------------------------------------------------------- Groth16


def test_verify_groth16_rejects_garbage_without_raising() -> None:
    signals = PROOF["public_signals"]
    good = PRESENTATION["proof"]
    cases: list[tuple[list[Any], dict[str, Any]]] = [
        (signals[:-1], good),
        ([*signals[:-1], str(proofs.SNARK_SCALAR_FIELD)], good),
        ([*signals[:-1], True], good),
        ([*signals[:-1], "1.5"], good),
        (signals, {**good, "protocol": "plonk"}),
        (signals, {**good, "pi_a": [*good["pi_a"][:2], "2"]}),
        (signals, {**good, "pi_a": good["pi_a"][:2]}),
        (signals, {**good, "pi_a": "1,2,1"}),
        (signals, {**good, "pi_a": ["1", "2", 1]}),
        (signals, {**good, "pi_a": [str(2**255), "2", "1"]}),
        (signals, {**good, "pi_b": [*good["pi_b"][:2], ["2", "0"]]}),
        (signals, {**good, "pi_b": [["1", "2"], ["3", "4"], ["1", "0"]]}),
        (signals, {**good, "pi_b": [["1", "2"], ["3"], ["1", "0"]]}),
        (signals, {**good, "pi_b": "nope"}),
        (signals, {**good, "pi_c": None}),
    ]
    for case_signals, case_proof in cases:
        assert proofs.verify_groth16(None, case_signals, case_proof) is False
    numeric = [int(s) for s in signals[:4]] + signals[4:]
    assert proofs.verify_groth16(None, numeric, {**good, "pi_c": ["1", "2", "1"]}) is False


def test_verify_groth16_with_a_bad_key() -> None:
    key = dict(proofs.load_verification_key())
    signals, proof = PROOF["public_signals"], PRESENTATION["proof"]
    for bad in (
        {**key, "curve": "bls12381"},
        {**key, "IC": []},
        {**key, "nPublic": 3},
        {**key, "vk_alpha_1": ["1", "2", "2"]},
    ):
        with pytest.raises(ValueError):  # noqa: PT011
            proofs.verify_groth16(bad, signals, proof)


def test_g2_points_must_be_in_the_subgroup() -> None:
    from agentbank import _groth16

    # (1, y) is on the twist curve but outside the prime-order subgroup.
    outside = [
        ["1", "0"],
        [
            "18278151005453108793778860132295291098363647455926340152056652516292830556603",
            "5912654199736721486680175016176231956195085055698687135131307249486702594212",
        ],
        ["1", "0"],
    ]
    with pytest.raises(ValueError, match="subgroup"):
        _groth16._g2(outside)
    proof = {**PRESENTATION["proof"], "pi_b": outside}
    assert proofs.verify_groth16(None, PROOF["public_signals"], proof) is False


# --------------------------------------------------------------------- HTTP headers


def test_header_json_round_trips() -> None:
    value = {"scope": "bücher.example", "n": 1}
    encoded = proofs.encode_header_json(value)
    assert proofs.decode_header_json(encoded) == value
    urlsafe = encoded.replace("+", "-").replace("/", "_").rstrip("=")
    assert proofs.decode_header_json(" " + urlsafe + " ") == value
    lone = proofs.decode_header_json(proofs.encode_header_json({"s": "a\ud800"}))
    assert lone == {"s": "a\ud800"}
    for bad in ("%%%", base64.b64encode(b"\xff").decode(), base64.b64encode(b"NaN").decode()):
        with pytest.raises(ProofHeaderError):
            proofs.decode_header_json(bad)
    with pytest.raises(ProofHeaderError):
        proofs.decode_header_json(None)  # type: ignore[arg-type]


def test_proof_header_codecs() -> None:
    required = proofs.encode_proof_required(REQUEST)
    assert proofs.request_data(proofs.decode_proof_required(required)) == REQUEST
    envelope = proofs.decode_proof(proofs.encode_proof(REQUEST, PRESENTATION))
    assert proofs.request_data(envelope.request) == REQUEST
    assert proofs.presentation_data(envelope.presentation) == PRESENTATION
    assert proofs.decode_proof(PROOF["agent_proof_header"]) == envelope
    with pytest.raises(ProofHeaderError, match="proof request"):
        proofs.decode_proof_required(proofs.encode_header_json({"type": "x"}))
    bad: Any
    for bad in ([], {"request": REQUEST}, {"request": REQUEST, "presentation": {}}):
        with pytest.raises(ProofHeaderError):
            proofs.decode_proof(proofs.encode_header_json(bad))
    nullifier = PRESENTATION["nullifier"]
    response = proofs.encode_proof_response(nullifier)
    assert proofs.decode_proof_response(response) == {"status": "accepted", "nullifier": nullifier}
    bad_response: Any
    for bad_response in ({"status": "accepted"}, {"status": "nope", "nullifier": nullifier}, []):
        with pytest.raises(ProofHeaderError):
            proofs.decode_proof_response(proofs.encode_header_json(bad_response))
    assert proofs.www_authenticate('a"b\\c') == 'AgentProof realm="a\\"b\\\\c"'
    assert proofs.PROOF_HEADERS.proof == proofs.PROOF_HEADER == "AGENT-PROOF"


# --------------------------------------------------------------------- replay caches


def test_memory_replay_cache() -> None:
    cache = MemoryReplayCache(max_entries=3)
    assert cache.consume("a", 100, 50)
    assert cache.has("a", 60)
    assert not cache.consume("a", 100, 60)
    assert not cache.has("a", 101)  # expired and evicted
    assert len(cache) == 0
    assert cache.consume("a", 200, 101)
    cache.consume("b", 30, 0)
    cache.consume("c", 20, 0)
    cache.consume("d", 40, 25)  # "c" expired: evicted
    assert len(cache) == 3
    cache.consume("e", 50, 25)  # full of live entries: drop "b" (soonest)
    assert not cache.has("b", 25)
    assert cache.has("e", 25)
    with pytest.raises(ValueError, match="positive"):
        MemoryReplayCache(max_entries=0)


# --------------------------------------------------------------------- gates


def test_gate_configuration_errors() -> None:
    def resolver(query: proofs.RootQuery) -> RootInfo | None:
        return None

    with pytest.raises(ValueError, match="32 bytes"):
        ProofGate(scope="a", key="short", root_resolver=resolver)
    with pytest.raises(ValueError, match="scope"):
        ProofGate(scope="", key=KEY, root_resolver=resolver)
    with pytest.raises(MainnetLockedError):
        ProofGate(scope="a", key=KEY, root_resolver=resolver, chain_id=1)
    with pytest.raises(AgentBankError, match="not supported"):
        ProofGate(scope="a", key=KEY, root_resolver=resolver, chain_id=999)
    with pytest.raises(ProofRequestError):
        ProofGate(
            scope="a",
            key=KEY,
            root_resolver=resolver,
            require=[proofs.verified_principal(), {"principal_verification": {"max": "0"}}],
        )


def test_gate_challenges() -> None:
    gate = ProofGate(
        scope="api.seller.example",
        key=OTHER_KEY,
        require=[proofs.verified_company()],
        root_resolver=lambda query: None,
        now=lambda: NOW,
    )
    assert gate.scope == "api.seller.example"
    challenge = gate.challenge("invalid_proof")
    assert challenge.status == 401
    assert challenge.headers["WWW-Authenticate"] == 'AgentProof realm="api.seller.example"'
    issued = proofs.decode_proof_required(challenge.headers["AGENT-PROOF-REQUIRED"])
    assert issued == challenge.request
    assert issued.nonce == proofs.gate_nonce(OTHER_KEY, issued)
    assert challenge.body == {
        "error": "proof_required",
        "reason": "invalid_proof",
        "request": proofs.request_data(issued),
    }
    for headers in ({}, {"AGENT-PROOF": "  "}, httpx.Headers({"x": "y"})):
        assert refusal(gate.check(headers)) is None
    assert refusal(gate.check({"Agent-Proof": ["not base64!"]})) == "malformed"
    assert refusal(gate.check({"agent-proof": []})) is None
    # A proof for another gate's request (same scope, another key) is a forgery.
    foreign = request_with(scope="api.seller.example")
    header = proofs.encode_proof(foreign, PRESENTATION)
    assert refusal(gate.check(httpx.Headers({"agent-proof": header}))) == "nonce_invalid"
    other_scope = proofs.encode_proof(request_with(scope="other.example"), PRESENTATION)
    assert refusal(gate.check({"AGENT-PROOF": other_scope})) == "nonce_invalid"


class SlowCache:
    """An async replay cache that loses the consume race."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def has(self, nonce: str, now: int) -> bool:
        self.calls.append("has")
        return False

    async def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        self.calls.append("consume")
        return False


async def test_async_gate_with_async_cache_treats_a_lost_race_as_a_replay() -> None:
    info = PROOF["root_info"]
    cache = SlowCache()
    gate = proofs.AsyncProofGate(
        scope="api.seller.example",
        key=KEY,
        require=[
            proofs.verified_company(),
            proofs.can_pay_per_tx("5.00"),
            proofs.reserved_for("500.00", for_seconds=3_600),
            proofs.reputation(disputes_lost_at_most=0),
            proofs.account_older_than(90),
        ],
        registry=PROOF["gate"]["registry"],
        replay_cache=cache,
        now=lambda: NOW,
        root_resolver=lambda query: RootInfo(
            int(info["epoch"]),
            info["snapshot_at"],
            info["published_at"],
            info["valid_until"],
            info["leaf_count"],
            info["revoked"],
        ),
    )
    result = await gate.check({"AGENT-PROOF": PROOF["agent_proof_header"]})
    assert refusal(result) == "nonce_reused"
    assert cache.calls == ["has", "consume"]
    assert refusal(await gate.check({})) is None
    forged = proofs.encode_proof(request_with(nonce="0x" + "ab" * 31), PROOF["presentation"])
    assert refusal(await gate.check({"AGENT-PROOF": forged})) == "nonce_invalid"


class RacyCache:
    """A replay cache that loses the consume race to another instance."""

    def has(self, nonce: str, now: int) -> bool:
        return False

    def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        return False


def test_gate_treats_a_lost_consume_race_as_a_replay() -> None:
    info = PROOF["root_info"]
    gate = ProofGate(
        scope="api.seller.example",
        key=KEY,
        require=[
            proofs.verified_company(),
            proofs.can_pay_per_tx("5.00"),
            proofs.reserved_for("500.00", for_seconds=3_600),
            proofs.reputation(disputes_lost_at_most=0),
            proofs.account_older_than(90),
        ],
        registry=PROOF["gate"]["registry"],
        replay_cache=RacyCache(),
        now=lambda: NOW,
        root_resolver=lambda query: RootInfo(
            7, info["snapshot_at"], info["published_at"], info["valid_until"], 20, False
        ),
    )
    assert refusal(gate.check({"AGENT-PROOF": PROOF["agent_proof_header"]})) == "nonce_reused"


# --------------------------------------------------------------------- the prover


@pytest.fixture
def prover_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FAKE_PROVER_LOG", str(tmp_path))
    return tmp_path


def calls(log: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text("utf-8")) for p in sorted(log.glob("call-*.json"))]


def test_prover_proves_through_stdin(prover_log: Path) -> None:
    prover = Prover(FAKE_PROVER)
    assert prover.configured
    assert prover.command is not None
    assert prover.command[-1].endswith("fake_prover.py")
    presentation = prover.prove(secret=SECRET, witness=WITNESS, request=REQUEST)
    assert presentation.request_hash == PROOF["request_hash"]
    assert presentation.nullifier == PRESENTATION["nullifier"]
    (call,) = calls(prover_log)
    assert call["argv"] == ["prove"]
    sent = json.loads(call["stdin"])
    assert sent == {"secret": SECRET, "witness": WITNESS, "request": REQUEST}
    model = ProofWitness.model_validate(WITNESS)
    again = prover.prove(secret=SECRET.upper().replace("0X", "0x"), witness=model, request=REQUEST)
    assert again == presentation
    resent = json.loads(calls(prover_log)[1]["stdin"])
    assert resent["secret"] == SECRET
    assert ProofWitness.model_validate(resent["witness"]) == model


def test_prover_identity(prover_log: Path) -> None:
    prover = Prover([sys.executable, str(Path(__file__).parent / "fake_prover.py")])
    identity = prover.identity(SECRET)
    assert identity.secret == SECRET
    # Normalized to lowercase whatever case the prover answers in.
    assert identity.identity_commitment == VECTORS["poseidon"]["identity"]["identity_commitment"]
    assert SECRET not in repr(identity)
    fresh = prover.identity()
    assert fresh.secret == "0x00" + "11" * 31
    assert [c["argv"] for c in calls(prover_log)] == [["identity"], ["identity"]]
    assert calls(prover_log)[1]["stdin"] == ""


@pytest.mark.parametrize(
    ("behavior", "error", "reason"),
    [
        ("refuse", ProofRefusedError, "witness_mismatch"),
        ("refuse-odd", ProofRefusedError, "unsatisfiable"),
        ("invalid", ProverError, "invalid_input"),
        ("crash", ProverError, "prover_failed"),
        ("crash-plain", ProverError, "prover_failed"),
        ("silent", ProverError, "prover_failed"),
        ("garbage", ProverError, "prover_failed"),
    ],
)
def test_prover_failures(
    behavior: str, error: type[ProofError], reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_PROVER", behavior)
    with pytest.raises(error) as raised:
        Prover(FAKE_PROVER).prove(secret=SECRET, witness=WITNESS, request=REQUEST)
    assert raised.value.reason == reason
    assert SECRET not in str(raised.value)
    assert SECRET[2:] not in str(raised.value)


def test_prover_identity_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_PROVER", "bad-identity")
    with pytest.raises(ProverError, match="invalid identity"):
        Prover(FAKE_PROVER).identity()


def test_prover_configuration_and_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ProverError) as missing:
        Prover().prove(secret=SECRET, witness=WITNESS, request=REQUEST)
    assert missing.value.reason == "prover_not_configured"
    assert missing.value.code == "configuration_error"
    monkeypatch.setenv("AGENTBANK_PROVER", FAKE_PROVER)
    assert Prover().configured
    with pytest.raises(ProverError, match="not found") as absent:
        Prover("/nonexistent/agentbank-prove").identity()
    assert absent.value.reason == "prover_not_configured"
    with pytest.raises(ProverError, match="Could not run"):
        Prover(str(Path(__file__).parent)).identity()
    monkeypatch.setenv("FAKE_PROVER", "sleep")
    with pytest.raises(ProverError, match="within") as slow:
        Prover(FAKE_PROVER, timeout=0.5).prove(secret=SECRET, witness=WITNESS, request=REQUEST)
    assert slow.value.reason == "prover_timeout"


@pytest.mark.parametrize("secret", ["", "nothex", "0x" + "00" * 32, "0x" + "ff" * 32, 42])
def test_prover_rejects_bad_secrets(secret: Any) -> None:
    with pytest.raises(ProverError) as raised:
        Prover(FAKE_PROVER).prove(secret=secret, witness=WITNESS, request=REQUEST)
    assert raised.value.reason == "invalid_input"


async def test_async_prover(prover_log: Path) -> None:
    prover = AsyncProver(FAKE_PROVER, timeout=60)
    assert prover.configured
    assert prover.command == Prover(FAKE_PROVER).command
    assert repr(prover).startswith("AsyncProver(command=")
    presentation = await prover.prove(secret=SECRET, witness=WITNESS, request=REQUEST)
    assert presentation.request_hash == PROOF["request_hash"]
    identity = await prover.identity(SECRET)
    assert identity.identity_commitment.startswith("0x159d")


def test_secrets_and_receipts(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = proofs.generate_proof_secret()
    assert len(secret) == 66
    assert secret.startswith("0x00")
    assert proofs.proof_secret_from_env() is None
    monkeypatch.setenv("AGENTBANK_PROOF_SECRET", f" {secret} ")
    assert proofs.proof_secret_from_env() == secret
    assert proofs.proof_receipt(object()) is None
    assert proofs.proof_receipt(httpx.Response(200)) is None
    assert repr(Prover(FAKE_PROVER)).startswith("Prover(command=(")


def test_proof_errors_are_agentbank_errors() -> None:
    refused = ProofRefusedError("reservation_required", "nothing reserved", attributes=("balance",))
    assert isinstance(refused, AgentBankError)
    assert refused.to_problem()["attributes"] == ["balance"]
    assert ProofError("odd", "x").code == "proof_error"
    assert ProverError("prover_timeout", "slow").code == "prover_error"
    assert ProofError("scope_not_allowed", "x").status == 403
    when = datetime.now(timezone.utc) + timedelta(days=1)
    assert proofs.create_proof_request("a", now=when).issued_at > 0
