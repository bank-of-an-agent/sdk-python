"""Cross-language private-proof vectors shared with ``@agentbank/proofs``.

``tests/proof_vectors.json`` is a verbatim copy of
``agent-bank/packages/proofs/test/vectors/proofs.json`` (refresh it with
``scripts/refresh_proofs.sh``). Scopes, tags, bounds, request hashes and gate nonces
must match byte for byte; the gate-issued presentation (a real Groth16 proof) must
verify, once, and every tampered variant must be refused for the stated reason.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentbank import proofs
from agentbank.canonical import canonical_json
from agentbank.errors import ProofRequestError
from agentbank.models import ProofRequest
from agentbank.proofs import (
    AsyncProofGate,
    ProofGate,
    ProofVerified,
    RootInfo,
    RootQuery,
)

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "proof_vectors.json").read_text("utf-8")
)
PROOF = VECTORS["proof"]
GATE = PROOF["gate"]
NOW = 1_760_000_100
REGISTRY = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
FIXED: dict[str, Any] = {
    "now": NOW,
    "chain_id": 84532,
    "registry": REGISTRY,
    "nonce": "0x" + "5e" * 31,
    "request_id": "9f2c1b0e5a7d4c3b8e6f1a2b3c4d5e6f",
}
#: What the vector gate requires (test/fixtures.ts GATE_REQUIREMENTS).
GATE_REQUIREMENTS: list[proofs.Requirement] = [
    proofs.verified_company(),
    proofs.can_pay_per_tx("5.00"),
    proofs.reserved_for("500.00", for_seconds=3_600),
    proofs.reputation(disputes_lost_at_most=0),
    proofs.account_older_than(90),
]


def root_info(json_info: dict[str, Any] | None) -> RootInfo | None:
    if json_info is None:
        return None
    return RootInfo(
        epoch=int(json_info["epoch"]),
        snapshot_at=json_info["snapshot_at"],
        published_at=json_info["published_at"],
        valid_until=json_info["valid_until"],
        leaf_count=json_info["leaf_count"],
        revoked=json_info["revoked"],
    )


def vector_gate(json_info: dict[str, Any] | None, now: int) -> ProofGate:
    def resolve(query: RootQuery) -> RootInfo | None:
        if json_info is not None:
            assert query.root == json_info["root"].lower()
            assert query.chain_id == GATE["chain_id"]
            assert query.registry == GATE["registry"]
        return root_info(json_info)

    return ProofGate(
        scope=GATE["scope"],
        key=GATE["key_utf8"],
        require=GATE_REQUIREMENTS,
        ttl_seconds=GATE["ttl_seconds"],
        chain_id=GATE["chain_id"],
        registry=GATE["registry"],
        min_anonymity_set=GATE["min_anonymity_set"],
        max_root_age_seconds=GATE["max_root_age_seconds"],
        now=lambda: now,
        root_resolver=resolve,
    )


# --------------------------------------------------------------------- constants


def test_constants_match() -> None:
    constants = VECTORS["constants"]
    assert VECTORS["schema"] == proofs.CLAIMS_SCHEMA
    assert str(proofs.SNARK_SCALAR_FIELD) == constants["snark_scalar_field"]
    assert str(proofs.MAX_U64) == constants["max_u64"]
    assert constants["tree_depth"] == proofs.TREE_DEPTH
    assert list(proofs.ATTRIBUTES) == constants["attributes"]
    assert {k: list(v) for k, v in proofs.CLASS_ATTRIBUTES.items()} == constants[
        "disclosure_classes"
    ]
    assert constants["scope_domain"] == proofs.SCOPE_DOMAIN


def test_bundled_circuit_files_match_the_manifest() -> None:
    manifest = proofs.circuit_manifest()
    assert manifest["schema"] == proofs.CLAIMS_SCHEMA
    assert manifest["attributes"] == list(proofs.ATTRIBUTES)
    assert len(manifest["public_signals"]) == proofs.PUBLIC_SIGNAL_COUNT
    key = proofs.load_verification_key()
    assert key["nPublic"] == proofs.PUBLIC_SIGNAL_COUNT
    raw = (Path(proofs.__file__).parent / "proofs_data" / "verification_key.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]["verification_key"]


@pytest.mark.parametrize("case", VECTORS["disclosure_masks"], ids=lambda c: str(c["mask"]))
def test_disclosure_masks(case: dict[str, Any]) -> None:
    assert proofs.disclosure_mask(case["classes"]) == case["mask"]
    assert proofs.classes_from_mask(case["mask"]) == case["classes"]


# --------------------------------------------------------------------- scopes


@pytest.mark.parametrize("case", VECTORS["scopes"], ids=lambda c: c["scope_id"][:20])
def test_scope_fields_and_tags(case: dict[str, Any]) -> None:
    scope = proofs.scope_field(case["scope_id"])
    assert str(scope) == case["scope"]
    assert proofs.to_bytes32(scope) == case["scope_bytes32"]
    assert str(proofs.scope_tag(scope)) == case["tag"]
    assert str(proofs.scope_tag_of(case["scope_id"])) == case["tag"]


@pytest.mark.parametrize("case", VECTORS["onchain_scopes"], ids=lambda c: c["consumer"][:10])
def test_onchain_scopes(case: dict[str, Any]) -> None:
    scope = proofs.onchain_scope(case["chain_id"], case["consumer"], case["context"])
    assert str(scope) == case["scope"]
    assert str(proofs.scope_tag(scope)) == case["tag"]


# --------------------------------------------------------------------- bounds


@pytest.mark.parametrize(
    "case", VECTORS["money_bounds"] + VECTORS["integer_bounds"], ids=lambda c: repr(c["value"])
)
def test_bound_values(case: dict[str, Any]) -> None:
    if case.get("error"):
        with pytest.raises(ProofRequestError):
            proofs.parse_bound_value(case["attribute"], case["value"])
        return
    expected = case.get("minor", case.get("value_parsed"))
    assert str(proofs.parse_bound_value(case["attribute"], case["value"])) == expected


def build_request(name: str) -> ProofRequest:
    scope = "api.seller.example"
    if name == "empty":
        return proofs.create_proof_request(scope, **FIXED)
    if name == "standard":
        require: list[proofs.Requirement] = [
            proofs.verified_company(),
            proofs.can_pay_per_tx("5.00"),
            proofs.balance_at_least("1000.00"),
            proofs.reputation(disputes_lost_at_most=0, payments_settled=10),
            proofs.account_older_than(90),
        ]
    elif name == "every_kind":
        require = [
            proofs.verified_principal(),
            proofs.can_pay_per_tx("2.5"),
            proofs.can_pay_per_day("100"),
            proofs.spending_capped_at(per_tx="250.000001", per_day="1000"),
            proofs.balance_at_least("0.000001"),
            proofs.reserved_for("500.00", until=NOW + 3_600),
            proofs.account_older_than(30),
            proofs.reputation(
                payments_settled=10,
                volume_settled="1234.5",
                escrows_completed=2,
                disputes_lost_at_most=1,
                counterparties=3,
            ),
        ]
    else:
        require = [
            proofs.verified_principal(),
            proofs.verified_company(),
            proofs.can_pay_per_tx("1"),
            proofs.can_pay_per_tx("3"),
        ]
    return proofs.create_proof_request(scope, require=require, **FIXED)


@pytest.mark.parametrize("case", VECTORS["requests"], ids=lambda c: c["name"])
def test_requests_hashes_and_bounds(case: dict[str, Any]) -> None:
    built = build_request(case["name"])
    assert proofs.request_data(built) == case["request"]
    assert canonical_json(case["request"]) == case["canonical_json"]
    assert proofs.request_hash(built) == case["request_hash"]
    assert proofs.request_hash(case["request"]) == case["request_hash"]
    b = proofs.bounds(case["request"])
    assert [str(v) for v in b.mins] == case["mins"]
    assert [str(v) for v in b.maxs] == case["maxs"]
    assert proofs.bounds(built) == b


@pytest.mark.parametrize("case", VECTORS["invalid_requests"], ids=lambda c: c["name"])
def test_invalid_requests_are_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ProofRequestError):
        proofs.parse_proof_request(case["request"])
    result = proofs.verify_presentation(
        case["request"], PROOF["presentation"], root_info=None, now=NOW
    )
    assert result.reason == "malformed"


@pytest.mark.parametrize("case", VECTORS["gate_nonces"]["cases"], ids=lambda c: c["nonce"][:10])
def test_gate_nonces(case: dict[str, Any]) -> None:
    keys = VECTORS["gate_nonces"]
    assert canonical_json(case["request_without_nonce"]) == case["canonical_json"]
    assert proofs.gate_nonce(keys["key_utf8"], case["request_without_nonce"]) == case["nonce"]
    key_bytes = bytes.fromhex(keys["key_hex"][2:])
    assert proofs.gate_nonce(key_bytes, case["request_without_nonce"]) == case["nonce"]


# --------------------------------------------------------------------- the real proof


def test_gate_issued_request_and_signals() -> None:
    request = PROOF["request"]
    assert request["nonce"] == proofs.gate_nonce(GATE["key_utf8"], request)
    assert proofs.request_hash(request) == PROOF["request_hash"]
    assert proofs.public_signals(request, PROOF["presentation"]) == PROOF["public_signals"]
    # A gate configured like the vector's, at its clock, issues exactly this request
    # (up to the random request id).
    issued = vector_gate(PROOF["root_info"], GATE["now"]).create_request()
    expected = {**request, "request_id": issued.request_id}
    expected["nonce"] = proofs.gate_nonce(GATE["key_utf8"], expected)
    assert proofs.request_data(issued) == expected


def test_vector_presentation_verifies() -> None:
    result = proofs.verify_presentation(
        PROOF["request"],
        PROOF["presentation"],
        root_info=root_info(PROOF["root_info"]),
        now=GATE["now"],
    )
    assert result.valid
    assert result.reason is None
    assert result.nullifier == PROOF["expected"]["nullifier"]
    assert result.root == PROOF["expected"]["root"]
    assert result.request is not None
    assert result.request.nonce == PROOF["request"]["nonce"]
    assert proofs.verify_groth16(
        proofs.load_verification_key(),
        PROOF["public_signals"],
        proofs.parse_presentation(PROOF["presentation"]).proof,
    )


def test_gate_accepts_the_vector_once() -> None:
    gate = vector_gate(PROOF["root_info"], GATE["now"])
    headers = {"AGENT-PROOF": PROOF["agent_proof_header"]}
    first = gate.check(headers)
    assert isinstance(first, ProofVerified)
    assert first.nullifier == PROOF["expected"]["nullifier"]
    assert first.root == PROOF["expected"]["root"]
    accepted = proofs.decode_proof_response(first.headers["AGENT-PROOF-RESPONSE"])
    assert accepted == {"status": "accepted", "nullifier": first.nullifier}
    replay = gate.check({"agent-proof": PROOF["agent_proof_header"]})
    assert replay.kind == "proof-required"
    assert replay.reason == "nonce_reused"
    assert replay.response.status == 401
    assert replay.response.body["reason"] == "nonce_reused"


async def test_async_gate_accepts_the_vector_once() -> None:
    async def resolve(query: RootQuery) -> RootInfo | None:
        assert query.root == PROOF["root_info"]["root"]
        return root_info(PROOF["root_info"])

    gate = AsyncProofGate(
        scope=GATE["scope"],
        key=GATE["key_utf8"].encode("utf-8"),
        require=GATE_REQUIREMENTS,
        registry=GATE["registry"],
        now=lambda: GATE["now"],
        root_resolver=resolve,
    )
    headers = {"AGENT-PROOF": PROOF["agent_proof_header"]}
    first = await gate.check(headers)
    assert first.kind == "verified"
    second = await gate.check(headers)
    assert second.kind == "proof-required"
    assert second.reason == "nonce_reused"


@pytest.mark.parametrize("case", VECTORS["tampered"], ids=lambda c: c["name"])
def test_tampered_variants_are_refused_by_the_gate(case: dict[str, Any]) -> None:
    gate = vector_gate(case["root_info"], case["now"])
    headers = {"AGENT-PROOF": case["agent_proof_header"]}
    if case.get("submit_twice"):
        assert gate.check(headers).kind == "verified"
    result = gate.check(headers)
    assert result.kind == "proof-required"
    assert result.reason == case["expected_reason"]


def test_tampered_variants_cover_every_reason() -> None:
    reasons = {case["expected_reason"] for case in VECTORS["tampered"]}
    assert reasons == set(proofs.PROOF_FAILURE_REASONS)


@pytest.mark.parametrize(
    "case",
    [c for c in VECTORS["tampered"] if not c["expected_reason"].startswith("nonce_")],
    ids=lambda c: c["name"],
)
def test_tampered_variants_are_refused_without_a_gate(case: dict[str, Any]) -> None:
    result = proofs.verify_presentation(
        case["request"],
        case["presentation"],
        root_info=root_info(case["root_info"]),
        now=case["now"],
    )
    assert not result.valid
    assert result.reason == case["expected_reason"]
    assert result.nullifier is None
