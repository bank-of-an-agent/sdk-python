"""Private proofs (schema ``agentbank.claims.v1``): requests, verification and the HTTP gate.

An agent proves a statement about itself ("a verified company backs me, I can pay
$5 a call, $500 is reserved for you") without revealing which agent it is; the
verifier learns only that the statement holds. Agent Bank attests 13 facts per
agent in a Poseidon Merkle tree whose root is published on Base; the agent proves
membership and bounds with a Groth16 proof (design: ``docs/private-proofs.md`` in
the monorepo). Byte-for-byte compatible with ``@agentbank/proofs`` (shared vectors).

**Verifiers** (a seller, an MCP tool provider) build requests from requirements and
check presentations in pure Python (``py_ecc``, about a second per proof)::

    from agentbank import AgentBank
    from agentbank.proofs import ProofGate, can_pay_per_tx, reserved_for, verified_company

    bank = AgentBank()  # public endpoints only: no credentials needed
    gate = ProofGate(
        scope="api.seller.example",  # your host name
        key=os.environ["PROOF_GATE_KEY"],  # >= 32 bytes; nonces are HMACs, no state
        require=[
            verified_company(),
            can_pay_per_tx("5.00"),
            reserved_for("500.00", for_seconds=3600),
        ],
        root_resolver=bank.proofs.root_resolver(),
    )
    result = gate.check(request.headers)  # reads AGENT-PROOF
    if result.kind == "proof-required":
        return Response(status=401, headers=result.response.headers, json=result.response.body)

**Agents** prove through the ``agentbank-prove`` CLI of ``@agentbank/proofs``
(``AGENTBANK_PROVER``), because proving needs the circuit's WebAssembly witness
generator; see :class:`Prover` and ``bank.proofs.prove``. The agent's proof secret
(``AGENTBANK_PROOF_SECRET``) is only ever written to the prover's stdin.

Testnet only: the proving key comes from a single-party, testnet-only setup.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import inspect
import json
import os
import re
import secrets
import shlex
import subprocess
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from functools import partial
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, TypeVar, get_args

import anyio.to_thread
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak

from agentbank.canonical import MAX_SAFE_INTEGER, canonical_json, canonical_keccak, to_jsonable
from agentbank.chains import DEFAULT_CHAIN_ID, assert_testnet
from agentbank.errors import (
    ProofHeaderError,
    ProofRefusedError,
    ProofRequestError,
    ProverError,
)
from agentbank.models import (
    Groth16Proof,
    ProofPresentation,
    ProofRequest,
    ProofReservation,
    ProofRoot,
    ProofWitness,
)
from agentbank.money import format_amount, parse_amount

__all__ = [
    "ATTRIBUTES",
    "ATTRIBUTE_COUNT",
    "ATTRIBUTE_INFO",
    "CLAIMS_SCHEMA",
    "CLASS_ATTRIBUTES",
    "DEFAULT_MAX_ROOT_AGE_SECONDS",
    "DEFAULT_MIN_ANONYMITY_SET",
    "DEFAULT_PROVER_TIMEOUT",
    "DEFAULT_TTL_SECONDS",
    "DISCLOSURE_CLASSES",
    "FULL_DISCLOSURE_MASK",
    "MAX_SCOPE_LENGTH",
    "MAX_U64",
    "PROOF_AUTH_SCHEME",
    "PROOF_FAILURE_REASONS",
    "PROOF_HEADER",
    "PROOF_HEADERS",
    "PROOF_RECEIPT_EXTENSION",
    "PROOF_REQUEST_TYPE",
    "PROOF_REQUIRED_HEADER",
    "PROOF_RESPONSE_HEADER",
    "PROOF_SECRET_ENV",
    "PROOF_TYPE",
    "PROVER_ENV",
    "PUBLIC_SIGNAL_COUNT",
    "SCOPE_DOMAIN",
    "SNARK_SCALAR_FIELD",
    "TREE_DEPTH",
    "AsyncProofGate",
    "AsyncProver",
    "AsyncReplayCache",
    "AsyncRootResolver",
    "Attribute",
    "AttributeInfo",
    "AttributeKind",
    "Bounds",
    "Constraints",
    "DisclosureClass",
    "MemoryReplayCache",
    "ProofChallenge",
    "ProofEnvelope",
    "ProofFailureReason",
    "ProofGate",
    "ProofGateResult",
    "ProofReceipt",
    "ProofRequired",
    "ProofRootStatus",
    "ProofVerified",
    "Prover",
    "ProverIdentity",
    "ReplayCache",
    "Requirement",
    "RequirementContext",
    "RootInfo",
    "RootQuery",
    "RootResolver",
    "VerificationResult",
    "WitnessCheck",
    "account_older_than",
    "assert_provable",
    "averify_presentation",
    "balance_at_least",
    "bounds",
    "can_pay_per_day",
    "can_pay_per_tx",
    "check_root",
    "check_witness",
    "circuit_manifest",
    "classes_from_mask",
    "create_proof_request",
    "decode_header_json",
    "decode_proof",
    "decode_proof_required",
    "decode_proof_response",
    "disclosure_mask",
    "encode_header_json",
    "encode_proof",
    "encode_proof_required",
    "encode_proof_response",
    "format_bound_value",
    "from_bytes32",
    "gate_nonce",
    "generate_proof_secret",
    "is_disclosed",
    "load_verification_key",
    "merge_constraints",
    "needs_reservation",
    "nonce_field",
    "onchain_scope",
    "parse_bound_value",
    "parse_presentation",
    "parse_proof_request",
    "parse_usdc_bound",
    "presentation_data",
    "proof_receipt",
    "proof_secret_from_env",
    "public_signals",
    "random_nonce",
    "reputation",
    "request_data",
    "request_hash",
    "reserved_for",
    "root_info_from_api",
    "root_status_of",
    "scope_field",
    "scope_tag",
    "scope_tag_of",
    "select_reservation",
    "spending_capped_at",
    "to_bytes32",
    "verified_company",
    "verified_principal",
    "verify_groth16",
    "verify_presentation",
    "www_authenticate",
]

T = TypeVar("T")

# ===================================================================== schema

CLAIMS_SCHEMA: Final = "agentbank.claims.v1"
PROOF_REQUEST_TYPE: Final = "agentbank.proof_request.v1"
PROOF_TYPE: Final = "agentbank.proof.v1"

#: The 13 attested attributes, in circuit order.
Attribute = Literal[
    "principal_verification",
    "per_tx_limit",
    "per_day_limit",
    "balance",
    "reserved_amount",
    "reserved_until",
    "reserved_for",
    "account_created_on",
    "payments_settled",
    "volume_settled",
    "escrows_completed",
    "disputes_lost",
    "counterparties",
]

#: Attributes in circuit order (index = position in ``mins``/``maxs`` and in the leaf).
ATTRIBUTES: Final[tuple[Attribute, ...]] = get_args(Attribute)

#: What an owner may let an agent prove; each class covers one or more attributes.
DisclosureClass = Literal[
    "principal", "limits", "balance", "reservations", "account_age", "reputation"
]

DISCLOSURE_CLASSES: Final[tuple[DisclosureClass, ...]] = get_args(DisclosureClass)

#: How bounds on an attribute are written: ``money`` as decimal USDC strings
#: (``"5.00"``, compared in minor units), ``integer`` counts and tags, ``timestamp``
#: unix seconds and ``enum`` codes (principal_verification: 0 none, 1 individual,
#: 2 company), all as base-10 strings.
AttributeKind = Literal["money", "integer", "timestamp", "enum"]

#: Why a presentation was refused, in the order the checks run.
ProofFailureReason = Literal[
    "malformed",
    "request_expired",
    "nonce_invalid",
    "nonce_reused",
    "request_hash_mismatch",
    "unknown_root",
    "root_revoked",
    "root_expired",
    "root_too_old",
    "anonymity_set_too_small",
    "invalid_proof",
]

PROOF_FAILURE_REASONS: Final[tuple[ProofFailureReason, ...]] = get_args(ProofFailureReason)

#: Lifecycle of a published root: publishing -> published -> (revoked | expired), or failed.
ProofRootStatus = Literal["publishing", "published", "revoked", "expired", "failed"]


@dataclass(frozen=True)
class AttributeInfo:
    """Where an attribute sits in the circuit and who may disclose it.

    Attributes:
        index: Position in circuit order.
        kind: How its bounds are written (see :data:`AttributeKind`).
        disclosure_class: The class an owner discloses it with.
    """

    index: int
    kind: AttributeKind
    disclosure_class: DisclosureClass


ATTRIBUTE_INFO: Final[Mapping[Attribute, AttributeInfo]] = MappingProxyType(
    {
        "principal_verification": AttributeInfo(0, "enum", "principal"),
        "per_tx_limit": AttributeInfo(1, "money", "limits"),
        "per_day_limit": AttributeInfo(2, "money", "limits"),
        "balance": AttributeInfo(3, "money", "balance"),
        "reserved_amount": AttributeInfo(4, "money", "reservations"),
        "reserved_until": AttributeInfo(5, "timestamp", "reservations"),
        "reserved_for": AttributeInfo(6, "integer", "reservations"),
        "account_created_on": AttributeInfo(7, "timestamp", "account_age"),
        "payments_settled": AttributeInfo(8, "integer", "reputation"),
        "volume_settled": AttributeInfo(9, "money", "reputation"),
        "escrows_completed": AttributeInfo(10, "integer", "reputation"),
        "disputes_lost": AttributeInfo(11, "integer", "reputation"),
        "counterparties": AttributeInfo(12, "integer", "reputation"),
    }
)

#: The attributes each disclosure class covers, in circuit order.
CLASS_ATTRIBUTES: Final[Mapping[DisclosureClass, tuple[Attribute, ...]]] = MappingProxyType(
    {
        c: tuple(a for a in ATTRIBUTES if ATTRIBUTE_INFO[a].disclosure_class == c)
        for c in DISCLOSURE_CLASSES
    }
)

_CLASS_ATTRIBUTES_BY_NAME: Final[dict[str, tuple[Attribute, ...]]] = {
    str(name): attributes for name, attributes in CLASS_ATTRIBUTES.items()
}

ATTRIBUTE_COUNT: Final = 13
TREE_DEPTH: Final = 20
#: nullifier, root, scope, nonce, mins[13], maxs[13].
PUBLIC_SIGNAL_COUNT: Final = 4 + 2 * ATTRIBUTE_COUNT
#: Every attribute and bound is below 2^64; ``[0, MAX_U64]`` means "unconstrained".
MAX_U64: Final = 2**64 - 1
#: The BN254 scalar field order r: public signals, roots and nullifiers are below it.
SNARK_SCALAR_FIELD: Final = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
#: Mask with every attribute disclosed.
FULL_DISCLOSURE_MASK: Final = (1 << ATTRIBUTE_COUNT) - 1

SCOPE_DOMAIN: Final = "agentbank.proofs.scope.v1"
MAX_SCOPE_LENGTH: Final = 253

DEFAULT_TTL_SECONDS: Final = 300
DEFAULT_MAX_ROOT_AGE_SECONDS: Final = 7_200
DEFAULT_MIN_ANONYMITY_SET: Final = 16

_SECONDS_PER_DAY = 86_400
_USDC_DECIMALS = 6
_USDC_SCALE = 1_000_000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Patterns are used with fullmatch (JavaScript's ``^...$`` without the multiline flag).
_BYTES32_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX_FIELD_RE = re.compile(r"0x[0-9a-fA-F]{1,64}")
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}")
_NONCE_RE = re.compile(r"0x[0-9a-f]{62}")
_ANY_CASE_NONCE_RE = re.compile(r"0x[0-9a-fA-F]{62}")
_BOUND_RE = re.compile(r"(0|[1-9][0-9]{0,19})(\.[0-9]{1,6})?")
_FIELD_DECIMAL_RE = re.compile(r"0|[1-9][0-9]{0,76}")
_INTEGER_RE = re.compile(r"0|[1-9][0-9]*")
_DECIMAL_RE = re.compile(r"(0|[1-9][0-9]*)(?:\.([0-9]+))?")


def _is_int(value: object) -> bool:
    """An ``int`` that is not a ``bool`` (checked at runtime: callers may pass anything)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    """Whether ``value`` is a string that fully matches ``pattern``."""
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def is_attribute(value: object) -> bool:
    """Whether ``value`` names one of the 13 attributes."""
    return isinstance(value, str) and value in ATTRIBUTE_INFO


def disclosure_mask(classes: Iterable[str]) -> int:
    """The 13-bit disclosure mask for some classes (bit i set when attribute i is disclosed).

    Raises:
        ValueError: A class is unknown.
    """
    mask = 0
    for name in classes:
        attributes = _CLASS_ATTRIBUTES_BY_NAME.get(name)
        if attributes is None:
            raise ValueError(f'unknown disclosure class "{name}"')
        for attribute in attributes:
            mask |= 1 << ATTRIBUTE_INFO[attribute].index
    return mask


def classes_from_mask(mask: int) -> list[DisclosureClass]:
    """The classes a disclosure mask discloses, in class order.

    Raises:
        ValueError: The mask is outside [0, 8191] or discloses part of a class.
    """
    if not _is_int(mask) or not 0 <= mask <= FULL_DISCLOSURE_MASK:
        raise ValueError(f"disclosure mask {mask} is not a 13-bit integer")
    classes = [c for c in DISCLOSURE_CLASSES if mask & disclosure_mask([c]) == disclosure_mask([c])]
    if disclosure_mask(classes) != mask:
        raise ValueError(f"disclosure mask {mask} discloses part of a class")
    return classes


def is_disclosed(mask: int, attribute: Attribute) -> bool:
    """Whether ``attribute`` is disclosed by ``mask``."""
    return mask & (1 << ATTRIBUTE_INFO[attribute].index) != 0


# ===================================================================== field elements


def _utf16_length(value: str) -> int:
    """``value.length`` in JavaScript (UTF-16 code units)."""
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _js_utf8(value: str) -> bytes:
    """UTF-8 bytes as ``TextEncoder`` produces them (lone surrogates become U+FFFD)."""
    utf16 = value.encode("utf-16-le", "surrogatepass")
    return utf16.decode("utf-16-le", "replace").encode("utf-8")


def to_bytes32(value: int) -> str:
    """``value`` as ``0x``-prefixed, zero-padded 32-byte big-endian hex (lowercase).

    Raises:
        ValueError: ``value`` does not fit in 32 bytes.
    """
    if not _is_int(value) or not 0 <= value < 1 << 256:
        raise ValueError("value does not fit in 32 bytes")
    return f"0x{value:064x}"


def from_bytes32(value: str) -> int:
    """Parse ``0x``-prefixed 32-byte hex (either case).

    Raises:
        ValueError: ``value`` is not 32 bytes of hex.
    """
    if not _matches(_BYTES32_RE, value):
        raise ValueError("expected 0x-prefixed 32-byte hex")
    return int(value, 16)


def _check_scope(scope_id: object) -> str:
    if not isinstance(scope_id, str) or not 0 < _utf16_length(scope_id) <= MAX_SCOPE_LENGTH:
        raise ValueError(f"scope must be 1 to {MAX_SCOPE_LENGTH} characters")
    return scope_id


def scope_field(scope_id: str) -> int:
    """The scope of an HTTP verifier: ``keccak256(utf8(SCOPE_DOMAIN + ":" + scope_id)) mod r``.

    ``scope_id`` is the verifier's host name, or any identifier of 1 to 253 characters.

    Raises:
        ValueError: ``scope_id`` is empty or longer than 253 characters.
    """
    _check_scope(scope_id)
    digest = keccak(_js_utf8(f"{SCOPE_DOMAIN}:{scope_id}"))
    return int.from_bytes(digest, "big") % SNARK_SCALAR_FIELD


def onchain_scope(chain_id: int, consumer: str, context: str) -> int:
    """The scope of an on-chain consumer, ``AgentClaimsVerifier.scopeOf(consumer, context)``.

    ``keccak256(abi.encode("agentbank.proofs.scope.v1", chainId, consumer, context)) mod r``.

    Args:
        chain_id: Chain the verifier contract is on.
        consumer: The consuming contract (``msg.sender`` of ``verifyAndConsume``).
        context: 32-byte hex context chosen by the consumer.

    Raises:
        ValueError: An argument is malformed (including a bad address checksum).
    """
    if not _matches(_BYTES32_RE, context):
        raise ValueError("context must be 0x-prefixed 32-byte hex")
    if not _matches(_ADDRESS_RE, consumer):
        raise ValueError("consumer must be a 0x-prefixed 20-byte hex address")
    if not _is_int(chain_id) or not 0 <= chain_id < 1 << 256:
        raise ValueError("chain_id must be a uint256")
    domain = SCOPE_DOMAIN.encode("utf-8")
    padded = domain + b"\x00" * (-len(domain) % 32)
    encoded = (
        (4 * 32).to_bytes(32, "big")
        + chain_id.to_bytes(32, "big")
        + bytes.fromhex(str(to_checksum_address(consumer))[2:]).rjust(32, b"\x00")
        + bytes.fromhex(context[2:])
        + len(domain).to_bytes(32, "big")
        + padded
    )
    return int.from_bytes(keccak(encoded), "big") % SNARK_SCALAR_FIELD


def scope_tag(scope: int) -> int:
    """The 64-bit tag a reservation stores for a scope: ``scope mod 2^64``."""
    return scope & MAX_U64


def scope_tag_of(scope_id: str) -> int:
    """``scope_tag(scope_field(scope_id))``."""
    return scope_tag(scope_field(scope_id))


def random_nonce() -> str:
    """A fresh 31-byte nonce as ``0x`` + 62 lowercase hex digits (always below r)."""
    return "0x" + secrets.token_hex(31)


def nonce_field(nonce: str) -> int:
    """A request nonce (``0x`` + 62 hex digits) as a field element.

    Raises:
        ValueError: The nonce is not 31 bytes of hex.
    """
    if not _matches(_ANY_CASE_NONCE_RE, nonce):
        raise ValueError("nonce must be 31 bytes of 0x-prefixed hex")
    return int(nonce, 16)


# ===================================================================== wire validation


class _SchemaError(ValueError):
    """A wire value does not match the API contract (zod parity)."""


_REQUEST_FIELDS: Final = (
    "type",
    "scope",
    "request_id",
    "nonce",
    "issued_at",
    "expires_at",
    "constraints",
    "max_root_age_seconds",
    "min_anonymity_set",
    "chain_id",
    "registry",
)
_PRESENTATION_FIELDS: Final = ("type", "request_hash", "root", "nullifier", "proof")
_PROOF_FIELDS: Final = ("pi_a", "pi_b", "pi_c", "protocol", "curve")


def _keys(value: Any, expected: Sequence[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _SchemaError(f"{path}: expected an object")
    extra = sorted(str(k) for k in value if k not in expected)
    if extra:
        raise _SchemaError(f"{path}: unrecognized keys {', '.join(extra)}")
    missing = [k for k in expected if k not in value]
    if missing:
        raise _SchemaError(f"{path}.{missing[0]}: required")
    return value


def _js_int(value: Any, path: str, *, minimum: int) -> int:
    """An integer as JavaScript's ``z.number().int()`` accepts it (integral floats included)."""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _SchemaError(f"{path}: expected an integer")
    if not minimum <= value <= MAX_SAFE_INTEGER:
        raise _SchemaError(f"{path}: out of range")
    return value


def _string(value: Any, pattern: re.Pattern[str], path: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _SchemaError(f"{path}: invalid")
    return value


def _validate_constraints(value: Any) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping):
        raise _SchemaError("constraints: expected an object")
    out: dict[str, dict[str, str]] = {}
    for name, bound in value.items():
        if not is_attribute(name):
            raise _SchemaError(f"constraints.{name}: unknown attribute")
        if not isinstance(bound, Mapping):
            raise _SchemaError(f"constraints.{name}: expected an object")
        extra = sorted(str(k) for k in bound if k not in ("min", "max"))
        if extra:
            raise _SchemaError(f"constraints.{name}: unrecognized keys {', '.join(extra)}")
        out[name] = {
            side: _string(bound[side], _BOUND_RE, f"constraints.{name}.{side}")
            for side in ("min", "max")
            if side in bound
        }
    return out


def _validate_request(value: Any) -> dict[str, Any]:
    """Validate a request against the API schema; return its canonical JSON object."""
    data = _keys(value, _REQUEST_FIELDS, "request")
    if data["type"] != PROOF_REQUEST_TYPE:
        raise _SchemaError(f'type: expected "{PROOF_REQUEST_TYPE}"')
    scope = data["scope"]
    if not isinstance(scope, str) or not 0 < _utf16_length(scope) <= MAX_SCOPE_LENGTH:
        raise _SchemaError(f"scope: must be 1 to {MAX_SCOPE_LENGTH} characters")
    registry = data["registry"]
    if registry is not None:
        _string(registry, _ADDRESS_RE, "registry")
    result: dict[str, Any] = {
        "type": PROOF_REQUEST_TYPE,
        "scope": scope,
        "request_id": _string(data["request_id"], _REQUEST_ID_RE, "request_id"),
        "nonce": _string(data["nonce"], _NONCE_RE, "nonce"),
        "issued_at": _js_int(data["issued_at"], "issued_at", minimum=0),
        "expires_at": _js_int(data["expires_at"], "expires_at", minimum=1),
        "constraints": _validate_constraints(data["constraints"]),
        "max_root_age_seconds": _js_int(
            data["max_root_age_seconds"], "max_root_age_seconds", minimum=1
        ),
        "min_anonymity_set": _js_int(data["min_anonymity_set"], "min_anonymity_set", minimum=1),
        "chain_id": _js_int(data["chain_id"], "chain_id", minimum=1),
        "registry": registry,
    }
    if result["expires_at"] <= result["issued_at"]:
        raise _SchemaError("expires_at: must be after issued_at")
    return result


def _tuple(value: Any, length: int, path: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)) or len(value) != length:
        raise _SchemaError(f"{path}: expected {length} items")
    return value


def _validate_proof(value: Any) -> dict[str, Any]:
    data = _keys(value, _PROOF_FIELDS, "proof")
    pi_a = [_string(v, _FIELD_DECIMAL_RE, "proof.pi_a") for v in _tuple(data["pi_a"], 3, "pi_a")]
    pi_b = [
        [_string(v, _FIELD_DECIMAL_RE, "proof.pi_b") for v in _tuple(pair, 2, "proof.pi_b")]
        for pair in _tuple(data["pi_b"], 3, "proof.pi_b")
    ]
    pi_c = [_string(v, _FIELD_DECIMAL_RE, "proof.pi_c") for v in _tuple(data["pi_c"], 3, "pi_c")]
    if data["protocol"] != "groth16" or data["curve"] != "bn128":
        raise _SchemaError('proof: expected protocol "groth16" on curve "bn128"')
    return {"pi_a": pi_a, "pi_b": pi_b, "pi_c": pi_c, "protocol": "groth16", "curve": "bn128"}


def _validate_presentation(value: Any) -> dict[str, Any]:
    data = _keys(value, _PRESENTATION_FIELDS, "presentation")
    if data["type"] != PROOF_TYPE:
        raise _SchemaError(f'type: expected "{PROOF_TYPE}"')
    return {
        "type": PROOF_TYPE,
        "request_hash": _string(data["request_hash"], _BYTES32_RE, "request_hash"),
        "root": _string(data["root"], _BYTES32_RE, "root"),
        "nullifier": _string(data["nullifier"], _BYTES32_RE, "nullifier"),
        "proof": _validate_proof(data["proof"]),
    }


RequestLike = ProofRequest | Mapping[str, Any]
PresentationLike = ProofPresentation | Mapping[str, Any]


def request_data(request: RequestLike) -> dict[str, Any]:
    """A request as its JSON object: what is hashed, bound into gate nonces and sent.

    Absent bounds are omitted and ``registry`` is always present (``null`` for the
    deployment's registry), exactly as the TypeScript SDK serializes it.
    """
    if isinstance(request, ProofRequest):
        data: dict[str, Any] = request.model_dump(mode="json", by_alias=True, exclude_none=True)
        data.setdefault("registry", None)
        return data
    if isinstance(request, Mapping):
        plain: dict[str, Any] = to_jsonable(request)
        return plain
    raise TypeError("a proof request is a ProofRequest or a mapping")


def presentation_data(presentation: PresentationLike) -> dict[str, Any]:
    """A presentation as its JSON object."""
    if isinstance(presentation, ProofPresentation):
        data: dict[str, Any] = presentation.model_dump(mode="json", by_alias=True)
        return data
    if isinstance(presentation, Mapping):
        plain: dict[str, Any] = to_jsonable(presentation)
        return plain
    raise TypeError("a presentation is a ProofPresentation or a mapping")


def _parse_request_data(value: Any) -> dict[str, Any]:
    """Validate (schema and bounds) and return the canonical JSON object of a request."""
    try:
        data = _validate_request(request_data(value))
    except (_SchemaError, TypeError, ValueError) as exc:
        raise ProofRequestError(f"invalid proof request: {exc}") from None
    bounds(data)
    return data


def parse_proof_request(value: RequestLike) -> ProofRequest:
    """Validate an untrusted proof request (schema and bounds).

    Raises:
        ProofRequestError: The request is malformed (verifiers report ``malformed``).
    """
    return ProofRequest.model_validate(_parse_request_data(value))


def _parse_presentation_data(value: Any) -> dict[str, Any]:
    data = _validate_presentation(presentation_data(value))
    if from_bytes32(data["root"]) >= SNARK_SCALAR_FIELD:
        raise _SchemaError("root: not a BN254 field element")
    if from_bytes32(data["nullifier"]) >= SNARK_SCALAR_FIELD:
        raise _SchemaError("nullifier: not a BN254 field element")
    return data


def parse_presentation(value: PresentationLike) -> ProofPresentation:
    """Validate an untrusted presentation (schema; root and nullifier below r).

    Raises:
        ValueError: The presentation is malformed.
    """
    try:
        data = _parse_presentation_data(value)
    except TypeError as exc:
        raise ValueError(str(exc)) from None
    return ProofPresentation.model_validate(data)


def request_hash(request: RequestLike) -> str:
    """``request_hash``: Keccak-256 of the request's canonical JSON (``0x`` hex)."""
    return canonical_keccak(request_data(request))


# ===================================================================== bounds


def parse_usdc_bound(value: str) -> int:
    """Parse a decimal USDC bound into minor units (at most 6 decimals, up to 2^64 - 1).

    Same grammar as API money: no sign, exponent, whitespace or leading zeros.

    Raises:
        ProofRequestError: The value is not a valid bound.
    """
    match = _DECIMAL_RE.fullmatch(value) if _matches(_DECIMAL_RE, value) else None
    if match is None:
        raise ProofRequestError(f'"{value}" is not a decimal USDC amount')
    whole: str = match.group(1)
    fraction: str = match.group(2) or ""
    if len(fraction) > _USDC_DECIMALS:
        raise ProofRequestError(f'"{value}" has more than {_USDC_DECIMALS} decimal places')
    minor = int(whole) * _USDC_SCALE + int(fraction.ljust(_USDC_DECIMALS, "0"))
    if minor > MAX_U64:
        raise ProofRequestError(f'"{value}" exceeds 2^64 - 1 minor units')
    return minor


def parse_bound_value(attribute: Attribute, value: str) -> int:
    """Parse one bound of ``attribute`` into the raw value the circuit compares.

    Raises:
        ProofRequestError: The value is malformed or out of range.
    """
    if not isinstance(value, str):
        raise ProofRequestError(f"bounds on {attribute} must be strings", attribute=attribute)
    if ATTRIBUTE_INFO[attribute].kind == "money":
        try:
            return parse_usdc_bound(value)
        except ProofRequestError as exc:
            raise ProofRequestError(f"{attribute}: {exc.detail}", attribute=attribute) from None
    if _INTEGER_RE.fullmatch(value) is None:
        raise ProofRequestError(
            f'{attribute}: "{value}" is not a base-10 integer', attribute=attribute
        )
    parsed = int(value)
    if parsed > MAX_U64:
        raise ProofRequestError(f'{attribute}: "{value}" exceeds 2^64 - 1', attribute=attribute)
    return parsed


def format_bound_value(attribute: Attribute, value: int) -> str:
    """Format a raw bound the way requests carry it (decimal USDC for money)."""
    if ATTRIBUTE_INFO[attribute].kind == "money":
        return format_amount(value, _USDC_DECIMALS)
    return str(value)


@dataclass(frozen=True)
class Bounds:
    """The circuit's per-attribute bounds, in circuit order.

    Attributes:
        mins: Lower bounds (0 when unconstrained).
        maxs: Upper bounds (2^64 - 1 when unconstrained).
    """

    mins: tuple[int, ...]
    maxs: tuple[int, ...]


def _constraints_of(request: Any) -> Any:
    if isinstance(request, ProofRequest):
        return {
            name: bound.model_dump(exclude_none=True) for name, bound in request.constraints.items()
        }
    if isinstance(request, Mapping):
        return request.get("constraints")
    raise ProofRequestError("a proof request is a ProofRequest or a mapping")


def bounds(request: RequestLike) -> Bounds:
    """The circuit's ``mins`` and ``maxs`` for a request's constraints.

    ``[0, 2^64 - 1]`` for every attribute or side left out.

    Raises:
        ProofRequestError: Unknown attributes, malformed or out-of-range values, or
            ``min > max``.
    """
    mins = [0] * ATTRIBUTE_COUNT
    maxs = [MAX_U64] * ATTRIBUTE_COUNT
    constraints = _constraints_of(request)
    if not isinstance(constraints, Mapping):
        raise ProofRequestError("constraints must be an object")
    for name, bound in constraints.items():
        if not is_attribute(name):
            raise ProofRequestError(f'unknown attribute "{name}"')
        if not isinstance(bound, Mapping):
            raise ProofRequestError(f"the bound on {name} must be an object", attribute=name)
        if any(key not in ("min", "max") for key in bound):
            raise ProofRequestError(f"the bound on {name} has unknown keys", attribute=name)
        i = ATTRIBUTE_INFO[name].index
        if "min" in bound:
            mins[i] = parse_bound_value(name, bound["min"])
        if "max" in bound:
            maxs[i] = parse_bound_value(name, bound["max"])
        if mins[i] > maxs[i]:
            raise ProofRequestError(f"{name}: min is greater than max", attribute=name)
    return Bounds(mins=tuple(mins), maxs=tuple(maxs))


# ===================================================================== requirements

#: Per-attribute bounds, e.g. ``{"per_tx_limit": {"min": "5.00"}}``.
Constraints = dict[str, dict[str, str]]


@dataclass(frozen=True)
class RequirementContext:
    """What a time- or scope-relative requirement is evaluated against.

    Attributes:
        scope: The request's scope.
        now: The request's ``issued_at`` (unix seconds).
        expires_at: The request's ``expires_at`` (unix seconds).
    """

    scope: str
    now: int
    expires_at: int


#: Constraints, or a function of the request being built.
Requirement = Mapping[str, Mapping[str, str]] | Callable[[RequirementContext], Constraints]


def _money(attribute: Attribute, amount: str | Decimal) -> str:
    if isinstance(amount, Decimal):
        if not amount.is_finite() or amount.is_signed():
            raise ProofRequestError(f"{attribute}: {amount} is not a valid amount")
        amount = format(amount, "f")
    if not isinstance(amount, str):
        raise ProofRequestError(f"{attribute}: amounts are decimal strings such as '5.00'")
    parse_bound_value(attribute, amount)
    return amount


def _int_string(value: int | str, what: str) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_U64:
        return str(value)
    if isinstance(value, str) and _INTEGER_RE.fullmatch(value) and int(value) <= MAX_U64:
        return value
    raise ProofRequestError(f"{what} must be a non-negative integer below 2^64")


def _unix_seconds(value: int | datetime) -> int:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ProofRequestError("datetimes must be timezone-aware")
        return (value - _EPOCH) // timedelta(seconds=1)
    if not _is_int(value) or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ProofRequestError("times must be unix seconds")
    return value


def verified_principal() -> Constraints:
    """A verified individual or company stands behind the agent (principal_verification >= 1)."""
    return {"principal_verification": {"min": "1"}}


def verified_company() -> Constraints:
    """A verified company stands behind the agent (principal_verification = 2)."""
    return {"principal_verification": {"min": "2", "max": "2"}}


def can_pay_per_tx(amount: str | Decimal) -> Constraints:
    """The agent's policy lets it pay at least ``amount`` USDC in one transaction."""
    return {"per_tx_limit": {"min": _money("per_tx_limit", amount)}}


def can_pay_per_day(amount: str | Decimal) -> Constraints:
    """The agent's policy lets it pay at least ``amount`` USDC per rolling day."""
    return {"per_day_limit": {"min": _money("per_day_limit", amount)}}


def spending_capped_at(
    *, per_tx: str | Decimal | None = None, per_day: str | Decimal | None = None
) -> Constraints:
    """The agent's spending is capped at most at these limits (a bounded-risk counterparty).

    Raises:
        ProofRequestError: Neither ``per_tx`` nor ``per_day`` is given.
    """
    if per_tx is None and per_day is None:
        raise ProofRequestError("spending_capped_at needs per_tx or per_day")
    out: Constraints = {}
    if per_tx is not None:
        out["per_tx_limit"] = {"max": _money("per_tx_limit", per_tx)}
    if per_day is not None:
        out["per_day_limit"] = {"max": _money("per_day_limit", per_day)}
    return out


def balance_at_least(amount: str | Decimal) -> Constraints:
    """The agent held at least ``amount`` available at the snapshot (whole dollars)."""
    return {"balance": {"min": _money("balance", amount)}}


def reserved_for(
    amount: str | Decimal,
    *,
    until: int | datetime | None = None,
    for_seconds: int | None = None,
    scope: str | None = None,
) -> Callable[[RequirementContext], Constraints]:
    """At least ``amount`` is reserved for the verifier until at least a time.

    Args:
        amount: Decimal USDC string (or ``Decimal``).
        until: Unix seconds or an aware datetime the reservation must last until.
        for_seconds: Alternatively, seconds after the request is issued.
        scope: The verifier scope the funds are reserved for (default: the
            request's own scope); ``reserved_for`` must equal its 64-bit tag.

    Raises:
        ProofRequestError: Not exactly one of ``until`` and ``for_seconds``, or a
            malformed value.
    """
    normalized = _money("reserved_amount", amount)
    if (until is None) == (for_seconds is None):
        raise ProofRequestError("reserved_for needs exactly one of until, for_seconds")
    absolute = None if until is None else _unix_seconds(until)
    relative = 0 if for_seconds is None else _unix_seconds(for_seconds)

    def requirement(context: RequirementContext) -> Constraints:
        try:
            tag = str(scope_tag_of(scope if scope is not None else context.scope))
        except ValueError as exc:
            raise ProofRequestError(f"reserved_for: {exc}") from None
        deadline = absolute if absolute is not None else context.now + relative
        return {
            "reserved_amount": {"min": normalized},
            "reserved_until": {"min": str(deadline)},
            "reserved_for": {"min": tag, "max": tag},
        }

    return requirement


def account_older_than(
    days: int, *, now: int | datetime | None = None
) -> Callable[[RequirementContext], Constraints]:
    """The agent's account was created at least ``days`` days before ``now``.

    ``now`` defaults to the request's ``issued_at``.

    Raises:
        ProofRequestError: ``days`` is not a non-negative integer, or the bound
            reaches before 1970.
    """
    if not _is_int(days) or days < 0:
        raise ProofRequestError("days must be a non-negative integer")
    fixed = None if now is None else _unix_seconds(now)

    def requirement(context: RequirementContext) -> Constraints:
        latest = (fixed if fixed is not None else context.now) - days * _SECONDS_PER_DAY
        if latest < 0:
            raise ProofRequestError("account_older_than reaches before 1970")
        return {"account_created_on": {"max": str(latest)}}

    return requirement


def reputation(
    *,
    payments_settled: int | str | None = None,
    volume_settled: str | Decimal | None = None,
    escrows_completed: int | str | None = None,
    disputes_lost_at_most: int | str | None = None,
    counterparties: int | str | None = None,
) -> Constraints:
    """Track-record thresholds; every option is optional, at least one is required.

    Raises:
        ProofRequestError: No threshold, or a malformed one.
    """
    out: Constraints = {}
    if payments_settled is not None:
        out["payments_settled"] = {"min": _int_string(payments_settled, "payments_settled")}
    if volume_settled is not None:
        out["volume_settled"] = {"min": _money("volume_settled", volume_settled)}
    if escrows_completed is not None:
        out["escrows_completed"] = {"min": _int_string(escrows_completed, "escrows_completed")}
    if disputes_lost_at_most is not None:
        out["disputes_lost"] = {"max": _int_string(disputes_lost_at_most, "disputes_lost_at_most")}
    if counterparties is not None:
        out["counterparties"] = {"min": _int_string(counterparties, "counterparties")}
    if not out:
        raise ProofRequestError("reputation needs at least one threshold")
    return out


def merge_constraints(parts: Iterable[Mapping[str, Mapping[str, str]]]) -> Constraints:
    """Intersect constraints: per attribute the largest min and the smallest max.

    Trivial sides are dropped and values normalized (money as canonical decimal strings).

    Raises:
        ProofRequestError: A part is invalid or the intersection is empty.
    """
    mins = [0] * ATTRIBUTE_COUNT
    maxs = [MAX_U64] * ATTRIBUTE_COUNT
    for part in parts:
        b = bounds({"constraints": part})
        for i in range(ATTRIBUTE_COUNT):
            mins[i] = max(mins[i], b.mins[i])
            maxs[i] = min(maxs[i], b.maxs[i])
    out: Constraints = {}
    for i, attribute in enumerate(ATTRIBUTES):
        if mins[i] > maxs[i]:
            raise ProofRequestError(
                f"requirements on {attribute} cannot all hold", attribute=attribute
            )
        bound: dict[str, str] = {}
        if mins[i] > 0:
            bound["min"] = format_bound_value(attribute, mins[i])
        if maxs[i] < MAX_U64:
            bound["max"] = format_bound_value(attribute, maxs[i])
        if bound:
            out[attribute] = bound
    return out


def create_proof_request(
    scope: str,
    *,
    require: Iterable[Requirement] = (),
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    max_root_age_seconds: int = DEFAULT_MAX_ROOT_AGE_SECONDS,
    min_anonymity_set: int = DEFAULT_MIN_ANONYMITY_SET,
    chain_id: int = DEFAULT_CHAIN_ID,
    registry: str | None = None,
    nonce: str | None = None,
    request_id: str | None = None,
    now: int | datetime | None = None,
) -> ProofRequest:
    """Build and validate a proof request.

    Args:
        scope: The verifier's identifier, normally its host name.
        require: Requirements (``verified_company()``, ``can_pay_per_tx("5.00")``, ...),
            intersected into per-attribute bounds.
        ttl_seconds: Seconds until the request expires (default 300).
        max_root_age_seconds: Oldest root snapshot accepted (default 7,200 s).
        min_anonymity_set: Fewest leaves the root must have (default 16).
        chain_id: Chain the root must be published on (default Base Sepolia, 84532).
        registry: Registry the root must be published in (default ``None``: the
            deployment's).
        nonce: 31-byte nonce (default random; gates derive it from their key).
        request_id: 16 bytes of lowercase hex (default random).
        now: Issue time (unix seconds or an aware datetime; default now).

    Raises:
        ProofRequestError: The request would be invalid.
        MainnetLockedError: ``chain_id`` is a mainnet.
    """
    issued_at = int(time.time()) if now is None else _unix_seconds(now)
    if not _is_int(ttl_seconds) or ttl_seconds <= 0:
        raise ProofRequestError("ttl_seconds must be a positive integer")
    try:
        _check_scope(scope)
    except ValueError as exc:
        raise ProofRequestError(f"invalid proof request: scope: {exc}") from None
    assert_testnet(chain_id)
    context = RequirementContext(scope=scope, now=issued_at, expires_at=issued_at + ttl_seconds)
    constraints = merge_constraints(r(context) if callable(r) else r for r in require)
    candidate = {
        "type": PROOF_REQUEST_TYPE,
        "scope": scope,
        "request_id": request_id if request_id is not None else secrets.token_hex(16),
        "nonce": nonce if nonce is not None else random_nonce(),
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "constraints": constraints,
        "max_root_age_seconds": max_root_age_seconds,
        "min_anonymity_set": min_anonymity_set,
        "chain_id": chain_id,
        "registry": registry,
    }
    try:
        data = _validate_request(candidate)
    except _SchemaError as exc:
        raise ProofRequestError(f"invalid proof request: {exc}") from None
    return ProofRequest.model_validate(data)


# ===================================================================== witnesses


@dataclass(frozen=True)
class WitnessCheck:
    """How a witness's attested values compare with a request's bounds.

    Attributes:
        out_of_bounds: Attributes whose attested value lies outside the bounds.
        undisclosed: Attributes the request constrains although the owner did not
            disclose them.
        undisclosed_classes: The classes of ``undisclosed``.
    """

    out_of_bounds: tuple[Attribute, ...]
    undisclosed: tuple[Attribute, ...]
    undisclosed_classes: tuple[DisclosureClass, ...]


def _witness_fields(witness: ProofWitness | Mapping[str, Any]) -> tuple[Mapping[str, Any], Any]:
    if isinstance(witness, ProofWitness):
        return witness.attributes, witness.disclosure_mask
    return witness.get("attributes") or {}, witness.get("disclosure_mask")


def check_witness(witness: ProofWitness | Mapping[str, Any], request: RequestLike) -> WitnessCheck:
    """Compare a witness's attested values and disclosure mask with a request's bounds.

    Raises:
        ProofRequestError: The request's bounds are invalid.
    """
    b = bounds(request)
    attributes, mask = _witness_fields(witness)
    mask_value = mask if isinstance(mask, int) and not isinstance(mask, bool) else 0
    out_of_bounds: list[Attribute] = []
    undisclosed: list[Attribute] = []
    for i, attribute in enumerate(ATTRIBUTES):
        raw = attributes.get(attribute)
        value = int(raw) if isinstance(raw, str) and _INTEGER_RE.fullmatch(raw) else -1
        if not b.mins[i] <= value <= b.maxs[i]:
            out_of_bounds.append(attribute)
        constrained = b.mins[i] != 0 or b.maxs[i] != MAX_U64
        if constrained and not is_disclosed(mask_value, attribute):
            undisclosed.append(attribute)
    classes = dict.fromkeys(ATTRIBUTE_INFO[a].disclosure_class for a in undisclosed)
    return WitnessCheck(tuple(out_of_bounds), tuple(undisclosed), tuple(classes))


def assert_provable(witness: ProofWitness, request: RequestLike) -> None:
    """Refuse, before proving, a request this witness cannot prove (prover parity).

    Checks run in the prover's order: chain and registry, undisclosed attributes,
    then attested values. (Whether the secret matches the witness is checked by
    the prover, which hashes with Poseidon.)

    Raises:
        ProofRefusedError: ``chain_mismatch``, ``undisclosed`` or ``unsatisfiable``.
        ProofRequestError: The request is malformed.
    """
    data = _parse_request_data(request)
    if witness.chain_id != data["chain_id"]:
        raise ProofRefusedError(
            "chain_mismatch",
            f"The witness is for chain {witness.chain_id}, the request for chain "
            f"{data['chain_id']}",
        )
    registry = data["registry"]
    if registry is not None and (witness.registry or "").lower() != registry.lower():
        raise ProofRefusedError(
            "chain_mismatch", "The witness root is from another registry than the request names"
        )
    check = check_witness(witness, data)
    if check.undisclosed:
        raise ProofRefusedError(
            "undisclosed",
            "The request constrains attributes the owner did not disclose (classes: "
            f"{', '.join(check.undisclosed_classes)})",
            attributes=check.out_of_bounds,
            undisclosed_classes=check.undisclosed_classes,
        )
    if check.out_of_bounds:
        raise ProofRefusedError(
            "unsatisfiable",
            "Attested values do not satisfy the request (attributes: "
            f"{', '.join(check.out_of_bounds)})",
            attributes=check.out_of_bounds,
        )


_RESERVATION_ATTRIBUTES: Final = ("reserved_amount", "reserved_until", "reserved_for")


def needs_reservation(request: RequestLike) -> bool:
    """Whether a request constrains the reservation attributes (proof of reserved funds)."""
    b = bounds(request)
    return any(
        b.mins[ATTRIBUTE_INFO[a].index] != 0 or b.maxs[ATTRIBUTE_INFO[a].index] != MAX_U64
        for a in _RESERVATION_ATTRIBUTES
    )


def _unix(value: datetime) -> int:
    return (value - _EPOCH) // timedelta(seconds=1)


def select_reservation(
    request: RequestLike,
    reservations: Iterable[ProofReservation],
    *,
    now: int | None = None,
    status: str = "active",
) -> ProofReservation | None:
    """The reservation (by default an active one) whose leaf satisfies the request.

    Among the matches (amount, expiry and scope tag within bounds, not expired),
    the latest expiry wins, then the lowest id, as in the TypeScript SDK.
    ``None`` when none matches.
    """
    b = bounds(request)
    current = int(time.time()) if now is None else now

    def within(attribute: Attribute, value: int) -> bool:
        i = ATTRIBUTE_INFO[attribute].index
        return b.mins[i] <= value <= b.maxs[i]

    matches = [
        r
        for r in reservations
        if r.status == status
        and _unix(r.expires_at) > current
        and within("reserved_amount", parse_amount(r.amount.amount))
        and within("reserved_until", _unix(r.expires_at))
        and within("reserved_for", int(r.scope_tag))
    ]
    matches.sort(key=lambda r: (-_unix(r.expires_at), r.id))
    return matches[0] if matches else None


# ===================================================================== verification


@dataclass(frozen=True)
class RootInfo:
    """What a verifier needs to know about a root (the registry's ``rootInfo``).

    Attributes:
        epoch: Snapshot number.
        snapshot_at: Unix seconds the attested facts were read.
        published_at: Unix seconds of publication; ``None`` while not on-chain.
        valid_until: Unix seconds after which proofs against the root are refused.
        leaf_count: The anonymity set.
        revoked: Whether the root was revoked.
        status: Lifecycle status, when the source tracks one (the API does).
    """

    epoch: int
    snapshot_at: int
    published_at: int | None
    valid_until: int
    leaf_count: int
    revoked: bool
    status: ProofRootStatus | None = None


@dataclass(frozen=True)
class RootQuery:
    """A root lookup: the presented root and where the request says it must be published.

    Attributes:
        root: The presented root (lowercase bytes32 hex).
        chain_id: The request's chain.
        registry: The request's registry (``None``: the deployment's).
    """

    root: str
    chain_id: int
    registry: str | None


#: Looks a root up; ``None`` when it was never published on that chain and registry.
RootResolver = Callable[[RootQuery], RootInfo | None]
#: The asynchronous form of :data:`RootResolver`.
AsyncRootResolver = Callable[[RootQuery], Awaitable[RootInfo | None]]

NonceReason = Literal["nonce_invalid", "nonce_reused"]
#: A gate's nonce check: ``None`` when the nonce is authentic and unused.
NonceCheck = Callable[[ProofRequest], NonceReason | None]


def root_info_from_api(root: ProofRoot) -> RootInfo:
    """Map an API :class:`~agentbank.models.ProofRoot` to a :class:`RootInfo`."""
    return RootInfo(
        epoch=int(root.epoch),
        snapshot_at=_unix(root.snapshot_at),
        published_at=None if root.published_at is None else _unix(root.published_at),
        valid_until=_unix(root.valid_until),
        leaf_count=root.leaf_count,
        revoked=root.status == "revoked",
        status=root.status,
    )


def root_status_of(info: RootInfo | None, now: int) -> ProofRootStatus | None:
    """The status a root has at ``now``, from its record."""
    if info is None:
        return None
    if info.revoked:
        return "revoked"
    if info.status in ("failed", "publishing"):
        return info.status
    if info.published_at is None:
        return "publishing"
    if info.status == "expired" or now > info.valid_until:
        return "expired"
    return "published"


def check_root(info: RootInfo | None, request: RequestLike, now: int) -> ProofFailureReason | None:
    """The root check: ``None`` when the root is acceptable for this request at ``now``."""
    data = request_data(request)
    if info is None or info.published_at is None or info.status in ("publishing", "failed"):
        return "unknown_root"
    if info.revoked or info.status == "revoked":
        return "root_revoked"
    if info.status == "expired" or now > info.valid_until:
        return "root_expired"
    if now > info.snapshot_at + data["max_root_age_seconds"]:
        return "root_too_old"
    if info.leaf_count < data["min_anonymity_set"]:
        return "anonymity_set_too_small"
    return None


def public_signals(request: RequestLike, presentation: PresentationLike) -> list[str]:
    """The 30 public signals in circuit order, as base-10 strings.

    ``nullifier, root, scope(request.scope), nonce, mins[13], maxs[13]``: built from
    the verifier's request; only the root and the nullifier come from the presentation.
    """
    data = request_data(request)
    shown = presentation_data(presentation)
    b = bounds(data)
    values = [
        from_bytes32(shown["nullifier"]),
        from_bytes32(shown["root"]),
        scope_field(data["scope"]),
        nonce_field(data["nonce"]),
        *b.mins,
        *b.maxs,
    ]
    return [str(v) for v in values]


def load_verification_key() -> Mapping[str, Any]:
    """The bundled snarkjs verification key of the claims circuit.

    Checked against the SHA-256 in the bundled circuit manifest on first use.

    Raises:
        ValueError: The bundled key does not match the manifest.
    """
    from agentbank import _groth16  # noqa: PLC0415 (py_ecc loads only when verifying)

    return _groth16.load_verification_key()


def circuit_manifest() -> Mapping[str, Any]:
    """The bundled claims-circuit manifest (schema, toolchain, public signals, hashes)."""
    from agentbank import _groth16  # noqa: PLC0415 (py_ecc loads only when verifying)

    return _groth16.circuit_manifest()


def verify_groth16(
    verification_key: Mapping[str, Any] | None,
    signals: Sequence[str | int],
    proof: Groth16Proof | Mapping[str, Any],
) -> bool:
    """Verify a snarkjs Groth16 proof on BN254 (``None``: the bundled key).

    Returns ``False`` for any malformed or invalid proof; about a second in CPython.

    Raises:
        ValueError: ``verification_key`` is not a Groth16 bn128 key.
    """
    from agentbank import _groth16  # noqa: PLC0415 (py_ecc loads only when verifying)

    data = proof.model_dump(mode="json") if isinstance(proof, Groth16Proof) else proof
    return _groth16.verify(verification_key, signals, data)


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of :func:`verify_presentation`.

    Attributes:
        valid: Whether the presentation proves the request.
        reason: Why not (``None`` when valid).
        nullifier: The agent's pseudonym for this scope, when valid.
        root: The presented root (lowercase), when the presentation parses.
        root_info: The root's record, when it was looked up.
        request: The validated request, when it parses.
    """

    valid: bool
    reason: ProofFailureReason | None
    nullifier: str | None
    root: str | None
    root_info: RootInfo | None
    request: ProofRequest | None


class _Missing(Enum):
    MISSING = "MISSING"


_MISSING: Final = _Missing.MISSING


def _failure(
    reason: ProofFailureReason,
    *,
    root: str | None = None,
    root_info: RootInfo | None = None,
    request: dict[str, Any] | None = None,
) -> VerificationResult:
    model = None if request is None else ProofRequest.model_validate(request)
    return VerificationResult(False, reason, None, root, root_info, model)


@dataclass(frozen=True)
class _Parsed:
    request: dict[str, Any]
    model: ProofRequest
    presentation: dict[str, Any]
    root: str


def _start(request: Any, presentation: Any, now: int) -> _Parsed | VerificationResult:
    try:
        data = _parse_request_data(request)
    except ProofRequestError:
        return _failure("malformed")
    try:
        shown = _parse_presentation_data(presentation)
    except (_SchemaError, TypeError, ValueError):
        return _failure("malformed", request=data)
    root = to_bytes32(from_bytes32(shown["root"]))
    if now > data["expires_at"]:
        return _failure("request_expired", root=root, request=data)
    return _Parsed(data, ProofRequest.model_validate(data), shown, root)


def _check_hash(parsed: _Parsed) -> VerificationResult | None:
    if parsed.presentation["request_hash"].lower() != request_hash(parsed.request):
        return _failure("request_hash_mismatch", root=parsed.root, request=parsed.request)
    return None


def _query(parsed: _Parsed) -> RootQuery:
    return RootQuery(parsed.root, parsed.request["chain_id"], parsed.request["registry"])


def _root_failure(
    parsed: _Parsed, root_info: RootInfo | None, now: int
) -> VerificationResult | None:
    reason = check_root(root_info, parsed.request, now)
    if reason is None:
        return None
    return _failure(reason, root=parsed.root, root_info=root_info, request=parsed.request)


def _finish(parsed: _Parsed, root_info: RootInfo | None, ok: bool) -> VerificationResult:
    if not ok:
        return _failure(
            "invalid_proof", root=parsed.root, root_info=root_info, request=parsed.request
        )
    nullifier = to_bytes32(from_bytes32(parsed.presentation["nullifier"]))
    return VerificationResult(True, None, nullifier, parsed.root, root_info, parsed.model)


def _signals_and_proof(parsed: _Parsed) -> tuple[list[str], dict[str, Any]]:
    return public_signals(parsed.request, parsed.presentation), parsed.presentation["proof"]


def verify_presentation(
    request: RequestLike,
    presentation: PresentationLike,
    *,
    root_info: RootInfo | _Missing | None = _MISSING,
    root_resolver: RootResolver | None = None,
    now: int | None = None,
    verification_key: Mapping[str, Any] | None = None,
    check_nonce: NonceCheck | None = None,
) -> VerificationResult:
    """Verify a presentation against the verifier's own request.

    The public signals are rebuilt from ``request``, the presented root and the
    presented nullifier; nothing else the agent sends is trusted. Checks run in
    the order of the design and stop at the first failure: ``malformed``,
    ``request_expired``, the nonce (gates), ``request_hash_mismatch``, the root
    (``unknown_root``, ``root_revoked``, ``root_expired``, ``root_too_old``,
    ``anonymity_set_too_small``), then ``invalid_proof``.

    Args:
        request: The verifier's own request (validated here).
        presentation: The agent's presentation (validated here).
        root_info: The root's record if already known (``None``: unknown root).
        root_resolver: Used when ``root_info`` is not given; its errors propagate
            (fail closed).
        now: Unix seconds (default now).
        verification_key: Defaults to the bundled claims-circuit key.
        check_nonce: Gates: nonce authenticity and freshness, run after expiry.

    Raises:
        TypeError: Neither ``root_info`` nor ``root_resolver`` is given.
    """
    if root_info is _MISSING and root_resolver is None:
        raise TypeError("verify_presentation needs root_info or root_resolver")
    current = int(time.time()) if now is None else now
    parsed = _start(request, presentation, current)
    if isinstance(parsed, VerificationResult):
        return parsed
    if check_nonce is not None:
        nonce_reason = check_nonce(parsed.model)
        if nonce_reason is not None:
            return _failure(nonce_reason, root=parsed.root, request=parsed.request)
    mismatch = _check_hash(parsed)
    if mismatch is not None:
        return mismatch
    if isinstance(root_info, _Missing):
        assert root_resolver is not None
        info = root_resolver(_query(parsed))
    else:
        info = root_info
    refused = _root_failure(parsed, info, current)
    if refused is not None:
        return refused
    signals, proof = _signals_and_proof(parsed)
    return _finish(parsed, info, verify_groth16(verification_key, signals, proof))


async def _resolve(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        result: T = await value
        return result
    return value


AsyncNonceCheck = Callable[[ProofRequest], NonceReason | Awaitable[NonceReason | None] | None]


async def averify_presentation(
    request: RequestLike,
    presentation: PresentationLike,
    *,
    root_info: RootInfo | _Missing | None = _MISSING,
    root_resolver: RootResolver | AsyncRootResolver | None = None,
    now: int | None = None,
    verification_key: Mapping[str, Any] | None = None,
    check_nonce: AsyncNonceCheck | None = None,
) -> VerificationResult:
    """:func:`verify_presentation` for async code.

    ``root_resolver`` and ``check_nonce`` may be sync or async; the pairing check
    runs in a worker thread so the event loop stays responsive.

    Raises:
        TypeError: Neither ``root_info`` nor ``root_resolver`` is given.
    """
    if root_info is _MISSING and root_resolver is None:
        raise TypeError("averify_presentation needs root_info or root_resolver")
    current = int(time.time()) if now is None else now
    parsed = _start(request, presentation, current)
    if isinstance(parsed, VerificationResult):
        return parsed
    if check_nonce is not None:
        nonce_reason = await _resolve(check_nonce(parsed.model))
        if nonce_reason is not None:
            return _failure(nonce_reason, root=parsed.root, request=parsed.request)
    mismatch = _check_hash(parsed)
    if mismatch is not None:
        return mismatch
    if isinstance(root_info, _Missing):
        assert root_resolver is not None
        info = await _resolve(root_resolver(_query(parsed)))
    else:
        info = root_info
    refused = _root_failure(parsed, info, current)
    if refused is not None:
        return refused
    signals, proof = _signals_and_proof(parsed)
    ok = await anyio.to_thread.run_sync(partial(verify_groth16, verification_key, signals, proof))
    return _finish(parsed, info, ok)


# ===================================================================== HTTP


@dataclass(frozen=True)
class _ProofHeaders:
    required: str = "AGENT-PROOF-REQUIRED"
    proof: str = "AGENT-PROOF"
    response: str = "AGENT-PROOF-RESPONSE"
    www_authenticate: str = "WWW-Authenticate"


#: The HTTP headers of private proofs (``PROOF_HEADERS.proof == "AGENT-PROOF"``).
PROOF_HEADERS: Final = _ProofHeaders()
#: 401 challenge: ``base64(json(request))``.
PROOF_REQUIRED_HEADER: Final = PROOF_HEADERS.required
#: The agent's retry: ``base64(json({request, presentation}))``.
PROOF_HEADER: Final = PROOF_HEADERS.proof
#: The verifier's acceptance: ``base64(json({status: "accepted", nullifier}))``.
PROOF_RESPONSE_HEADER: Final = PROOF_HEADERS.response
PROOF_AUTH_SCHEME: Final = "AgentProof"


def www_authenticate(scope: str) -> str:
    """``AgentProof realm="<scope>"`` (quotes and backslashes escaped)."""
    escaped = re.sub(r'(["\\])', r"\\\1", scope)
    return f'{PROOF_AUTH_SCHEME} realm="{escaped}"'


def encode_header_json(value: Any) -> str:
    """``base64(utf8(json(value)))`` as the proof headers carry it."""
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates: escape them, as JSON.stringify does
        raw = json.dumps(value, separators=(",", ":")).encode("ascii")
    return base64.b64encode(raw).decode("ascii")


def _no_constants(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def decode_header_json(header: str) -> Any:
    """Decode a base64 (standard or URL-safe, padding optional) JSON header.

    Raises:
        ProofHeaderError: The header is not base64-encoded UTF-8 JSON.
    """
    try:
        normalized = header.strip().replace("-", "+").replace("_", "/")
        padded = normalized + "=" * (-len(normalized) % 4)
        raw = base64.b64decode(padded, validate=True)
        return json.loads(raw.decode("utf-8"), parse_constant=_no_constants)
    except (AttributeError, binascii.Error, UnicodeDecodeError, ValueError):
        raise ProofHeaderError("header is not base64-encoded JSON") from None


@dataclass(frozen=True)
class ProofEnvelope:
    """The ``AGENT-PROOF`` header: the request being answered and the presentation."""

    request: ProofRequest
    presentation: ProofPresentation


def encode_proof_required(request: RequestLike) -> str:
    """The ``AGENT-PROOF-REQUIRED`` header value for a request."""
    return encode_header_json(request_data(request))


def decode_proof_required(header: str) -> ProofRequest:
    """Decode and validate (schema) an ``AGENT-PROOF-REQUIRED`` header.

    Raises:
        ProofHeaderError: The header is not a valid proof request.
    """
    try:
        data = _validate_request(decode_header_json(header))
    except _SchemaError as exc:
        raise ProofHeaderError(f"invalid proof request header: {exc}") from None
    return ProofRequest.model_validate(data)


def encode_proof(request: RequestLike, presentation: PresentationLike) -> str:
    """The ``AGENT-PROOF`` header value: ``base64(json({request, presentation}))``."""
    return encode_header_json(
        {"request": request_data(request), "presentation": presentation_data(presentation)}
    )


def decode_proof(header: str) -> ProofEnvelope:
    """Decode and validate (schemas) an ``AGENT-PROOF`` header.

    Raises:
        ProofHeaderError: The header is not a valid envelope.
    """
    envelope = decode_header_json(header)
    try:
        if not isinstance(envelope, Mapping):
            raise _SchemaError("expected an object")
        request = _validate_request(envelope.get("request"))
        presentation = _validate_presentation(envelope.get("presentation"))
    except _SchemaError as exc:
        raise ProofHeaderError(f"invalid proof header: {exc}") from None
    return ProofEnvelope(
        ProofRequest.model_validate(request), ProofPresentation.model_validate(presentation)
    )


def encode_proof_response(nullifier: str) -> str:
    """The ``AGENT-PROOF-RESPONSE`` header value for an accepted proof."""
    return encode_header_json({"status": "accepted", "nullifier": nullifier})


def decode_proof_response(header: str) -> dict[str, str]:
    """Decode and validate an ``AGENT-PROOF-RESPONSE`` header.

    Raises:
        ProofHeaderError: The header is not ``{"status": "accepted", "nullifier"}``.
    """
    value = decode_header_json(header)
    if (
        not isinstance(value, Mapping)
        or value.get("status") != "accepted"
        or not isinstance(value.get("nullifier"), str)
        or _BYTES32_RE.fullmatch(value["nullifier"]) is None
    ):
        raise ProofHeaderError("invalid proof response header")
    return {"status": "accepted", "nullifier": value["nullifier"]}


def _key_bytes(key: str | bytes) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else bytes(key)


def gate_nonce(key: str | bytes, request: RequestLike) -> str:
    """A stateless gate's nonce: the first 31 bytes of HMAC-SHA256 of the request.

    ``HMAC-SHA256(key, canonical_json(request without nonce))[:31]`` as ``0x`` + 62
    hex digits. String keys are UTF-8 encoded.
    """
    data = request_data(request)
    data.pop("nonce", None)
    digest = hmac.new(_key_bytes(key), canonical_json(data).encode("utf-8"), hashlib.sha256)
    return "0x" + digest.digest()[:31].hex()


# ===================================================================== replay caches


class ReplayCache(Protocol):
    """Remembers nonces of accepted proofs until their request expires."""

    def has(self, nonce: str, now: int) -> bool:
        """Whether the nonce was accepted before and its request has not expired at ``now``."""
        ...

    def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        """Record the nonce until ``expires_at``; ``False`` when already recorded (a replay)."""
        ...


class AsyncReplayCache(Protocol):
    """A :class:`ReplayCache` backed by async storage (Redis, a database, ...)."""

    async def has(self, nonce: str, now: int) -> bool:
        """Whether the nonce was accepted before and its request has not expired at ``now``."""
        ...

    async def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        """Record the nonce until ``expires_at``; ``False`` when already recorded (a replay)."""
        ...


class MemoryReplayCache:
    """An in-memory replay cache for a single process.

    Expired entries are evicted as new ones arrive; when ``max_entries`` unexpired
    entries exist, the soonest-expiring is dropped. Share a persistent cache
    (:class:`ReplayCache`) across instances behind a load balancer.
    """

    def __init__(self, *, max_entries: int = 100_000) -> None:
        if not _is_int(max_entries) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self._entries: dict[str, int] = {}
        self._max_entries = max_entries

    def __len__(self) -> int:
        return len(self._entries)

    def has(self, nonce: str, now: int) -> bool:
        """Whether ``nonce`` was consumed and its request has not expired at ``now``."""
        expires_at = self._entries.get(nonce)
        if expires_at is None:
            return False
        if expires_at < now:
            del self._entries[nonce]
            return False
        return True

    def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        """Record ``nonce`` until ``expires_at``; ``False`` if it is already recorded."""
        if self.has(nonce, now):
            return False
        if len(self._entries) >= self._max_entries:
            self.evict(now)
        self._entries[nonce] = expires_at
        return True

    def evict(self, now: int) -> None:
        """Drop expired entries, then the soonest-expiring ones while the cache is full."""
        for nonce in [n for n, expires_at in self._entries.items() if expires_at < now]:
            del self._entries[nonce]
        while len(self._entries) >= self._max_entries:
            soonest = min(self._entries.items(), key=lambda item: item[1])
            del self._entries[soonest[0]]


# ===================================================================== gates


class HeaderSource(Protocol):
    """Request headers: a mapping, ``httpx.Headers``, Starlette or Werkzeug headers."""

    def get(self, key: str, /) -> Any:
        """The header's value, or ``None``."""
        ...


def _read_header(headers: HeaderSource, name: str) -> str | None:
    value = headers.get(name)
    if value is None:
        items = getattr(headers, "items", None)
        if callable(items):
            wanted = name.lower()
            for key, item in items():
                if isinstance(key, str) and key.lower() == wanted:
                    value = item
                    break
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value if isinstance(value, str) else None


@dataclass(frozen=True)
class ProofChallenge:
    """The 401 response asking for a proof.

    Attributes:
        status: Always 401.
        headers: ``WWW-Authenticate`` and ``AGENT-PROOF-REQUIRED``.
        body: ``{"error": "proof_required", "reason", "request"}`` (JSON).
        request: The request the agent must prove.
    """

    status: int
    headers: dict[str, str]
    body: dict[str, Any]
    request: ProofRequest


@dataclass(frozen=True)
class ProofRequired:
    """A gate's verdict: no acceptable proof; answer with ``response``.

    Attributes:
        reason: Why the proof was refused (``None``: there was none).
        response: The 401 challenge to send.
    """

    reason: ProofFailureReason | None
    response: ProofChallenge
    kind: Literal["proof-required"] = "proof-required"


@dataclass(frozen=True)
class ProofVerified:
    """A gate's verdict: the proof holds.

    Attributes:
        nullifier: The agent's stable pseudonym for this scope.
        root: The root it proved against.
        request: The request it proved.
        headers: Add these to the 2xx response (``AGENT-PROOF-RESPONSE``).
    """

    nullifier: str
    root: str
    request: ProofRequest
    headers: dict[str, str]
    kind: Literal["verified"] = "verified"


#: The result of :meth:`ProofGate.check`.
ProofGateResult = ProofVerified | ProofRequired


class _GateCore:
    def __init__(
        self,
        *,
        scope: str,
        key: str | bytes,
        require: Iterable[Requirement],
        ttl_seconds: int,
        min_anonymity_set: int,
        max_root_age_seconds: int,
        chain_id: int,
        registry: str | None,
        now: Callable[[], int] | None,
        verification_key: Mapping[str, Any] | None,
    ) -> None:
        self._key = _key_bytes(key)
        if len(self._key) < 32:
            raise ValueError("the gate key must be at least 32 bytes")
        self._scope = _check_scope(scope)
        assert_testnet(chain_id)
        self._require = tuple(require)
        self._ttl_seconds = ttl_seconds
        self._min_anonymity_set = min_anonymity_set
        self._max_root_age_seconds = max_root_age_seconds
        self._chain_id = chain_id
        self._registry = registry
        self._clock = now or (lambda: int(time.time()))
        self._verification_key = verification_key
        self.create_request()  # surface configuration errors now, not per request

    @property
    def scope(self) -> str:
        """The verifier's scope."""
        return self._scope

    def create_request(self) -> ProofRequest:
        """A fresh request with an authentic (HMAC-derived) nonce."""
        draft = create_proof_request(
            self._scope,
            require=self._require,
            ttl_seconds=self._ttl_seconds,
            max_root_age_seconds=self._max_root_age_seconds,
            min_anonymity_set=self._min_anonymity_set,
            chain_id=self._chain_id,
            registry=self._registry,
            nonce="0x" + "0" * 62,
            now=self._clock(),
        )
        return draft.model_copy(update={"nonce": gate_nonce(self._key, draft)})

    def challenge(self, reason: ProofFailureReason | None = None) -> ProofChallenge:
        """The 401 response asking for a proof (a fresh request each time)."""
        request = self.create_request()
        return ProofChallenge(
            status=401,
            headers={
                PROOF_HEADERS.www_authenticate: www_authenticate(self._scope),
                PROOF_REQUIRED_HEADER: encode_proof_required(request),
            },
            body={"error": "proof_required", "reason": reason, "request": request_data(request)},
            request=request,
        )

    def _required(self, reason: ProofFailureReason | None) -> ProofRequired:
        return ProofRequired(reason=reason, response=self.challenge(reason))

    def _decode(self, headers: HeaderSource) -> ProofEnvelope | ProofRequired:
        header = _read_header(headers, PROOF_HEADER)
        if header is None or not header.strip():
            return self._required(None)
        try:
            return decode_proof(header)
        except ProofHeaderError:
            return self._required("malformed")

    def _forged(self, request: ProofRequest) -> bool:
        if request.scope != self._scope:
            return True
        return not hmac.compare_digest(request.nonce, gate_nonce(self._key, request))

    def _verified(self, result: VerificationResult) -> ProofVerified:
        assert result.request is not None
        assert result.nullifier is not None
        assert result.root is not None
        return ProofVerified(
            nullifier=result.nullifier,
            root=result.root,
            request=result.request,
            headers={PROOF_RESPONSE_HEADER: encode_proof_response(result.nullifier)},
        )


class ProofGate(_GateCore):
    """A stateless proof gate for an HTTP resource (synchronous).

    Nonces are derived from ``key`` (HMAC-SHA256 of the request), so the gate
    keeps no per-challenge state; a replay cache remembers used nonces until
    their request expires. Byte-for-byte compatible with ``createProofGate`` in
    ``@agentbank/proofs``::

        gate = ProofGate(
            scope="api.seller.example",
            key=key,
            require=[verified_company()],
            root_resolver=bank.proofs.root_resolver(),
        )
        result = gate.check(request.headers)
        if result.kind == "proof-required":
            ...  # answer result.response.status / .headers / .body
        else:
            ...  # serve; add result.headers; result.nullifier identifies the agent here

    Args:
        scope: The verifier's scope, normally its host name.
        key: HMAC key for stateless nonces, at least 32 bytes (strings are UTF-8).
        require: Requirements every request carries.
        root_resolver: Where roots are checked, e.g. ``bank.proofs.root_resolver()``.
        ttl_seconds: How long a challenge stays valid (default 300 s).
        replay_cache: Used nonces (default: a fresh in-memory cache).
        min_anonymity_set: Default 16.
        max_root_age_seconds: Default 7,200 s.
        chain_id: Default Base Sepolia (84532); mainnets are refused.
        registry: Default ``None`` (the deployment's registry).
        now: Clock in unix seconds (default the system clock).
        verification_key: Defaults to the bundled claims-circuit key.

    Raises:
        ValueError: The key is shorter than 32 bytes or the scope is invalid.
        ProofRequestError: The requirements cannot all hold.
    """

    def __init__(
        self,
        *,
        scope: str,
        key: str | bytes,
        root_resolver: RootResolver,
        require: Iterable[Requirement] = (),
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        replay_cache: ReplayCache | None = None,
        min_anonymity_set: int = DEFAULT_MIN_ANONYMITY_SET,
        max_root_age_seconds: int = DEFAULT_MAX_ROOT_AGE_SECONDS,
        chain_id: int = DEFAULT_CHAIN_ID,
        registry: str | None = None,
        now: Callable[[], int] | None = None,
        verification_key: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            key=key,
            require=require,
            ttl_seconds=ttl_seconds,
            min_anonymity_set=min_anonymity_set,
            max_root_age_seconds=max_root_age_seconds,
            chain_id=chain_id,
            registry=registry,
            now=now,
            verification_key=verification_key,
        )
        self._resolver = root_resolver
        self._cache: ReplayCache = replay_cache if replay_cache is not None else MemoryReplayCache()

    def check(self, headers: HeaderSource) -> ProofGateResult:
        """Check a request's ``AGENT-PROOF`` header.

        Root resolver errors propagate (answer 5xx: fail closed).
        """
        decoded = self._decode(headers)
        if isinstance(decoded, ProofRequired):
            return decoded
        now = self._clock()

        def check_nonce(request: ProofRequest) -> NonceReason | None:
            if self._forged(request):
                return "nonce_invalid"
            return "nonce_reused" if self._cache.has(request.nonce, now) else None

        result = verify_presentation(
            decoded.request,
            decoded.presentation,
            root_resolver=self._resolver,
            now=now,
            verification_key=self._verification_key,
            check_nonce=check_nonce,
        )
        if not result.valid:
            return self._required(result.reason)
        assert result.request is not None
        if not self._cache.consume(result.request.nonce, result.request.expires_at, now):
            return self._required("nonce_reused")
        return self._verified(result)


class AsyncProofGate(_GateCore):
    """:class:`ProofGate` for async servers (FastAPI, Starlette, aiohttp, ...).

    ``root_resolver`` and ``replay_cache`` may be sync or async; the pairing check
    runs in a worker thread. Same arguments as :class:`ProofGate`.
    """

    def __init__(
        self,
        *,
        scope: str,
        key: str | bytes,
        root_resolver: RootResolver | AsyncRootResolver,
        require: Iterable[Requirement] = (),
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        replay_cache: ReplayCache | AsyncReplayCache | None = None,
        min_anonymity_set: int = DEFAULT_MIN_ANONYMITY_SET,
        max_root_age_seconds: int = DEFAULT_MAX_ROOT_AGE_SECONDS,
        chain_id: int = DEFAULT_CHAIN_ID,
        registry: str | None = None,
        now: Callable[[], int] | None = None,
        verification_key: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            key=key,
            require=require,
            ttl_seconds=ttl_seconds,
            min_anonymity_set=min_anonymity_set,
            max_root_age_seconds=max_root_age_seconds,
            chain_id=chain_id,
            registry=registry,
            now=now,
            verification_key=verification_key,
        )
        self._resolver = root_resolver
        self._cache: ReplayCache | AsyncReplayCache = (
            replay_cache if replay_cache is not None else MemoryReplayCache()
        )

    async def check(self, headers: HeaderSource) -> ProofGateResult:
        """Check a request's ``AGENT-PROOF`` header.

        Root resolver errors propagate (answer 5xx: fail closed).
        """
        decoded = self._decode(headers)
        if isinstance(decoded, ProofRequired):
            return decoded
        now = self._clock()

        async def check_nonce(request: ProofRequest) -> NonceReason | None:
            if self._forged(request):
                return "nonce_invalid"
            used = await _resolve(self._cache.has(request.nonce, now))
            return "nonce_reused" if used else None

        result = await averify_presentation(
            decoded.request,
            decoded.presentation,
            root_resolver=self._resolver,
            now=now,
            verification_key=self._verification_key,
            check_nonce=check_nonce,
        )
        if not result.valid:
            return self._required(result.reason)
        assert result.request is not None
        consumed = await _resolve(
            self._cache.consume(result.request.nonce, result.request.expires_at, now)
        )
        if not consumed:
            return self._required("nonce_reused")
        return self._verified(result)


# ===================================================================== proving

#: Environment variable holding the prover command line.
PROVER_ENV: Final = "AGENTBANK_PROVER"
#: Environment variable holding the agent's proof secret (32-byte hex).
PROOF_SECRET_ENV: Final = "AGENTBANK_PROOF_SECRET"  # noqa: S105 (a variable name)
#: Seconds the prover may run (proving takes about two seconds).
DEFAULT_PROVER_TIMEOUT: Final = 120.0

_REFUSAL_REASONS: Final = frozenset(
    {"unsatisfiable", "undisclosed", "witness_mismatch", "chain_mismatch"}
)


def generate_proof_secret() -> str:
    """A fresh proof secret: 31 random bytes (always a field element) as 32-byte hex.

    Keep it secret: whoever holds it can prove as the agent. Enroll only its
    commitment (``bank.proofs.enroll(secret=...)`` computes it with the prover).
    """
    return to_bytes32(int.from_bytes(secrets.token_bytes(31), "big"))


def proof_secret_from_env() -> str | None:
    """``AGENTBANK_PROOF_SECRET``, if set."""
    value = os.environ.get(PROOF_SECRET_ENV, "").strip()
    return value or None


def _normalize_secret(secret: object) -> str:
    """The secret as 32-byte hex (never echoed in errors)."""
    value = secret.strip() if isinstance(secret, str) else ""
    if _HEX_FIELD_RE.fullmatch(value) is None:
        raise ProverError("invalid_input", "The proof secret must be 0x-prefixed hex (32 bytes)")
    number = int(value, 16)
    if not 0 < number < SNARK_SCALAR_FIELD:
        raise ProverError(
            "invalid_input", "The proof secret must be a non-zero BN254 field element"
        )
    return to_bytes32(number)


def _witness_data(witness: ProofWitness | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(witness, ProofWitness):
        data: dict[str, Any] = witness.model_dump(mode="json", by_alias=True)
        return data
    plain: dict[str, Any] = to_jsonable(witness)
    return plain


@dataclass(frozen=True)
class ProverIdentity:
    """A proof secret and its enrolled commitment (``identity = Poseidon(secret)``).

    Attributes:
        secret: The agent's proof secret (hidden from ``repr``).
        identity_commitment: What ``PUT /v1/accounts/{id}/proofs/identity`` enrolls.
    """

    secret: str = field(repr=False)
    identity_commitment: str


def _redact(text: str, secrets_: Iterable[str]) -> str:
    for value in secrets_:
        if value:
            text = text.replace(value, "[redacted]")
    return text


def _last_json_line(text: str) -> Any:
    for line in reversed(text.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


class Prover:
    """Runs the ``agentbank-prove`` CLI of ``@agentbank/proofs`` in a subprocess.

    The command comes from ``command`` or ``AGENTBANK_PROVER``, e.g.
    ``node /path/to/agent-bank/packages/proofs/bin/agentbank-prove.mjs``. The secret
    is only written to the prover's stdin, never to its arguments, environment or
    any error message.

    Args:
        command: The command line (a string, split like a shell would) or argv.
        timeout: Seconds the prover may run (default 120).
    """

    def __init__(
        self,
        command: str | Sequence[str] | None = None,
        *,
        timeout: float = DEFAULT_PROVER_TIMEOUT,
    ) -> None:
        if command is None:
            command = os.environ.get(PROVER_ENV, "").strip() or None
        argv = tuple(shlex.split(command)) if isinstance(command, str) else tuple(command or ())
        self._argv = argv or None
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"{type(self).__name__}(command={self._argv!r}, timeout={self._timeout!r})"

    @property
    def command(self) -> tuple[str, ...] | None:
        """The prover's argv (without the mode), or ``None`` when not configured."""
        return self._argv

    @property
    def configured(self) -> bool:
        """Whether a prover command is configured."""
        return self._argv is not None

    def prove(
        self,
        *,
        secret: str,
        witness: ProofWitness | Mapping[str, Any],
        request: RequestLike,
    ) -> ProofPresentation:
        """Prove ``request`` with the agent's ``secret`` and ``witness`` (about two seconds).

        Raises:
            ProofRefusedError: The witness cannot prove the request (exit code 3).
            ProverError: No prover, invalid input (exit 2), a failure or a timeout.
        """
        normalized = _normalize_secret(secret)
        payload = {
            "secret": normalized,
            "witness": _witness_data(witness),
            "request": request_data(request),
        }
        output = self._run("prove", payload, (secret, normalized))
        try:
            data = _validate_presentation(output)
        except _SchemaError as exc:
            raise ProverError(
                "prover_failed", f"The prover returned an invalid presentation ({exc})"
            ) from None
        return ProofPresentation.model_validate(data)

    def identity(self, secret: str | None = None) -> ProverIdentity:
        """The identity commitment of ``secret`` (a fresh secret when ``None``).

        Raises:
            ProverError: No prover, an invalid secret, a failure or a timeout.
        """
        normalized = None if secret is None else _normalize_secret(secret)
        payload = None if normalized is None else {"secret": normalized}
        output = self._run("identity", payload, (secret or "", normalized or ""))
        if (
            not isinstance(output, Mapping)
            or not isinstance(output.get("secret"), str)
            or not isinstance(output.get("identity_commitment"), str)
            or _BYTES32_RE.fullmatch(output["identity_commitment"]) is None
        ):
            raise ProverError("prover_failed", "The prover returned an invalid identity")
        return ProverIdentity(
            secret=_normalize_secret(output["secret"]),
            identity_commitment=output["identity_commitment"].lower(),
        )

    def _run(self, mode: str, payload: Any, hidden: Iterable[str]) -> Any:
        if self._argv is None:
            raise ProverError(
                "prover_not_configured",
                f"No prover is configured: set {PROVER_ENV} to the agentbank-prove command, "
                "e.g. 'node /path/to/agent-bank/packages/proofs/bin/agentbank-prove.mjs'",
            )
        stdin = b"" if payload is None else json.dumps(payload).encode("utf-8")
        try:
            completed = subprocess.run(  # noqa: S603 (the user's prover command)
                [*self._argv, mode],
                input=stdin,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError:
            raise ProverError(
                "prover_not_configured", f"The prover command {self._argv[0]!r} was not found"
            ) from None
        except subprocess.TimeoutExpired:
            raise ProverError(
                "prover_timeout", f"The prover did not finish within {self._timeout:g} s"
            ) from None
        except OSError as exc:
            raise ProverError(
                "prover_failed", f"Could not run the prover: {exc.strerror}"
            ) from None
        stderr = _redact(completed.stderr.decode("utf-8", "replace"), hidden)
        if completed.returncode == 0:
            output = _last_json_line(completed.stdout.decode("utf-8", "replace"))
            if output is None:
                raise ProverError("prover_failed", "The prover wrote no JSON on stdout")
            return output
        error = _last_json_line(stderr)
        error = error if isinstance(error, Mapping) else {}
        message = str(error.get("message") or stderr.strip()[-500:] or "no message")
        if completed.returncode == 3:
            reason = error.get("reason")
            raise ProofRefusedError(
                reason if reason in _REFUSAL_REASONS else "unsatisfiable",
                message,
                attributes=tuple(str(a) for a in error.get("attributes") or ()),
                undisclosed_classes=tuple(str(c) for c in error.get("undisclosed_classes") or ()),
            )
        if completed.returncode == 2:
            raise ProverError("invalid_input", f"The prover rejected its input: {message}")
        raise ProverError(
            "prover_failed", f"The prover exited with status {completed.returncode}: {message}"
        )


class AsyncProver:
    """:class:`Prover` for async code: the subprocess runs in a worker thread.

    Same arguments as :class:`Prover`.
    """

    def __init__(
        self,
        command: str | Sequence[str] | None = None,
        *,
        timeout: float = DEFAULT_PROVER_TIMEOUT,
    ) -> None:
        self._prover = Prover(command, timeout=timeout)

    def __repr__(self) -> str:
        return repr(self._prover).replace("Prover(", "AsyncProver(", 1)

    @property
    def command(self) -> tuple[str, ...] | None:
        """The prover's argv (without the mode), or ``None`` when not configured."""
        return self._prover.command

    @property
    def configured(self) -> bool:
        """Whether a prover command is configured."""
        return self._prover.configured

    async def prove(
        self,
        *,
        secret: str,
        witness: ProofWitness | Mapping[str, Any],
        request: RequestLike,
    ) -> ProofPresentation:
        """See :meth:`Prover.prove`."""
        return await anyio.to_thread.run_sync(
            partial(self._prover.prove, secret=secret, witness=witness, request=request)
        )

    async def identity(self, secret: str | None = None) -> ProverIdentity:
        """See :meth:`Prover.identity`."""
        return await anyio.to_thread.run_sync(partial(self._prover.identity, secret))


# ===================================================================== receipts

#: Key under which proof transports attach a :class:`ProofReceipt` to ``response.extensions``.
PROOF_RECEIPT_EXTENSION: Final = "agentbank.proof"


@dataclass(frozen=True)
class ProofReceipt:
    """What a proof transport proved for a response.

    Attributes:
        request: The verifier's request.
        presentation: The presentation sent.
        header: The ``AGENT-PROOF`` header value sent.
        nullifier: The pseudonym the verifier reported (``AGENT-PROOF-RESPONSE``), if any.
    """

    request: ProofRequest
    presentation: ProofPresentation
    header: str = field(repr=False)
    nullifier: str | None = None


def proof_receipt(response: Any) -> ProofReceipt | None:
    """The :class:`ProofReceipt` attached to an ``httpx.Response``, if a proof was sent."""
    extensions = getattr(response, "extensions", None)
    if not isinstance(extensions, Mapping):
        return None
    receipt = extensions.get(PROOF_RECEIPT_EXTENSION)
    return receipt if isinstance(receipt, ProofReceipt) else None
