"""Groth16 verification on BN254 in pure Python (``py_ecc``), and the bundled circuit key.

A snarkjs proof ``(A, B, C)`` verifies against a verification key and public
signals ``s`` when

    e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta),
    vk_x = IC[0] + sum(s[i] * IC[i + 1]),

checked here as one product of Miller loops with a single final exponentiation:
``e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1``. Points come in
snarkjs JSON form: G1 as ``[x, y, "1"]``, G2 as ``[[x0, x1], [y0, y1], ["1", "0"]]``
with ``x = x0 + x1 * u`` (``FQ2([x0, x1])``). Proof points must be affine, on the
curve and (for B) in the prime-order subgroup.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Final

from py_ecc.fields import optimized_bn128_FQ as FQ
from py_ecc.fields import optimized_bn128_FQ2 as FQ2
from py_ecc.fields import optimized_bn128_FQ12 as FQ12
from py_ecc.optimized_bn128.optimized_curve import (
    add,
    b,
    b2,
    curve_order,
    field_modulus,
    is_inf,
    is_on_curve,
    multiply,
    neg,
)
from py_ecc.optimized_bn128.optimized_pairing import final_exponentiate, pairing

__all__ = [
    "VerificationKey",
    "circuit_manifest",
    "load_verification_key",
    "parse_verification_key",
    "verify",
]

_DECIMAL = re.compile(r"(0|[1-9][0-9]{0,76})")

#: The BN254 scalar field order (public signals are below it).
SCALAR_FIELD: Final = curve_order

G1Point = tuple[FQ, FQ, FQ]
G2Point = tuple[FQ2, FQ2, FQ2]


@dataclass(frozen=True)
class VerificationKey:
    """A parsed Groth16 verification key (points on BN254)."""

    alpha: G1Point
    beta: G2Point
    gamma: G2Point
    delta: G2Point
    ic: tuple[G1Point, ...]

    @property
    def public_inputs(self) -> int:
        """Number of public signals the key verifies."""
        return len(self.ic) - 1


def _coordinate(value: Any) -> int:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        raise ValueError("coordinates must be base-10 strings")
    number = int(value)
    if number >= field_modulus:
        raise ValueError("coordinate is not below the field modulus")
    return number


def _g1(value: Any) -> G1Point:
    if not isinstance(value, Sequence) or isinstance(value, str) or len(value) != 3:
        raise ValueError("a G1 point is [x, y, z]")
    x, y, z = (_coordinate(v) for v in value)
    if z != 1:
        raise ValueError("G1 points must be affine (z = 1)")
    point = (FQ(x), FQ(y), FQ(1))
    if not is_on_curve(point, b):
        raise ValueError("G1 point is not on the curve")
    return point


def _g2(value: Any) -> G2Point:
    if not isinstance(value, Sequence) or isinstance(value, str) or len(value) != 3:
        raise ValueError("a G2 point is [[x0, x1], [y0, y1], [z0, z1]]")
    pairs: list[tuple[int, int]] = []
    for pair in value:
        if not isinstance(pair, Sequence) or isinstance(pair, str) or len(pair) != 2:
            raise ValueError("G2 coordinates are pairs")
        pairs.append((_coordinate(pair[0]), _coordinate(pair[1])))
    (x0, x1), (y0, y1), z = pairs
    if z != (1, 0):
        raise ValueError("G2 points must be affine (z = [1, 0])")
    point = (FQ2([x0, x1]), FQ2([y0, y1]), FQ2.one())
    if not is_on_curve(point, b2):
        raise ValueError("G2 point is not on the twist curve")
    if not is_inf(multiply(point, curve_order)):
        raise ValueError("G2 point is not in the prime-order subgroup")
    return point


def parse_verification_key(vkey: Mapping[str, Any]) -> VerificationKey:
    """Parse a snarkjs ``verification_key.json`` for Groth16 on bn128.

    Raises:
        ValueError: The key is not a Groth16 bn128 key or a point is invalid.
    """
    if vkey.get("protocol") != "groth16" or vkey.get("curve") != "bn128":
        raise ValueError("the verification key must be Groth16 on bn128")
    ic = vkey.get("IC")
    if not isinstance(ic, list) or len(ic) < 1:
        raise ValueError("the verification key has no IC points")
    n_public = vkey.get("nPublic")
    if n_public is not None and n_public != len(ic) - 1:
        raise ValueError("nPublic does not match the IC points")
    return VerificationKey(
        alpha=_g1(vkey.get("vk_alpha_1")),
        beta=_g2(vkey.get("vk_beta_2")),
        gamma=_g2(vkey.get("vk_gamma_2")),
        delta=_g2(vkey.get("vk_delta_2")),
        ic=tuple(_g1(point) for point in ic),
    )


def _data(name: str) -> bytes:
    return resources.files("agentbank").joinpath("proofs_data").joinpath(name).read_bytes()


@lru_cache(maxsize=1)
def circuit_manifest() -> Mapping[str, Any]:
    """The bundled claims-circuit manifest (``proofs_data/manifest.json``)."""
    manifest: dict[str, Any] = json.loads(_data("manifest.json"))
    return manifest


@lru_cache(maxsize=1)
def load_verification_key() -> Mapping[str, Any]:
    """The bundled verification key, checked against the manifest's SHA-256.

    Raises:
        ValueError: The bundled key does not match the manifest.
    """
    raw = _data("verification_key.json")
    expected = circuit_manifest()["sha256"]["verification_key"]
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(
            f"bundled verification_key.json does not match the circuit manifest "
            f"(sha256 {actual}, expected {expected})"
        )
    vkey: dict[str, Any] = json.loads(raw)
    return vkey


@lru_cache(maxsize=1)
def _bundled_key() -> VerificationKey:
    return parse_verification_key(load_verification_key())


def _signal(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value) is not None:
        number = int(value)
    else:
        raise ValueError("public signals are integers or base-10 strings")
    if not 0 <= number < SCALAR_FIELD:
        raise ValueError("public signals must be BN254 scalar field elements")
    return number


def verify(
    vkey: Mapping[str, Any] | VerificationKey | None,
    public_signals: Sequence[str | int],
    proof: Mapping[str, Any],
) -> bool:
    """Verify a snarkjs Groth16 proof; ``None`` uses the bundled claims-circuit key.

    Returns ``False`` for any malformed or invalid proof or signal (it never
    raises for agent-supplied data).

    Raises:
        ValueError: ``vkey`` is not a valid Groth16 bn128 verification key.
    """
    if vkey is None:
        key = _bundled_key()
    elif isinstance(vkey, VerificationKey):
        key = vkey
    else:
        key = parse_verification_key(vkey)
    try:
        if proof.get("protocol", "groth16") != "groth16" or proof.get("curve", "bn128") != "bn128":
            return False
        signals = [_signal(s) for s in public_signals]
        if len(signals) != key.public_inputs:
            return False
        a = _g1(proof.get("pi_a"))
        b_point = _g2(proof.get("pi_b"))
        c = _g1(proof.get("pi_c"))
    except (ValueError, TypeError, AttributeError):
        return False
    vk_x = key.ic[0]
    for scalar, point in zip(signals, key.ic[1:], strict=True):
        if scalar:
            vk_x = add(vk_x, multiply(point, scalar))
    product = (
        pairing(b_point, neg(a), final_exponentiate=False)
        * pairing(key.beta, key.alpha, final_exponentiate=False)
        * pairing(key.gamma, vk_x, final_exponentiate=False)
        * pairing(key.delta, c, final_exponentiate=False)
    )
    result: bool = final_exponentiate(product) == FQ12.one()
    return result
