"""Errors, money, chains and keys."""

from __future__ import annotations

import json
import os
import stat
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentbank import (
    AgentBankError,
    APIConnectionError,
    APITimeoutError,
    ConfigurationError,
    FrozenError,
    IdempotencyConflictError,
    InternalServerError,
    MainnetLockedError,
    NotFoundError,
    PolicyDeniedError,
    RateLimitError,
    ServiceUnavailableError,
    SessionKey,
    format_amount,
    generate_session_key,
    generate_spend_key,
    money,
    parse_amount,
)
from agentbank.chains import (
    BASE_SEPOLIA,
    assert_testnet,
    chain_by_id,
    chain_by_name,
    chain_for_network,
    find_asset,
)
from agentbank.errors import (
    ERROR_CATALOG,
    BadRequestError,
    PermissionDeniedError,
    UnprocessableEntityError,
    error_from_response,
)
from agentbank.keys import personal_sign_hash, to_signer
from agentbank.models import Money
from agentbank.money import coerce_money, to_minor
from tests.conftest import SESSION_ADDRESS, SESSION_KEY, VIEM_VECTORS

# --------------------------------------------------------------------- errors


def problem_response(status: int, body: Any, **headers: str) -> httpx.Response:
    request = httpx.Request("GET", "https://api.agentbank.test/v1/x")
    if isinstance(body, (dict, list)):
        return httpx.Response(
            status,
            json=body,
            headers={"content-type": "application/problem+json", **headers},
            request=request,
        )
    return httpx.Response(status, text=body, headers=headers, request=request)


@pytest.mark.parametrize(
    ("status", "code", "cls"),
    [
        (422, "policy_denied", PolicyDeniedError),
        (409, "idempotency_conflict", IdempotencyConflictError),
        (423, "agent_frozen", FrozenError),
        (503, "cosigner_unavailable", ServiceUnavailableError),
        (403, "mainnet_locked", MainnetLockedError),
        (400, "invalid_amount", BadRequestError),
        (403, "feature_gated", PermissionDeniedError),
        (404, "not_found", NotFoundError),
        (429, "rate_limited", RateLimitError),
        (502, "chain_error", InternalServerError),
        (422, "mandate_expired", UnprocessableEntityError),
        (418, "teapot", AgentBankError),
    ],
)
def test_problem_documents_map_to_specific_errors(
    status: int, code: str, cls: type[AgentBankError]
) -> None:
    problem = {
        "type": f"urn:agentbank:problem:{code}",
        "title": "Title",
        "status": status,
        "detail": "Something precise",
        "instance": "/v1/payments/pay_1",
        "code": code,
        "rule_hits": [{"rule": "limits.per_day"}],
    }
    error = error_from_response(problem_response(status, problem, **{"x-request-id": "req_1"}))
    assert type(error) is cls
    assert error.code == code
    assert error.status == status
    assert error.detail == "Something precise"
    assert error.instance == "/v1/payments/pay_1"
    assert error.extensions == {"rule_hits": [{"rule": "limits.per_day"}]}
    assert error.request_id == "req_1"
    assert error.response is not None
    assert str(error) == f"{status} {code}: Something precise"
    assert code in repr(error)
    assert error.to_problem()["rule_hits"] == [{"rule": "limits.per_day"}]


def test_non_problem_error_bodies() -> None:
    html = error_from_response(problem_response(502, "<html>Bad gateway</html>"))
    assert isinstance(html, InternalServerError)
    assert html.code == "internal"
    assert html.detail == "<html>Bad gateway</html>"
    empty = error_from_response(problem_response(404, ""))
    assert isinstance(empty, NotFoundError)
    assert empty.detail == "Not Found"
    titled = error_from_response(problem_response(400, {"title": "Bad thing", "status": 400}))
    assert titled.code == "invalid_request"
    assert titled.detail == "Bad thing"
    odd = error_from_response(problem_response(418, ["not", "an", "object"]))
    assert odd.code == "http_error"


def test_local_errors_carry_catalog_metadata() -> None:
    error = AgentBankError("policy_denied")
    assert error.status == 422
    assert error.detail == ERROR_CATALOG["policy_denied"][1]
    assert error.type == "urn:agentbank:problem:policy_denied"
    assert error.to_problem() == {
        "type": "urn:agentbank:problem:policy_denied",
        "title": "Payment denied by policy",
        "detail": "Payment denied by policy",
        "code": "policy_denied",
        "status": 422,
    }
    custom = AgentBankError("x402_unsupported", "nope")
    assert custom.status is None
    assert custom.type is None
    assert str(custom) == "x402_unsupported: nope"
    assert "status" not in custom.to_problem()
    assert APITimeoutError().code == "timeout"
    assert isinstance(APITimeoutError(), APIConnectionError)
    assert ConfigurationError("missing").code == "configuration_error"


# --------------------------------------------------------------------- money


@pytest.mark.parametrize(
    ("text", "minor"),
    [("0", 0), ("12.50", 12_500_000), ("0.000001", 1), ("1", 1_000_000), ("25.00", 25_000_000)],
)
def test_parse_and_format_amounts(text: str, minor: int) -> None:
    assert parse_amount(text) == minor
    assert parse_amount(format_amount(minor)) == minor


@pytest.mark.parametrize(
    "bad",
    ["", "01", "1.", ".5", "1e3", "-1", " 1", "1.0000001", "٣", str(2**63)],
)
def test_parse_amount_rejects_malformed(bad: str) -> None:
    with pytest.raises(AgentBankError) as excinfo:
        parse_amount(bad)
    assert excinfo.value.code == "invalid_amount"


def test_amount_helpers_edge_cases() -> None:
    assert format_amount(25_000_000) == "25.00"
    assert format_amount(1) == "0.000001"
    assert format_amount(-1_500_000) == "-1.50"
    assert format_amount(5, 0) == "5"
    assert format_amount(10, 2, min_fraction_digits=0) == "0.1"
    with pytest.raises(AgentBankError):
        parse_amount(12.5)  # type: ignore[arg-type]
    with pytest.raises(AgentBankError):
        format_amount(1.5)  # type: ignore[arg-type]
    with pytest.raises(AgentBankError):
        parse_amount("1", 40)


def test_money_coercion_never_accepts_floats() -> None:
    assert money("1.50") == Money(amount="1.50", asset="USDC")
    assert money(Decimal("2.5")).amount == "2.5"
    assert coerce_money({"amount": "3.00"}).asset == "USDC"
    assert coerce_money({"amount": Decimal("3"), "asset": "USDC"}).amount == "3"
    existing = Money(amount="4.00", asset="USDC")
    assert coerce_money(existing) is existing
    assert to_minor("0.10") == 100_000
    for bad in (1.5, 2, None, {"amount": 1.5}, Decimal("-1"), Decimal("Infinity")):
        with pytest.raises(AgentBankError):
            coerce_money(bad)  # type: ignore[arg-type]
    with pytest.raises(AgentBankError) as unsupported:
        money("1.00", "EURC")
    assert unsupported.value.code == "unsupported_asset"


# --------------------------------------------------------------------- chains


def test_testnet_lock() -> None:
    assert assert_testnet(84532) is BASE_SEPOLIA
    assert chain_by_id(31337).name == "anvil"
    assert chain_by_name("simulated").id == 1337
    for mainnet in (1, 8453, 10, 42161, 137):
        with pytest.raises(MainnetLockedError):
            assert_testnet(mainnet)
    with pytest.raises(AgentBankError, match="not supported"):
        assert_testnet(5)
    with pytest.raises(AgentBankError, match="Unknown chain"):
        chain_by_name("base")


def test_x402_network_resolution() -> None:
    assert chain_for_network("eip155:84532") is BASE_SEPOLIA
    assert chain_for_network("base-sepolia") is BASE_SEPOLIA
    with pytest.raises(MainnetLockedError):
        chain_for_network("eip155:8453")
    with pytest.raises(MainnetLockedError):
        chain_for_network("base")
    with pytest.raises(AgentBankError, match="Invalid CAIP-2"):
        chain_for_network("eip155:abc")
    with pytest.raises(AgentBankError, match="Unknown network"):
        chain_for_network("solana-devnet")
    usdc = find_asset(84532, "0x036cbd53842c5426634e7929541ec2318f3dcf7e")
    assert usdc is not None
    assert usdc.decimals == 6
    assert find_asset(84532, "0x" + "00" * 20) is None
    assert find_asset(31337, "0x036CbD53842c5426634e7929541eC2318f3dCF7e") is None


# --------------------------------------------------------------------- keys


def test_session_keys_hide_private_material(tmp_path: Path) -> None:
    key = generate_session_key()
    assert key.private_key not in repr(key)
    assert key.address.startswith("0x")
    assert generate_spend_key().address != key.address
    path = tmp_path / "session.json"
    key.save(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert SessionKey.load(path) == key
    with pytest.raises(FileExistsError):
        key.save(path)
    other = generate_session_key()
    other.save(path, overwrite=True)
    assert SessionKey.load(path) == other
    tampered = json.loads(path.read_text())
    tampered["address"] = key.address
    path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="does not match"):
        SessionKey.load(path)


def test_session_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTBANK_SESSION_KEY", f" {SESSION_KEY} ")
    assert SessionKey.from_env().address == SESSION_ADDRESS
    monkeypatch.delenv("AGENTBANK_SESSION_KEY")
    with pytest.raises(KeyError):
        SessionKey.from_env()


def test_signer_normalization_and_raw_hash_signing() -> None:
    vector = VIEM_VECTORS["user_op"]
    from_bytes = to_signer(bytes.fromhex(vector["session_private_key"][2:]))
    assert from_bytes.address == vector["session_address"]
    assert personal_sign_hash(from_bytes, vector["user_op_hash"]) == vector["signature"]
    key = SessionKey.from_private_key(vector["session_private_key"])
    assert to_signer(key).address == key.address
    assert to_signer(key.account) is not None
    with pytest.raises(ValueError, match="32-byte"):
        personal_sign_hash(from_bytes, "0x1234")
