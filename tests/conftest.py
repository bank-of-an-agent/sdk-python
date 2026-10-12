"""Shared fixtures. Keys are public Anvil development keys (never use for real funds)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from agentbank import AgentBank, AsyncAgentBank, verify_request
from agentbank.http_signatures import VerifiedSignature
from tests.factories import id_for

VECTORS: dict[str, Any] = json.loads((Path(__file__).parent / "vectors.json").read_text("utf-8"))
VIEM_VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "viem_vectors.json").read_text("utf-8")
)

BASE_URL = "https://api.agentbank.test"
API_KEY = "abk_test_0123456789abcdef"
SESSION_KEY = VECTORS["keys"]["session_private_key"]
SESSION_ADDRESS = VECTORS["keys"]["session_address"]
OWNER_KEY = VECTORS["keys"]["owner_private_key"]
OWNER_ADDRESS = VECTORS["keys"]["owner_address"]
SPEND_KEY = VIEM_VECTORS["eip3009"]["spend_private_key"]
SPEND_ADDRESS = VIEM_VECTORS["eip3009"]["spend_address"]

SESSION_ID = id_for("ses")
ACCOUNT_ID = id_for("acct")
AGENT_ID = id_for("agt")
ORG_ID = id_for("org")
PAYMENT_ID = id_for("pay")


def verify_agent_request(request: httpx.Request) -> VerifiedSignature:
    """Verify an agent request exactly as the API would (RFC 9421)."""
    return verify_request(
        request.method,
        str(request.url),
        dict(request.headers),
        request.content,
        resolve_key=lambda key_id: SESSION_ADDRESS if key_id == SESSION_ID else None,
    )


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's AGENTBANK_* environment out of the tests."""
    for name in (
        "AGENTBANK_BASE_URL",
        "AGENTBANK_FACILITATOR_URL",
        "AGENTBANK_API_KEY",
        "AGENTBANK_SESSION_ID",
        "AGENTBANK_SESSION_KEY",
        "AGENTBANK_SPEND_KEY",
        "AGENTBANK_ACCOUNT_ID",
        "AGENTBANK_PROOF_SECRET",
        "AGENTBANK_PROVER",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record retry/poll delays instead of sleeping."""
    recorded: list[float] = []

    def fake_sleep(self: object, seconds: float) -> None:
        recorded.append(seconds)

    async def fake_async_sleep(self: object, seconds: float) -> None:
        recorded.append(seconds)

    monkeypatch.setattr(AgentBank, "_sleep", fake_sleep)
    monkeypatch.setattr(AsyncAgentBank, "_sleep", fake_async_sleep)
    return recorded


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """A respx router for the mocked Agent Bank API."""
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
def principal() -> Iterator[AgentBank]:
    """A principal client (org API key)."""
    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as client:
        yield client


@pytest.fixture
def agent() -> Iterator[AgentBank]:
    """An agent client (session key, spend key and default account)."""
    with AgentBank(
        session_id=SESSION_ID,
        session_key=SESSION_KEY,
        spend_key=SPEND_KEY,
        account_id=ACCOUNT_ID,
        base_url=BASE_URL,
    ) as client:
        yield client


@pytest.fixture
async def async_agent() -> AsyncIterator[AsyncAgentBank]:
    """An async agent client."""
    async with AsyncAgentBank(
        session_id=SESSION_ID,
        session_key=SESSION_KEY,
        spend_key=SPEND_KEY,
        account_id=ACCOUNT_ID,
        base_url=BASE_URL,
    ) as client:
        yield client


@pytest.fixture
async def async_principal() -> AsyncIterator[AsyncAgentBank]:
    """An async principal client."""
    async with AsyncAgentBank(api_key=API_KEY, base_url=BASE_URL) as client:
        yield client
