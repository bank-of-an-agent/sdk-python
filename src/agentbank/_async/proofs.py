"""Private-proof-aware ``httpx`` transport (asynchronous)."""

from __future__ import annotations

import json
from collections.abc import Callable, Collection, Sequence
from typing import TYPE_CHECKING

import httpx

from agentbank.errors import ProofError, ProofHeaderError
from agentbank.proofs import (
    PROOF_HEADER,
    PROOF_RECEIPT_EXTENSION,
    PROOF_REQUIRED_HEADER,
    PROOF_RESPONSE_HEADER,
    AsyncProver,
    ProofReceipt,
    decode_proof_required,
    decode_proof_response,
    encode_proof,
)

if TYPE_CHECKING:
    from agentbank._async.client import AsyncAgentBank

__all__ = ["AsyncProofTransport"]


class AsyncProofTransport(httpx.AsyncBaseTransport):
    """An ``httpx`` transport that answers private-proof challenges (HTTP 401).

    A response ``401`` with ``AGENT-PROOF-REQUIRED`` is answered by proving the
    verifier's request (``bank.proofs.prove``: witness from Agent Bank, proof by
    the external prover) and retrying once with ``AGENT-PROOF``::

        transport = bank.proofs.transport()
        async with httpx.AsyncClient(transport=transport) as http:
            response = await http.get("https://api.seller.example/v1/data")

    Wrapped by the x402 transport (``bank.x402.client(proofs=True)``), a resource
    that wants a proof and then a payment is answered in one call, and the paid
    retry carries the proof. A verifier that consumed the nonce of that proof gets
    a fresh proof with the payment.

    By default only a verifier whose scope is the request's host is answered (a
    proof for another scope could be relayed to that verifier); ``allowed_scopes``
    lists other scopes to answer. Each proved response carries an
    :class:`agentbank.proofs.ProofReceipt` (:func:`agentbank.proofs.proof_receipt`).

    Args:
        bank: An agent-authenticated client (session key) for witnesses and reservations.
        secret: The agent's proof secret (default ``AGENTBANK_PROOF_SECRET``).
        prover: An :class:`~agentbank.proofs.AsyncProver` or command line (default
            ``AGENTBANK_PROVER``).
        reservation_id: Prove from this reservation (default: picked per request).
        allowed_scopes: Scopes to prove to besides the request's host.
        on_proof: Called with the receipt after each proved request.
        transport: The transport to wrap (default: a new ``httpx.AsyncHTTPTransport``).
    """

    def __init__(
        self,
        bank: AsyncAgentBank,
        *,
        secret: str | None = None,
        prover: AsyncProver | str | Sequence[str] | None = None,
        reservation_id: str | None = None,
        allowed_scopes: Collection[str] | None = None,
        on_proof: Callable[[ProofReceipt], None] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._bank = bank
        self._secret = secret
        self._prover = prover if isinstance(prover, AsyncProver) else AsyncProver(prover)
        self._reservation_id = reservation_id
        self._allowed_scopes = frozenset(s.lower() for s in allowed_scopes or ())
        self._on_proof = on_proof
        self._transport = transport or httpx.AsyncHTTPTransport()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(prover={self._prover!r})"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send ``request``; on a proof challenge, prove and retry once.

        Raises:
            ProofError: ``scope_not_allowed``, ``invalid_header`` or
                ``proof_rejected`` (the verifier refused the proof).
            ProofRefusedError: The agent's attested facts cannot prove the request.
            ProverError: No secret or prover, or the prover failed.
        """
        await request.aread()  # buffer the body so the request can be replayed
        response = await self._transport.handle_async_request(request)
        challenge = response.headers.get(PROOF_REQUIRED_HEADER)
        if response.status_code != 401 or not challenge:
            return response
        try:
            await response.aread()
        finally:
            await response.aclose()

        proof_request = decode_proof_required(challenge)
        scope = proof_request.scope.lower()
        if scope != request.url.host.lower() and scope not in self._allowed_scopes:
            raise ProofError(
                "scope_not_allowed",
                f"{request.url.host} asked for a proof for scope {proof_request.scope!r}; "
                "add it to allowed_scopes to prove to it",
            )
        presentation = await self._bank.proofs.prove(
            proof_request,
            secret=self._secret,
            reservation_id=self._reservation_id,
            prover=self._prover,
        )
        header = encode_proof(proof_request, presentation)
        proved = httpx.Request(
            request.method,
            request.url,
            headers=request.headers.copy(),
            content=request.content,
            extensions=dict(request.extensions),
        )
        proved.headers[PROOF_HEADER] = header
        response = await self._transport.handle_async_request(proved)
        if response.status_code == 401 and response.headers.get(PROOF_REQUIRED_HEADER):
            try:
                await response.aread()
            finally:
                await response.aclose()
            raise ProofError(
                "proof_rejected",
                f"The verifier refused the proof ({_refusal_reason(response.content)})",
                response=response,
            )
        receipt = ProofReceipt(
            request=proof_request,
            presentation=presentation,
            header=header,
            nullifier=_accepted_nullifier(response.headers.get(PROOF_RESPONSE_HEADER)),
        )
        response.extensions[PROOF_RECEIPT_EXTENSION] = receipt
        if self._on_proof is not None:
            self._on_proof(receipt)
        return response

    async def aclose(self) -> None:
        """Close the wrapped transport."""
        await self._transport.aclose()


def _refusal_reason(body: bytes) -> str:
    try:
        parsed = json.loads(body or b"null")
    except ValueError:
        parsed = None
    reason = parsed.get("reason") if isinstance(parsed, dict) else None
    return reason if isinstance(reason, str) and reason else "no reason given"


def _accepted_nullifier(header: str | None) -> str | None:
    if not header:
        return None
    try:
        return decode_proof_response(header)["nullifier"]
    except ProofHeaderError:
        return None
