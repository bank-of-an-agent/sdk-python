# Generated from src/agentbank/_async/resources/proofs.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Private proofs: ``/v1/proofs/*``, proof settings, identities, witnesses and reservations."""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, Literal

import httpx

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.proofs import ProofTransport
from agentbank._sync.resources._base import APIResource
from agentbank.chains import DEFAULT_CHAIN_ID, assert_testnet
from agentbank.errors import (
    AgentBankError,
    ConfigurationError,
    NotFoundError,
    ProofRefusedError,
    ProverError,
)
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import (
    ListProofReservationsResponse,
    ListProofRootsResponse,
    ProofCircuit,
    ProofIdentity,
    ProofPresentation,
    ProofRequest,
    ProofReservation,
    ProofRoot,
    ProofSettings,
    ProofWitness,
    VerifyProofResponse,
)
from agentbank.money import MoneyInput, coerce_money, format_amount
from agentbank.proofs import (
    DEFAULT_MAX_ROOT_AGE_SECONDS,
    DEFAULT_MIN_ANONYMITY_SET,
    DEFAULT_TTL_SECONDS,
    DISCLOSURE_CLASSES,
    MAX_U64,
    PROOF_SECRET_ENV,
    ProofGate,
    ProofReceipt,
    Prover,
    ReplayCache,
    Requirement,
    RootInfo,
    RootQuery,
    RootResolver,
    assert_provable,
    bounds,
    from_bytes32,
    needs_reservation,
    parse_proof_request,
    presentation_data,
    proof_secret_from_env,
    request_data,
    request_hash,
    root_info_from_api,
    scope_field,
    select_reservation,
)

__all__ = ["Proofs"]

ReservationStatus = Literal["pending", "active", "released", "expired"]
RootStatus = Literal["publishing", "published", "revoked", "expired", "failed"]
ProverLike = Prover | str | Sequence[str] | None


def _prover(prover: ProverLike) -> Prover:
    return prover if isinstance(prover, Prover) else Prover(prover)


def _secret(secret: str | None) -> str:
    resolved = secret if secret is not None else proof_secret_from_env()
    if not resolved:
        raise ProverError(
            "secret_missing",
            f"No proof secret: pass secret=... or set {PROOF_SECRET_ENV} "
            "(generate one with agentbank.proofs.generate_proof_secret())",
        )
    return resolved


def _same_registry(expected: str | None, actual: str | None) -> bool:
    return expected is None or (actual is not None and actual.lower() == expected.lower())


class Proofs(APIResource):
    """Private proofs: prove facts about an agent without revealing which agent it is.

    Verifiers use :meth:`root_resolver` and :meth:`gate` (public endpoints, no
    credentials); principals configure what each agent may disclose
    (:meth:`update_settings`); agents enroll, reserve funds for a verifier and
    :meth:`prove`. See :mod:`agentbank.proofs` for the protocol.
    """

    # ------------------------------------------------------------------ public

    def circuit(self, *, request_options: RequestOptions | None = None) -> ProofCircuit:
        """The claims circuit: attributes, disclosure classes, verification key, registry."""
        return self._request(ops.GET_PROOF_CIRCUIT, ProofCircuit, request_options=request_options)

    def roots(
        self,
        *,
        status: RootStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListProofRootsResponse:
        """List attested-facts roots (one page), newest first."""
        return self._request(
            ops.LIST_PROOF_ROOTS,
            ListProofRootsResponse,
            query={"status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def roots_all(
        self,
        *,
        status: RootStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[ProofRoot]:
        """Iterate over every root, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_PROOF_ROOTS,
            ListProofRootsResponse,
            query={"status": status, "limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def root(self, root: str, *, request_options: RequestOptions | None = None) -> ProofRoot:
        """Get a root (verifiers without chain access check presented roots here)."""
        return self._request(
            ops.GET_PROOF_ROOT,
            ProofRoot,
            path_params={"root": root},
            request_options=request_options,
        )

    def verify(
        self,
        request: ProofRequest | Mapping[str, Any],
        presentation: ProofPresentation | Mapping[str, Any],
        *,
        request_options: RequestOptions | None = None,
    ) -> VerifyProofResponse:
        """Ask Agent Bank to check a presentation (expiry, request hash, root, proof).

        A convenience for verifiers that cannot verify locally; nonce freshness
        stays the verifier's concern. :func:`agentbank.proofs.verify_presentation`
        verifies locally, without trusting Agent Bank for the proof check.
        """
        body = {"request": request_data(request), "presentation": presentation_data(presentation)}
        return self._request(
            ops.VERIFY_PROOF, VerifyProofResponse, body=body, request_options=request_options
        )

    def root_resolver(self) -> RootResolver:
        """A root resolver backed by ``GET /v1/proofs/roots/{root}`` (for gates).

        A root Agent Bank does not know, or one published on another chain or
        registry than the request names, resolves to ``None`` (``unknown_root``).
        Other API errors propagate, so gates fail closed.
        """

        def resolve(query: RootQuery) -> RootInfo | None:
            return self._resolve_root(query)

        return resolve

    def _resolve_root(self, query: RootQuery) -> RootInfo | None:
        try:
            found = self.root(query.root)
        except NotFoundError:
            return None
        if found.root.lower() != query.root.lower():
            raise AgentBankError("invalid_response", "The root lookup returned another root")
        if found.chain_id != query.chain_id or not _same_registry(query.registry, found.registry):
            return None
        return root_info_from_api(found)

    def gate(
        self,
        *,
        scope: str,
        key: str | bytes,
        require: Iterable[Requirement] = (),
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        replay_cache: ReplayCache | None = None,
        min_anonymity_set: int = DEFAULT_MIN_ANONYMITY_SET,
        max_root_age_seconds: int = DEFAULT_MAX_ROOT_AGE_SECONDS,
        chain_id: int = DEFAULT_CHAIN_ID,
        registry: str | None = None,
        now: Callable[[], int] | None = None,
    ) -> ProofGate:
        """A stateless proof gate whose roots are checked through this client.

        See :class:`agentbank.proofs.ProofGate` for the arguments.
        """
        return ProofGate(
            scope=scope,
            key=key,
            require=require,
            root_resolver=self.root_resolver(),
            ttl_seconds=ttl_seconds,
            replay_cache=replay_cache,
            min_anonymity_set=min_anonymity_set,
            max_root_age_seconds=max_root_age_seconds,
            chain_id=chain_id,
            registry=registry,
            now=now,
        )

    # ------------------------------------------------------------------ principals

    def settings(
        self, agent_id: str, *, request_options: RequestOptions | None = None
    ) -> ProofSettings:
        """What the agent may prove privately (principal)."""
        return self._request(
            ops.GET_PROOF_SETTINGS,
            ProofSettings,
            path_params={"id": agent_id},
            request_options=request_options,
        )

    def update_settings(
        self,
        agent_id: str,
        *,
        enabled: bool,
        disclose: Iterable[str],
        owner: SignerLike | SessionKey | None = None,
        owner_authorization: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ProofSettings:
        """Set whether the agent appears in the attested tree and what it may disclose.

        Widening (enabling proofs or adding a class) needs an owner authorization
        (``proofs.disclose`` over ``{agent_id, enabled, disclose}``, classes sorted)
        and applies from the next root. Narrowing needs only the API key and applies
        at once: a new root is published and older roots are revoked.

        Args:
            agent_id: The agent.
            enabled: Whether the agent appears in the tree at all.
            disclose: Classes a proof may constrain: ``principal``, ``limits``,
                ``balance``, ``reservations``, ``account_age``, ``reputation``.
            owner: The owner key; the SDK reads the current settings and signs
                ``proofs.disclose`` only when the change widens disclosure.
            owner_authorization: Alternatively, a pre-signed ``proofs.disclose``
                authorization (see :func:`agentbank.owner_payloads.proofs_disclose`).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Raises:
            ValueError: An unknown disclosure class.
            OwnerSignatureRequiredError: A widening change without an owner signature.
        """
        classes = sorted(set(disclose))
        unknown = [c for c in classes if c not in DISCLOSURE_CLASSES]
        if unknown:
            raise ValueError(f"Unknown disclosure classes: {', '.join(unknown)}")
        body: dict[str, Any] = {"enabled": enabled, "disclose": classes}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            current = self.settings(agent_id, request_options=request_options)
            widens = (enabled and not current.enabled) or bool(set(classes) - set(current.disclose))
            if widens:
                body["owner_authorization"] = self._owner_authorization(
                    owner,
                    owner_payloads.proofs_disclose(agent_id, enabled=enabled, disclose=classes),
                )
        return self._request(
            ops.UPDATE_PROOF_SETTINGS,
            ProofSettings,
            path_params={"id": agent_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def release_reservation(
        self,
        reservation_id: str,
        *,
        owner: SignerLike | SessionKey | None = None,
        owner_authorization: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ProofReservation:
        """Release a reservation before it expires (principal, owner signature).

        Voids the hold and revokes every root containing the reservation. The
        agent itself can never release one.

        Args:
            reservation_id: The reservation (``prv_...``).
            owner: The owner key; the SDK signs ``proofs.reservation.release``.
            owner_authorization: Alternatively, a pre-signed authorization over
                ``{reservation_id}``.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Raises:
            ConfigurationError: Neither ``owner`` nor ``owner_authorization``.
        """
        if owner_authorization is None:
            if owner is None:
                raise ConfigurationError(
                    "release_reservation needs the owner key (owner=...) or owner_authorization"
                )
            owner_authorization = self._owner_authorization(
                owner, owner_payloads.proof_reservation_release(reservation_id)
            )
        return self._request(
            ops.RELEASE_PROOF_RESERVATION,
            ProofReservation,
            path_params={"id": reservation_id},
            body={"owner_authorization": owner_authorization},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    # ------------------------------------------------------------------ agents

    def identity(
        self, account_id: str | None = None, *, request_options: RequestOptions | None = None
    ) -> ProofIdentity:
        """The account's enrolled identity commitment."""
        return self._request(
            ops.GET_PROOF_IDENTITY,
            ProofIdentity,
            path_params={"id": self._account(account_id)},
            request_options=request_options,
        )

    def enroll(
        self,
        identity_commitment: str | None = None,
        *,
        secret: str | None = None,
        account_id: str | None = None,
        prover: ProverLike = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ProofIdentity:
        """Enroll the agent's identity commitment ``Poseidon(secret)`` (agent).

        Agent Bank only ever sees the commitment. Without ``identity_commitment``
        it is computed from ``secret`` (default ``AGENTBANK_PROOF_SECRET``) by the
        prover's ``identity`` mode. Generate a secret once with
        :func:`agentbank.proofs.generate_proof_secret` and keep it.

        Raises:
            ProverError: No secret or no prover to compute the commitment.
            ValueError: ``identity_commitment`` is not 32-byte hex.
        """
        if identity_commitment is None:
            keys = _prover(prover).identity(_secret(secret))
            identity_commitment = keys.identity_commitment
        from_bytes32(identity_commitment)
        return self._request(
            ops.ENROLL_PROOF_IDENTITY,
            ProofIdentity,
            path_params={"id": self._account(account_id)},
            body={"identity_commitment": identity_commitment},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def witness(
        self,
        account_id: str | None = None,
        *,
        reservation_id: str | None = None,
        root: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ProofWitness:
        """The agent's leaf values and Merkle path for proving (agent).

        Args:
            account_id: The account (defaults to the client's).
            reservation_id: The reservation leaf to prove from (default: the base leaf).
            root: A still-valid root (default: the latest).
            request_options: Per-request overrides.
        """
        return self._request(
            ops.GET_PROOF_WITNESS,
            ProofWitness,
            path_params={"id": self._account(account_id)},
            query={"reservation_id": reservation_id, "root": root},
            request_options=request_options,
        )

    def reserve(
        self,
        amount: MoneyInput,
        *,
        expires_at: datetime | int,
        scope: str | None = None,
        scope_tag: int | str | None = None,
        account_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ProofReservation:
        """Hold funds for one verifier so the agent can prove "$X is reserved for you" (agent).

        The amount moves ``operating -> reserved`` until ``expires_at`` (at most 7
        days ahead); from the next root the agent can prove it to that verifier
        only. The agent cannot cancel it; the owner can release it early.

        Args:
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            expires_at: Aware datetime or unix seconds.
            scope: The verifier's scope (normally its host name), or
            scope_tag: just its 64-bit tag (``scope_field(scope) mod 2^64``).
            account_id: The account (defaults to the client's).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Raises:
            ValueError: Not exactly one of ``scope`` and ``scope_tag``, or a bad value.
        """
        if (scope is None) == (scope_tag is None):
            raise ValueError("reserve needs exactly one of scope, scope_tag")
        if scope is not None:
            scope_field(scope)
        tag = None if scope_tag is None else str(scope_tag)
        if tag is not None and (not tag.isdigit() or not 0 < int(tag) <= MAX_U64):
            raise ValueError("scope_tag must be an integer in [1, 2^64 - 1]")
        if isinstance(expires_at, datetime):
            until = expires_at
        else:
            until = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        body = compact(
            amount=coerce_money(amount),
            scope=scope,
            scope_tag=None if tag is None else str(int(tag)),
            expires_at=until,
        )
        return self._request(
            ops.CREATE_PROOF_RESERVATION,
            ProofReservation,
            path_params={"id": self._account(account_id)},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def reservations(
        self,
        account_id: str | None = None,
        *,
        status: ReservationStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListProofReservationsResponse:
        """List the account's proof-of-funds reservations (one page)."""
        return self._request(
            ops.LIST_PROOF_RESERVATIONS,
            ListProofReservationsResponse,
            path_params={"id": self._account(account_id)},
            query={"status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def reservations_all(
        self,
        account_id: str | None = None,
        *,
        status: ReservationStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[ProofReservation]:
        """Iterate over every reservation of the account, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_PROOF_RESERVATIONS,
            ListProofReservationsResponse,
            path_params={"id": self._account(account_id)},
            query={"status": status, "limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def reservation(
        self, reservation_id: str, *, request_options: RequestOptions | None = None
    ) -> ProofReservation:
        """Get a proof-of-funds reservation."""
        return self._request(
            ops.GET_PROOF_RESERVATION,
            ProofReservation,
            path_params={"id": reservation_id},
            request_options=request_options,
        )

    def prove(
        self,
        request: ProofRequest | Mapping[str, Any],
        *,
        secret: str | None = None,
        reservation_id: str | None = None,
        root: str | None = None,
        account_id: str | None = None,
        prover: ProverLike = None,
        request_options: RequestOptions | None = None,
    ) -> ProofPresentation:
        """Prove a verifier's request (agent): fetch the witness, then run the prover.

        When the request asks for reserved funds and no ``reservation_id`` is
        given, the active reservation that satisfies it is picked (latest
        expiry, then lowest id). The witness is checked against the request
        before proving, so an unprovable request is refused in milliseconds.

        Args:
            request: The verifier's request (from ``AGENT-PROOF-REQUIRED``).
            secret: The proof secret (default ``AGENTBANK_PROOF_SECRET``).
            reservation_id: Prove from this reservation's leaf.
            root: Prove against this still-valid root (default: the latest).
            account_id: The account (defaults to the client's).
            prover: An :class:`~agentbank.proofs.Prover` or a command line
                (default ``AGENTBANK_PROVER``).
            request_options: Per-request overrides for the API calls.

        Returns:
            The presentation to send as ``AGENT-PROOF`` (with
            :func:`agentbank.proofs.encode_proof`).

        Raises:
            ProofRequestError: The request is malformed.
            ProofRefusedError: The attested facts cannot prove it (``unsatisfiable``,
                ``undisclosed``, ``chain_mismatch``, ``reservation_required``,
                ``witness_mismatch``).
            ProverError: No secret, no prover, or the prover failed.
            MainnetLockedError: The request is for a mainnet.
        """
        parsed = parse_proof_request(request)
        assert_testnet(parsed.chain_id)
        resolved_secret = _secret(secret)
        runner = _prover(prover)
        if not runner.configured:
            raise ProverError(
                "prover_not_configured",
                "No prover is configured: set AGENTBANK_PROVER to the agentbank-prove command",
            )
        account = self._account(account_id)
        if reservation_id is None and needs_reservation(parsed):
            reservation_id = self._matching_reservation(account, parsed, request_options)
        witness = self.witness(
            account, reservation_id=reservation_id, root=root, request_options=request_options
        )
        assert_provable(witness, parsed)
        presentation = runner.prove(secret=resolved_secret, witness=witness, request=parsed)
        if presentation.request_hash.lower() != request_hash(parsed):
            raise ProverError("prover_failed", "The prover answered another request")
        return presentation

    def _matching_reservation(
        self, account_id: str, request: ProofRequest, request_options: RequestOptions | None
    ) -> str:
        active: list[ProofReservation] = []
        for item in self.reservations_all(
            account_id, status="active", request_options=request_options
        ):
            active.append(item)
        chosen = select_reservation(request, active)
        if chosen is None:
            b = bounds(request)
            pending: list[ProofReservation] = []
            for item in self.reservations_all(
                account_id, status="pending", request_options=request_options
            ):
                pending.append(item)
            if select_reservation(request, pending, status="pending") is not None:
                raise ProofRefusedError(
                    "reservation_pending",
                    "A matching reservation exists but is not in a published root yet: "
                    "prove after the next root",
                    attributes=("reserved_amount", "reserved_until", "reserved_for"),
                )
            raise ProofRefusedError(
                "reservation_required",
                f"No active reservation covers this request ({format_amount(b.mins[4])} USDC "
                f"or more for scope tag {b.mins[6]}, until at least {b.mins[5]}): reserve "
                "funds with proofs.reserve(...) and prove after the next root",
                attributes=("reserved_amount", "reserved_until", "reserved_for"),
            )
        return chosen.id

    # ------------------------------------------------------------------ HTTP

    def transport(
        self,
        *,
        secret: str | None = None,
        prover: ProverLike = None,
        reservation_id: str | None = None,
        allowed_scopes: Collection[str] | None = None,
        on_proof: Callable[[ProofReceipt], None] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> ProofTransport:
        """An ``httpx`` transport that answers ``AGENT-PROOF-REQUIRED`` challenges.

        See :class:`agentbank.ProofTransport` for the arguments. To answer
        proof and payment challenges together, use ``x402.client(proofs=True)``.
        """
        return ProofTransport(
            self._client,
            secret=secret,
            prover=prover,
            reservation_id=reservation_id,
            allowed_scopes=allowed_scopes,
            on_proof=on_proof,
            transport=transport,
        )

    def client(
        self,
        *,
        secret: str | None = None,
        prover: ProverLike = None,
        reservation_id: str | None = None,
        allowed_scopes: Collection[str] | None = None,
        on_proof: Callable[[ProofReceipt], None] | None = None,
        transport: httpx.BaseTransport | None = None,
        **httpx_options: Any,
    ) -> httpx.Client:
        """An ``httpx.Client`` that answers proof challenges (no payments).

        Extra keyword arguments (``timeout``, ``headers``, ...) go to ``httpx.Client``.
        """
        proof_transport = self.transport(
            secret=secret,
            prover=prover,
            reservation_id=reservation_id,
            allowed_scopes=allowed_scopes,
            on_proof=on_proof,
            transport=transport,
        )
        return httpx.Client(transport=proof_transport, **httpx_options)
