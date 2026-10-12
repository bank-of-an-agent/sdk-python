# Generated from src/agentbank/_async/client.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""The synchronous Agent Bank client."""

from __future__ import annotations

import time
from collections.abc import Mapping
from types import TracebackType
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel
from typing_extensions import Self

from agentbank import _operations as ops
from agentbank._base_client import (
    DEFAULT_MAX_RETRIES,
    ClientConfig,
    PreparedRequest,
    RequestOptions,
    is_retryable_exception,
    is_retryable_response,
    parse_json,
    parse_model,
    retry_delay,
)
from agentbank._resource_helpers import require_session_for
from agentbank._spec import Operation
from agentbank._sync.resources.accounts import Accounts, ChainName
from agentbank._sync.resources.agents import Agents
from agentbank._sync.resources.api_keys import ApiKeys
from agentbank._sync.resources.approvals import Approvals
from agentbank._sync.resources.billing import Billing
from agentbank._sync.resources.escrows import Escrows
from agentbank._sync.resources.ledger import Ledger
from agentbank._sync.resources.mandates import Mandates
from agentbank._sync.resources.members import Members
from agentbank._sync.resources.orgs import Orgs
from agentbank._sync.resources.owner_operations import OwnerOperations
from agentbank._sync.resources.payments import (
    DEFAULT_POLL_INTERVAL,
    DEFAULT_SETTLEMENT_TIMEOUT,
    PaymentRequests,
    Payments,
)
from agentbank._sync.resources.policies import Policies
from agentbank._sync.resources.proofs import Proofs
from agentbank._sync.resources.sandbox import Sandbox
from agentbank._sync.resources.sessions import Sessions
from agentbank._sync.resources.streams import Streams
from agentbank._sync.resources.treasury import Treasury
from agentbank._sync.resources.vaults import Vaults
from agentbank._sync.resources.webhooks import Webhooks
from agentbank._sync.resources.x402 import X402
from agentbank.chains import assert_testnet
from agentbank.errors import (
    APIConnectionError,
    APITimeoutError,
    BadRequestError,
    ConfigurationError,
    error_from_response,
)
from agentbank.flows import (
    DEFAULT_SESSION_TTL_SECONDS,
    GrantSessionResult,
    PermitOptions,
    SessionGrant,
    SetupAgentAccountResult,
    VaultWithdrawalResult,
    session_scope_with_expiry,
)
from agentbank.http_signatures import DEFAULT_SIGNATURE_LIFETIME_SECONDS
from agentbank.keys import SessionKey, SignerLike, personal_sign_hash, to_signer
from agentbank.models import (
    Account,
    HealthResponse,
    Meta,
    Payment,
    PaymentDestination,
    SessionScope,
    SigningRequest,
)
from agentbank.money import MoneyInput
from agentbank.spend_key import MAX_UINT256, sign_spend_key_permit

__all__ = ["AgentBank"]

ModelT = TypeVar("ModelT", bound=BaseModel)


class AgentBank:
    """Synchronous client for the Agent Bank REST API.

    Principals (humans or companies) authenticate with an org API key; agents
    authenticate every request with an RFC 9421 signature by their session
    key. Configure either or both; each operation uses the credentials it
    accepts. Writes get an ``Idempotency-Key`` automatically, and failed
    attempts are retried with backoff under the same key.

    Example::

        with AgentBank(
            session_id="ses_...",
            session_key=os.environ["AGENTBANK_SESSION_KEY"],
            account_id="acct_...",
        ) as agent:
            payment = agent.pay(to="0x...", amount="12.50", memo="dataset")

    Args:
        api_key: Org API key (``abk_test_...``) for principal operations.
        session_id: Session id (``ses_...``) for agent operations.
        session_key: The session private key (hex), a :class:`SessionKey`, or a signer.
        spend_key: The x402 spend key, used by the x402 client.
        account_id: Default account for agent operations (payments, balances, ...).
        base_url: API base URL (default ``AGENTBANK_BASE_URL`` or ``http://localhost:8080``).
        facilitator_url: x402 facilitator base URL (default: ``base_url``).
        chain_id: EIP-712 chain id for owner authorizations. Default: the
            deployment's ``owner_authorization_chain_id`` from ``GET /v1/meta``
            (fetched once and cached). Mainnet chain ids are refused.
        timeout: Request timeout in seconds or an ``httpx.Timeout`` (default 30 s).
        max_retries: Retries on network errors, 429 and 5xx (default 2).
        signature_lifetime_seconds: Lifetime of request signatures (max 300).
        default_headers: Headers added to every request.
        http_client: Your own ``httpx.Client`` (proxies, mTLS, ...). It must
            not add authentication of its own.
    """

    orgs: Orgs
    api_keys: ApiKeys
    members: Members
    agents: Agents
    accounts: Accounts
    sessions: Sessions
    owner_operations: OwnerOperations
    mandates: Mandates
    policies: Policies
    payments: Payments
    payment_requests: PaymentRequests
    x402: X402
    escrows: Escrows
    streams: Streams
    approvals: Approvals
    ledger: Ledger
    vaults: Vaults
    treasury: Treasury
    webhooks: Webhooks
    billing: Billing
    sandbox: Sandbox
    proofs: Proofs

    def __init__(
        self,
        *,
        api_key: str | None = None,
        session_id: str | None = None,
        session_key: SignerLike | SessionKey | None = None,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        base_url: str | None = None,
        facilitator_url: str | None = None,
        chain_id: int | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        signature_lifetime_seconds: int = DEFAULT_SIGNATURE_LIFETIME_SECONDS,
        default_headers: Mapping[str, str] | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._config = ClientConfig.resolve(
            api_key=api_key,
            session_id=session_id,
            session_key=session_key,
            spend_key=spend_key,
            account_id=account_id,
            base_url=base_url,
            facilitator_url=facilitator_url,
            chain_id=chain_id,
            timeout=timeout,
            max_retries=max_retries,
            signature_lifetime_seconds=signature_lifetime_seconds,
            default_headers=default_headers,
        )
        self._meta: Meta | None = None
        self._owns_http_client = http_client is None
        self._http = http_client or httpx.Client(timeout=self._config.timeout)
        self.orgs = Orgs(self)
        self.api_keys = ApiKeys(self)
        self.members = Members(self)
        self.agents = Agents(self)
        self.accounts = Accounts(self)
        self.sessions = Sessions(self)
        self.owner_operations = OwnerOperations(self)
        self.mandates = Mandates(self)
        self.policies = Policies(self)
        self.payments = Payments(self)
        self.payment_requests = PaymentRequests(self)
        self.x402 = X402(self)
        self.escrows = Escrows(self)
        self.streams = Streams(self)
        self.approvals = Approvals(self)
        self.ledger = Ledger(self)
        self.vaults = Vaults(self)
        self.treasury = Treasury(self)
        self.webhooks = Webhooks(self)
        self.billing = Billing(self)
        self.sandbox = Sandbox(self)
        self.proofs = Proofs(self)

    # ------------------------------------------------------------------ properties

    @property
    def config(self) -> ClientConfig:
        """The resolved client configuration."""
        return self._config

    @property
    def account_id(self) -> str | None:
        """Default account for agent operations."""
        return self._config.account_id

    @property
    def session_id(self) -> str | None:
        """Session id used to sign agent requests."""
        return self._config.session_id

    @property
    def chain_id(self) -> int | None:
        """The configured owner-authorization chain id (``None``: from ``GET /v1/meta``)."""
        return self._config.chain_id

    def __repr__(self) -> str:
        auth = [
            name
            for name, present in (
                ("api_key", self._config.api_key is not None),
                ("session", self._config.session_id is not None),
                ("spend_key", self._config.spend_signer is not None),
            )
            if present
        ]
        return f"{type(self).__name__}(base_url={self._config.base_url!r}, auth={auth})"

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Close the underlying HTTP client (unless it was passed in)."""
        if self._owns_http_client:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ------------------------------------------------------------------ shortcuts

    def pay(
        self,
        *,
        to: PaymentDestination | Mapping[str, Any] | str,
        amount: MoneyInput,
        account_id: str | None = None,
        memo: str | None = None,
        mandate_id: str | None = None,
        payment_request_id: str | None = None,
        metadata: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        wait_for_approval: bool = False,
        wait_for_settlement: bool = False,
        timeout: float = DEFAULT_SETTLEMENT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        request_options: RequestOptions | None = None,
    ) -> Payment:
        """Pay in one call (create, check, sign with the session key, submit).

        Shorthand for ``payments.pay`` so an agent-authenticated client reads
        naturally::

            agent = AgentBank(session_id=..., session_key=..., account_id=...)
            agent.pay(to="0x...", amount="1.00", wait_for_settlement=True)

        See ``payments.pay`` for the arguments and errors.
        """
        return self.payments.pay(
            to=to,
            amount=amount,
            account_id=account_id,
            memo=memo,
            mandate_id=mandate_id,
            payment_request_id=payment_request_id,
            metadata=metadata,
            idempotency_key=idempotency_key,
            wait_for_approval=wait_for_approval,
            wait_for_settlement=wait_for_settlement,
            timeout=timeout,
            poll_interval=poll_interval,
            request_options=request_options,
        )

    def health(self, *, request_options: RequestOptions | None = None) -> HealthResponse:
        """Liveness and dependency checks (public)."""
        return self._request_model(ops.HEALTH, HealthResponse, request_options=request_options)

    def meta(self, *, refresh: bool = False, request_options: RequestOptions | None = None) -> Meta:
        """Deployment facts (public, cached after the first call).

        Chain, USDC deployment, contract addresses, feature flags and the
        EIP-712 chain id for owner authorizations.
        """
        if self._meta is None or refresh:
            self._meta = self._request_model(ops.GET_META, Meta, request_options=request_options)
        return self._meta

    def owner_authorization_chain_id(self) -> int:
        """EIP-712 domain chain id for owner authorizations (testnets only).

        The client's ``chain_id`` if set, else ``owner_authorization_chain_id``
        from ``GET /v1/meta`` (fetched once and cached).

        Raises:
            MainnetLockedError: The chain id is a mainnet.
        """
        chain_id = self._config.chain_id
        if chain_id is None:
            chain_id = (self.meta()).owner_authorization_chain_id
        assert_testnet(chain_id)
        return chain_id

    def call(
        self,
        operation_id: str,
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Any:
        """Call any operation by its OpenAPI ``operationId``; returns the decoded JSON.

        A low-level escape hatch for operations without a typed method. The
        same authentication, idempotency and retry rules apply.
        """
        operation = ops.OPERATIONS.get(operation_id)
        if operation is None:
            raise ValueError(f"Unknown operation {operation_id!r}")
        return self._request_json(
            operation,
            path_params=path_params,
            query=query,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    # ------------------------------------------------------------------ principal flows

    def spend_key_permit(
        self,
        account: Account | str,
        spend_key: SignerLike | SessionKey,
        *,
        nonce: int | str = 0,
        value: int | str = MAX_UINT256,
        deadline: int | str = MAX_UINT256,
        request_options: RequestOptions | None = None,
    ) -> dict[str, str]:
        """Sign the spend key's float-recovery permit for an existing account.

        Spender = ``account.address``; the USDC address and EIP-712 domain come
        from ``GET /v1/meta``. Sends nothing (see :meth:`provision_spend_key`).

        Raises:
            BadRequestError: The account is not on the deployment's chain, or the
                permit parameters are invalid.
        """
        target = (
            account
            if isinstance(account, Account)
            else self.accounts.retrieve(account, request_options=request_options)
        )
        meta = self.meta(request_options=request_options)
        if target.chain_id != meta.chain_id:
            raise BadRequestError(
                "invalid_request",
                f"Account {target.id} is on chain {target.chain_id}, but this deployment's "
                f"USDC is on chain {meta.chain_id}",
            )
        return sign_spend_key_permit(
            spend_key,
            account=target.address,
            chain_id=target.chain_id,
            usdc=meta.usdc.address,
            name=meta.usdc.eip712_name,
            version=meta.usdc.eip712_version,
            nonce=nonce,
            value=value,
            deadline=deadline,
        )

    def provision_spend_key(
        self,
        account_id: str,
        spend_key: SignerLike | SessionKey,
        *,
        owner: SignerLike | SessionKey,
        nonce: int | str = 0,
        value: int | str = MAX_UINT256,
        deadline: int | str = MAX_UINT256,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Account:
        """Attach an agent's x402 spend key to its account (ADR 0001).

        The spend key signs the float-recovery permit for the account's address,
        the owner key signs ``spend_key.set`` (which pins the spend key in the
        co-signer; x402 payments and float refills are refused until then), and
        both go to ``PUT /v1/accounts/{id}/spend-key``. The permit is executed
        on-chain by the account's next owner operation (normally the install of
        the first session), after which ``account.spend_key_permit`` is ``executed``.

        Args:
            account_id: The agent's account.
            spend_key: The spend key (``generate_spend_key()``).
            owner: The owner key (signs ``spend_key.set``).
            nonce: USDC ``nonces(spend key)``; 0 for a fresh key.
            value: Permit allowance (default max uint256).
            deadline: Permit deadline (default max uint256).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        account = self.accounts.retrieve(account_id, request_options=request_options)
        return self._attach_spend_key(
            account,
            spend_key,
            owner=owner,
            permit={"nonce": nonce, "value": value, "deadline": deadline},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def grant_session(
        self,
        *,
        account_id: str,
        public_key: str,
        scope: SessionScope | Mapping[str, Any],
        owner: SignerLike | SessionKey,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        install: bool = True,
        wait_for_install: bool = False,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> GrantSessionResult:
        """Grant an agent a session key and install it on-chain.

        Signs the ``session.grant`` owner authorization over
        ``{account_id, public_key, scope}`` (scope defaults made explicit,
        ``expires_at`` = now + ``ttl_seconds`` when absent), registers the
        session, prepares its on-chain install (Smart Sessions) and signs the
        install operation with the owner key. The scope is enforced on-chain.

        Args:
            account_id: The agent's account.
            public_key: The session key address (``generate_session_key().address``).
            scope: ``max_per_tx``, ``max_per_day`` and optional limits and expiry.
            owner: The owner key.
            ttl_seconds: Lifetime when ``scope`` has no ``expires_at`` (default 24 h, max 7 days).
            install: Prepare and sign the on-chain install (default ``True``).
            wait_for_install: Wait until the install operation is done.
            timeout: Seconds to wait when ``wait_for_install`` is true.
            poll_interval: Seconds between status checks.
            idempotency_key: Optional base key; suffixed per step (``.create``,
                ``.install``, ``.sign``) so the whole flow can be retried safely.
            request_options: Per-request overrides.
        """
        session = self.sessions.create(
            account_id=account_id,
            public_key=public_key,
            scope=session_scope_with_expiry(scope, ttl_seconds),
            owner=owner,
            idempotency_key=_step(idempotency_key, "create"),
            request_options=request_options,
        )
        if not install:
            return GrantSessionResult(session=session, install_operation=None)
        session = self.sessions.install(
            session.id,
            idempotency_key=_step(idempotency_key, "install"),
            request_options=request_options,
        )
        if session.install_operation_id is None:
            return GrantSessionResult(session=session, install_operation=None)
        operation = self.owner_operations.sign_and_submit(
            session.install_operation_id,
            owner=owner,
            wait=wait_for_install,
            timeout=timeout,
            poll_interval=poll_interval,
            idempotency_key=_step(idempotency_key, "sign"),
            request_options=request_options,
        )
        if wait_for_install:
            session = self.sessions.retrieve(session.id, request_options=request_options)
        return GrantSessionResult(session=session, install_operation=operation)

    def setup_agent_account(
        self,
        *,
        agent_id: str,
        owner: SignerLike | SessionKey | None = None,
        chain: ChainName | None = None,
        spend_key: SignerLike | SessionKey | None = None,
        permit: PermitOptions | None = None,
        session: SessionGrant | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> SetupAgentAccountResult:
        """Provision an agent's account in the order the contracts require.

        Creates the smart account; with ``spend_key``, signs the float-recovery
        permit for its counterfactual address, has the owner authorize the
        spend key (``spend_key.set``) and attaches both; with ``session``,
        grants and installs the first session, whose setup owner operation also
        executes the permit on-chain::

            spend_key, session_key = generate_spend_key(), generate_session_key()
            result = bank.setup_agent_account(
                agent_id=agent.id,
                owner=owner_key,
                spend_key=spend_key,
                session={
                    "public_key": session_key.address,
                    "scope": {"max_per_tx": "5.00", "max_per_day": "50.00"},
                },
            )

        Args:
            agent_id: The agent.
            owner: The owner key (needed with ``spend_key`` or ``session``).
            chain: Chain of the account (API default: Base Sepolia).
            spend_key: The agent's x402 spend key, attached before the first session.
            permit: Permit overrides (``nonce`` for a key that is not fresh).
            session: The first session to grant (see :class:`~agentbank.flows.SessionGrant`).
            idempotency_key: Optional base key; suffixed per step (``.account``,
                ``.spend-key``, ``.session.*``) so the setup can be retried safely.
            request_options: Per-request overrides.

        Raises:
            ConfigurationError: ``spend_key`` or ``session`` without an owner key.
        """
        session_owner = session.get("owner", owner) if session is not None else owner
        if (spend_key is not None and owner is None) or (
            session is not None and session_owner is None
        ):
            raise ConfigurationError("setup_agent_account needs the owner key (owner=...)")
        account = self.accounts.create(
            agent_id,
            chain=chain,
            idempotency_key=_step(idempotency_key, "account"),
            request_options=request_options,
        )
        if spend_key is not None:
            assert owner is not None
            account = self._attach_spend_key(
                account,
                spend_key,
                owner=owner,
                permit=permit or {},
                idempotency_key=_step(idempotency_key, "spend-key"),
                request_options=request_options,
            )
        if session is None:
            return SetupAgentAccountResult(account=account, session=None, install_operation=None)
        assert session_owner is not None
        granted = self.grant_session(
            account_id=account.id,
            public_key=session["public_key"],
            scope=session["scope"],
            owner=session_owner,
            ttl_seconds=session.get("ttl_seconds", DEFAULT_SESSION_TTL_SECONDS),
            install=session.get("install", True),
            wait_for_install=session.get("wait_for_install", False),
            idempotency_key=_step(idempotency_key, "session"),
            request_options=request_options,
        )
        if spend_key is not None and session.get("wait_for_install", False):
            account = self.accounts.retrieve(account.id, request_options=request_options)
        return SetupAgentAccountResult(
            account=account,
            session=granted.session,
            install_operation=granted.install_operation,
        )

    def withdraw_vault(
        self,
        vault_id: str,
        amount: MoneyInput,
        *,
        owner: SignerLike | SessionKey,
        wait: bool = False,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> VaultWithdrawalResult:
        """Withdraw from a vault, signing whatever the owner must (principal only).

        Goal vaults, and locked vaults past ``unlock_at``, withdraw at once.
        Before a locked vault's ``unlock_at``, the ``TimeLockVaults`` contract
        needs the owner's EIP-712 ``EarlyWithdrawal`` signature: this checks the
        API's challenge against the vault, the deployment (``GET /v1/meta``)
        and ``amount``, signs it, resends the withdrawal, then signs the owner
        operation that carries it on-chain::

            result = bank.withdraw_vault(vault.id, "15.00", owner=owner_key, wait=True)
            print(result.operation.status if result.operation else "withdrawn")

        Args:
            vault_id: The vault.
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            owner: The org owner key (the owner of every vault).
            wait: Wait until the early withdrawal's owner operation is done,
                then read the vault again.
            timeout: Seconds to wait when ``wait`` is true.
            poll_interval: Seconds between status checks.
            idempotency_key: Optional base key, suffixed per request
                (``.withdraw``, ``.withdraw.signed``, ``.sign``) so the
                withdrawal can be retried safely with the same key.
            request_options: Per-request overrides.

        Raises:
            BadRequestError: The challenge, or the owner operation the API
                prepared, is not the requested withdrawal (it is not signed).
            AgentBankError: ``operation_timeout`` when ``wait`` and the
                operation is still pending after ``timeout``.
        """
        vault, early = self.vaults._withdraw_as_owner(
            vault_id,
            amount,
            owner,
            idempotency_key=_step(idempotency_key, "withdraw"),
            request_options=request_options,
        )
        if not early or vault.pending_operation_id is None:
            return VaultWithdrawalResult(vault=vault, operation=None)
        operation = self.owner_operations.retrieve(
            vault.pending_operation_id, request_options=request_options
        )
        if operation.purpose != "vault.withdraw" or operation.subject_id != vault.id:
            raise BadRequestError(
                "invalid_request",
                f"Refusing to sign owner operation {operation.id}: it is a {operation.purpose} "
                f"for {operation.subject_id}, not the withdrawal from vault {vault.id}",
            )
        operation = self.owner_operations.sign_and_submit(
            operation,
            owner=owner,
            wait=wait,
            timeout=timeout,
            poll_interval=poll_interval,
            idempotency_key=_step(idempotency_key, "sign"),
            request_options=request_options,
        )
        if wait:
            vault = self.vaults.retrieve(vault_id, request_options=request_options)
        return VaultWithdrawalResult(vault=vault, operation=operation)

    def _attach_spend_key(
        self,
        account: Account,
        spend_key: SignerLike | SessionKey,
        *,
        owner: SignerLike | SessionKey,
        permit: PermitOptions,
        idempotency_key: str | None,
        request_options: RequestOptions | None,
    ) -> Account:
        if account.role != "agent":
            raise BadRequestError(
                "invalid_request", "Spend keys are for agent accounts, not the treasury"
            )
        signed = self.spend_key_permit(
            account,
            spend_key,
            nonce=permit.get("nonce", 0),
            value=permit.get("value", MAX_UINT256),
            deadline=permit.get("deadline", MAX_UINT256),
            request_options=request_options,
        )
        return self.accounts.attach_spend_key(
            account.id,
            spend_key_address=to_signer(spend_key).address,
            permit=signed,
            owner=owner,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    # ------------------------------------------------------------------ internals

    def _sign_operation(self, signing_request: SigningRequest) -> tuple[str, str]:
        """Sign a user operation hash with the session key: ``(session_id, signature)``."""
        session_id = require_session_for(signing_request, self._config.session_id)
        assert_testnet(signing_request.chain_id)
        assert self._config.session_signer is not None
        return session_id, personal_sign_hash(
            self._config.session_signer, signing_request.user_op_hash
        )

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def _monotonic(self) -> float:
        return time.monotonic()

    def _send(self, prepared: PreparedRequest) -> httpx.Response:
        attempt = 0
        while True:
            request = self._http.build_request(
                prepared.method,
                prepared.url,
                headers=prepared.headers,
                content=prepared.content,
                timeout=prepared.timeout,
            )
            request.headers.update(self._config.auth_headers(prepared, str(request.url)))
            try:
                response = self._http.send(request)
            except httpx.TransportError as exc:
                delay = retry_delay(attempt)
                if (
                    attempt < prepared.max_retries
                    and delay is not None
                    and is_retryable_exception(prepared, exc)
                ):
                    self._sleep(delay)
                    attempt += 1
                    continue
                if isinstance(exc, httpx.TimeoutException):
                    raise APITimeoutError(f"{prepared.operation.operation_id}: {exc}") from exc
                raise APIConnectionError(f"{prepared.operation.operation_id}: {exc}") from exc
            if response.is_success:
                return response
            delay = retry_delay(attempt, response)
            if (
                attempt < prepared.max_retries
                and delay is not None
                and is_retryable_response(prepared, response)
            ):
                self._sleep(delay)
                attempt += 1
                continue
            raise error_from_response(response)

    def _request_json(
        self,
        operation: Operation,
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Any:
        prepared = self._config.prepare(
            operation,
            path_params=path_params,
            query=query,
            body=body,
            idempotency_key=idempotency_key,
            options=request_options,
        )
        return parse_json(self._send(prepared))

    def _request_model(
        self,
        operation: Operation,
        cast_to: type[ModelT],
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ModelT:
        prepared = self._config.prepare(
            operation,
            path_params=path_params,
            query=query,
            body=body,
            idempotency_key=idempotency_key,
            options=request_options,
        )
        return parse_model(self._send(prepared), cast_to)

    def _request_text(
        self,
        operation: Operation,
        *,
        query: Mapping[str, Any] | None = None,
        accept: str = "text/plain",
        request_options: RequestOptions | None = None,
    ) -> str:
        prepared = self._config.prepare(
            operation, query=query, accept=accept, options=request_options
        )
        return (self._send(prepared)).text


def _step(idempotency_key: str | None, step: str) -> str | None:
    """Suffix a caller-supplied idempotency key per step of a multi-call helper."""
    return f"{idempotency_key}.{step}" if idempotency_key else None
