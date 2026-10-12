"""The asynchronous Agent Bank client."""

from __future__ import annotations

import time
from collections.abc import Mapping
from types import TracebackType
from typing import Any, TypeVar

import anyio
import httpx
from pydantic import BaseModel
from typing_extensions import Self

from agentbank import _operations as ops
from agentbank._async.resources.accounts import AsyncAccounts, ChainName
from agentbank._async.resources.agents import AsyncAgents
from agentbank._async.resources.api_keys import AsyncApiKeys
from agentbank._async.resources.approvals import AsyncApprovals
from agentbank._async.resources.billing import AsyncBilling
from agentbank._async.resources.escrows import AsyncEscrows
from agentbank._async.resources.ledger import AsyncLedger
from agentbank._async.resources.mandates import AsyncMandates
from agentbank._async.resources.members import AsyncMembers
from agentbank._async.resources.orgs import AsyncOrgs
from agentbank._async.resources.owner_operations import AsyncOwnerOperations
from agentbank._async.resources.payments import (
    DEFAULT_POLL_INTERVAL,
    DEFAULT_SETTLEMENT_TIMEOUT,
    AsyncPaymentRequests,
    AsyncPayments,
)
from agentbank._async.resources.policies import AsyncPolicies
from agentbank._async.resources.proofs import AsyncProofs
from agentbank._async.resources.sandbox import AsyncSandbox
from agentbank._async.resources.sessions import AsyncSessions
from agentbank._async.resources.streams import AsyncStreams
from agentbank._async.resources.treasury import AsyncTreasury
from agentbank._async.resources.vaults import AsyncVaults
from agentbank._async.resources.webhooks import AsyncWebhooks
from agentbank._async.resources.x402 import AsyncX402
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
from agentbank.proofs import DEFAULT_MAX_PRESENTATIONS_PER_SCOPE_PER_HOUR
from agentbank.spend_key import MAX_UINT256, sign_spend_key_permit

__all__ = ["AsyncAgentBank"]

ModelT = TypeVar("ModelT", bound=BaseModel)


class AsyncAgentBank:
    """Asynchronous client for the Agent Bank REST API.

    Principals (humans or companies) authenticate with an org API key; agents
    authenticate every request with an RFC 9421 signature by their session
    key. Configure either or both; each operation uses the credentials it
    accepts. Writes get an ``Idempotency-Key`` automatically, and failed
    attempts are retried with backoff under the same key.

    Example::

        async with AsyncAgentBank(
            session_id="ses_...",
            session_key=os.environ["AGENTBANK_SESSION_KEY"],
            account_id="acct_...",
        ) as agent:
            payment = await agent.pay(to="0x...", amount="12.50", memo="dataset")

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
        http_client: Your own ``httpx.AsyncClient`` (proxies, mTLS, ...). It must
            not add authentication of its own.
        max_presentations_per_scope_per_hour: Private proofs' probing guard: at most
            this many proofs to one verifier scope in any hour (default 30; ``0``
            refuses every proof, ``math.inf`` disables the guard). A verifier asking
            many questions with different thresholds could otherwise narrow down the
            attested values.
    """

    orgs: AsyncOrgs
    api_keys: AsyncApiKeys
    members: AsyncMembers
    agents: AsyncAgents
    accounts: AsyncAccounts
    sessions: AsyncSessions
    owner_operations: AsyncOwnerOperations
    mandates: AsyncMandates
    policies: AsyncPolicies
    payments: AsyncPayments
    payment_requests: AsyncPaymentRequests
    x402: AsyncX402
    escrows: AsyncEscrows
    streams: AsyncStreams
    approvals: AsyncApprovals
    ledger: AsyncLedger
    vaults: AsyncVaults
    treasury: AsyncTreasury
    webhooks: AsyncWebhooks
    billing: AsyncBilling
    sandbox: AsyncSandbox
    proofs: AsyncProofs

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
        http_client: httpx.AsyncClient | None = None,
        max_presentations_per_scope_per_hour: float = DEFAULT_MAX_PRESENTATIONS_PER_SCOPE_PER_HOUR,
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
            max_presentations_per_scope_per_hour=max_presentations_per_scope_per_hour,
        )
        self._meta: Meta | None = None
        self._owns_http_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=self._config.timeout)
        self.orgs = AsyncOrgs(self)
        self.api_keys = AsyncApiKeys(self)
        self.members = AsyncMembers(self)
        self.agents = AsyncAgents(self)
        self.accounts = AsyncAccounts(self)
        self.sessions = AsyncSessions(self)
        self.owner_operations = AsyncOwnerOperations(self)
        self.mandates = AsyncMandates(self)
        self.policies = AsyncPolicies(self)
        self.payments = AsyncPayments(self)
        self.payment_requests = AsyncPaymentRequests(self)
        self.x402 = AsyncX402(self)
        self.escrows = AsyncEscrows(self)
        self.streams = AsyncStreams(self)
        self.approvals = AsyncApprovals(self)
        self.ledger = AsyncLedger(self)
        self.vaults = AsyncVaults(self)
        self.treasury = AsyncTreasury(self)
        self.webhooks = AsyncWebhooks(self)
        self.billing = AsyncBilling(self)
        self.sandbox = AsyncSandbox(self)
        self.proofs = AsyncProofs(self)

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

    async def close(self) -> None:
        """Close the underlying HTTP client (unless it was passed in)."""
        if self._owns_http_client:
            await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    # ------------------------------------------------------------------ shortcuts

    async def pay(
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

            agent = AsyncAgentBank(session_id=..., session_key=..., account_id=...)
            await agent.pay(to="0x...", amount="1.00", wait_for_settlement=True)

        See ``payments.pay`` for the arguments and errors.
        """
        return await self.payments.pay(
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

    async def health(self, *, request_options: RequestOptions | None = None) -> HealthResponse:
        """Liveness and dependency checks (public)."""
        return await self._request_model(
            ops.HEALTH, HealthResponse, request_options=request_options
        )

    async def meta(
        self, *, refresh: bool = False, request_options: RequestOptions | None = None
    ) -> Meta:
        """Deployment facts (public, cached after the first call).

        Chain, USDC deployment, contract addresses, feature flags and the
        EIP-712 chain id for owner authorizations.
        """
        if self._meta is None or refresh:
            self._meta = await self._request_model(
                ops.GET_META, Meta, request_options=request_options
            )
        return self._meta

    async def owner_authorization_chain_id(self) -> int:
        """EIP-712 domain chain id for owner authorizations (testnets only).

        The client's ``chain_id`` if set, else ``owner_authorization_chain_id``
        from ``GET /v1/meta`` (fetched once and cached).

        Raises:
            MainnetLockedError: The chain id is a mainnet.
        """
        chain_id = self._config.chain_id
        if chain_id is None:
            chain_id = (await self.meta()).owner_authorization_chain_id
        assert_testnet(chain_id)
        return chain_id

    async def call(
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
        return await self._request_json(
            operation,
            path_params=path_params,
            query=query,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    # ------------------------------------------------------------------ principal flows

    async def spend_key_permit(
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
            else await self.accounts.retrieve(account, request_options=request_options)
        )
        meta = await self.meta(request_options=request_options)
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

    async def provision_spend_key(
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
        account = await self.accounts.retrieve(account_id, request_options=request_options)
        return await self._attach_spend_key(
            account,
            spend_key,
            owner=owner,
            permit={"nonce": nonce, "value": value, "deadline": deadline},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def grant_session(
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
        session = await self.sessions.create(
            account_id=account_id,
            public_key=public_key,
            scope=session_scope_with_expiry(scope, ttl_seconds),
            owner=owner,
            idempotency_key=_step(idempotency_key, "create"),
            request_options=request_options,
        )
        if not install:
            return GrantSessionResult(session=session, install_operation=None)
        session = await self.sessions.install(
            session.id,
            idempotency_key=_step(idempotency_key, "install"),
            request_options=request_options,
        )
        if session.install_operation_id is None:
            return GrantSessionResult(session=session, install_operation=None)
        operation = await self.owner_operations.sign_and_submit(
            session.install_operation_id,
            owner=owner,
            wait=wait_for_install,
            timeout=timeout,
            poll_interval=poll_interval,
            idempotency_key=_step(idempotency_key, "sign"),
            request_options=request_options,
        )
        if wait_for_install:
            session = await self.sessions.retrieve(session.id, request_options=request_options)
        return GrantSessionResult(session=session, install_operation=operation)

    async def setup_agent_account(
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
        account = await self.accounts.create(
            agent_id,
            chain=chain,
            idempotency_key=_step(idempotency_key, "account"),
            request_options=request_options,
        )
        if spend_key is not None:
            assert owner is not None
            account = await self._attach_spend_key(
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
        granted = await self.grant_session(
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
            account = await self.accounts.retrieve(account.id, request_options=request_options)
        return SetupAgentAccountResult(
            account=account,
            session=granted.session,
            install_operation=granted.install_operation,
        )

    async def withdraw_vault(
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
        vault, early = await self.vaults._withdraw_as_owner(
            vault_id,
            amount,
            owner,
            idempotency_key=_step(idempotency_key, "withdraw"),
            request_options=request_options,
        )
        if not early or vault.pending_operation_id is None:
            return VaultWithdrawalResult(vault=vault, operation=None)
        operation = await self.owner_operations.retrieve(
            vault.pending_operation_id, request_options=request_options
        )
        if operation.purpose != "vault.withdraw" or operation.subject_id != vault.id:
            raise BadRequestError(
                "invalid_request",
                f"Refusing to sign owner operation {operation.id}: it is a {operation.purpose} "
                f"for {operation.subject_id}, not the withdrawal from vault {vault.id}",
            )
        operation = await self.owner_operations.sign_and_submit(
            operation,
            owner=owner,
            wait=wait,
            timeout=timeout,
            poll_interval=poll_interval,
            idempotency_key=_step(idempotency_key, "sign"),
            request_options=request_options,
        )
        if wait:
            vault = await self.vaults.retrieve(vault_id, request_options=request_options)
        return VaultWithdrawalResult(vault=vault, operation=operation)

    async def _attach_spend_key(
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
        signed = await self.spend_key_permit(
            account,
            spend_key,
            nonce=permit.get("nonce", 0),
            value=permit.get("value", MAX_UINT256),
            deadline=permit.get("deadline", MAX_UINT256),
            request_options=request_options,
        )
        return await self.accounts.attach_spend_key(
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

    async def _sleep(self, seconds: float) -> None:
        await anyio.sleep(seconds)

    def _monotonic(self) -> float:
        return time.monotonic()

    async def _send(self, prepared: PreparedRequest) -> httpx.Response:
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
                response = await self._http.send(request)
            except httpx.TransportError as exc:
                delay = retry_delay(attempt)
                if (
                    attempt < prepared.max_retries
                    and delay is not None
                    and is_retryable_exception(prepared, exc)
                ):
                    await self._sleep(delay)
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
                await self._sleep(delay)
                attempt += 1
                continue
            raise error_from_response(response)

    async def _request_json(
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
        return parse_json(await self._send(prepared))

    async def _request_model(
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
        return parse_model(await self._send(prepared), cast_to)

    async def _request_text(
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
        return (await self._send(prepared)).text


def _step(idempotency_key: str | None, step: str) -> str | None:
    """Suffix a caller-supplied idempotency key per step of a multi-call helper."""
    return f"{idempotency_key}.{step}" if idempotency_key else None
