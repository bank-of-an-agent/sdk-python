"""Inputs and results of the multi-step principal helpers.

``AgentBank.grant_session``, ``AgentBank.provision_spend_key``,
``AgentBank.setup_agent_account`` and ``AgentBank.withdraw_vault`` (and their
async twins) chain several API calls and owner signatures; these types
describe what they take and return.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, TypedDict

from typing_extensions import Required

from agentbank.canonical import to_jsonable
from agentbank.errors import BadRequestError
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import Account, OwnerOperation, Session, SessionScope, Vault
from agentbank.owner_payloads import with_defaults

__all__ = [
    "DEFAULT_SESSION_TTL_SECONDS",
    "MAX_SESSION_TTL_SECONDS",
    "GrantSessionResult",
    "PermitOptions",
    "SessionGrant",
    "SetupAgentAccountResult",
    "VaultWithdrawalResult",
    "session_scope_with_expiry",
]

#: Default session lifetime when the scope has no ``expires_at``: 24 hours.
DEFAULT_SESSION_TTL_SECONDS: Final = 24 * 60 * 60
#: Longest session the API accepts: 7 days.
MAX_SESSION_TTL_SECONDS: Final = 7 * 24 * 60 * 60


class PermitOptions(TypedDict, total=False):
    """Overrides for the spend-key permit (see :func:`agentbank.sign_spend_key_permit`).

    Keys:
        nonce: USDC ``nonces(spend key)`` (default 0, right for a fresh key).
        value: Allowance in USDC minor units (default max uint256).
        deadline: Unix-seconds deadline (default max uint256).
    """

    nonce: int | str
    value: int | str
    deadline: int | str


class SessionGrant(TypedDict, total=False):
    """The first session to grant in ``setup_agent_account``.

    Keys:
        public_key: The session key address (``generate_session_key().address``).
        scope: ``max_per_tx``, ``max_per_day`` and optional ``allowed_recipients``,
            ``allowed_contracts``, ``asset``, ``expires_at``.
        ttl_seconds: Lifetime when ``scope`` has no ``expires_at`` (default 24 h).
        install: Prepare and sign the on-chain install (default ``True``).
        wait_for_install: Wait until the install operation is done (default ``False``).
        owner: Owner key for the grant, if different from ``setup_agent_account``'s.
    """

    public_key: Required[str]
    scope: Required[SessionScope | Mapping[str, Any]]
    ttl_seconds: int
    install: bool
    wait_for_install: bool
    owner: SignerLike | SessionKey


@dataclass(frozen=True)
class GrantSessionResult:
    """Result of ``grant_session``.

    Attributes:
        session: The session (``pending_install`` until its install succeeds).
        install_operation: The signed install owner operation (``None`` when not installed).
    """

    session: Session
    install_operation: OwnerOperation | None


@dataclass(frozen=True)
class SetupAgentAccountResult:
    """Result of ``setup_agent_account``.

    Attributes:
        account: The account as of the last step (spend key attached if requested).
        session: The granted session, if one was requested.
        install_operation: The signed setup owner operation, if a session was installed.
    """

    account: Account
    session: Session | None
    install_operation: OwnerOperation | None


@dataclass(frozen=True)
class VaultWithdrawalResult:
    """Result of ``withdraw_vault``.

    Attributes:
        vault: The vault (read again after the operation when waiting).
        operation: The signed early-withdrawal owner operation (``None`` when
            the vault withdrew at once).
    """

    vault: Vault
    operation: OwnerOperation | None


def session_scope_with_expiry(
    scope: SessionScope | Mapping[str, Any],
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Make every session-scope default explicit (``asset``, ``expires_at`` = now + ttl).

    Same rules as the TypeScript SDK: the expiry must be in the future and at
    most 7 days away.

    Raises:
        BadRequestError: ``ttl_seconds`` or ``expires_at`` out of range.
        pydantic.ValidationError: The scope does not match the schema.
    """
    if isinstance(ttl_seconds, bool) or not 0 < ttl_seconds <= MAX_SESSION_TTL_SECONDS:
        raise BadRequestError(
            "invalid_request", f"ttl_seconds must be between 1 and {MAX_SESSION_TTL_SECONDS}"
        )
    current = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    candidate: dict[str, Any] = dict(to_jsonable(scope))
    candidate.setdefault("asset", "USDC")
    if candidate.get("expires_at") is None:
        candidate["expires_at"] = current + timedelta(seconds=ttl_seconds)
    normalized = with_defaults(SessionScope, candidate)
    expires = SessionScope.model_validate(normalized).expires_at
    limit = current + timedelta(seconds=MAX_SESSION_TTL_SECONDS + 60)
    if expires <= current or expires > limit:
        raise BadRequestError(
            "invalid_request", "Session expiry must be in the future and at most 7 days away"
        )
    return normalized
