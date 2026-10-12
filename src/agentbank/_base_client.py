"""I/O-free request machinery shared by :class:`AgentBank` and :class:`AsyncAgentBank`.

Everything here is deterministic and transport-agnostic: building URLs and
bodies, choosing credentials from the operation table, adding idempotency keys,
signing agent requests, deciding whether a failed attempt may be retried, and
parsing responses. The sync and async clients only add the I/O loop.
"""

from __future__ import annotations

import email.utils
import os
import platform
import random
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from agentbank._spec import Operation
from agentbank._version import __version__
from agentbank.canonical import canonical_json
from agentbank.chains import assert_testnet
from agentbank.errors import ConfigurationError
from agentbank.http_signatures import sign_request
from agentbank.keys import EthSigner, SessionKey, SignerLike, to_signer

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_TIMEOUT",
    "ClientConfig",
    "PreparedRequest",
    "RequestOptions",
]

ModelT = TypeVar("ModelT", bound=BaseModel)

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
DEFAULT_MAX_RETRIES = 2
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
INITIAL_RETRY_DELAY = 0.5
MAX_RETRY_DELAY = 8.0
MAX_RETRY_AFTER = 60.0

AuthMode = Literal["principal", "agent"]


class RequestOptions(TypedDict, total=False):
    """Per-request overrides accepted by every resource method.

    Keys:
        timeout: Seconds or an ``httpx.Timeout`` for this request.
        max_retries: Retries for this request (``0`` disables retries).
        extra_headers: Additional headers (cannot override authentication).
        extra_query: Additional query parameters.
    """

    timeout: float | httpx.Timeout | None
    max_retries: int
    extra_headers: Mapping[str, str]
    extra_query: Mapping[str, Any]


@dataclass(frozen=True)
class PreparedRequest:
    """A request ready to be signed and sent (one logical operation, many attempts).

    The body bytes and the idempotency key are fixed across attempts; agent
    signatures are recomputed per attempt because their nonce is single-use.
    """

    operation: Operation
    method: str
    url: str
    headers: dict[str, str]
    content: bytes | None
    auth: AuthMode | None
    timeout: httpx.Timeout
    max_retries: int


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else None


def _timeout(value: float | httpx.Timeout | None) -> httpx.Timeout:
    if value is None:
        return DEFAULT_TIMEOUT
    if isinstance(value, httpx.Timeout):
        return value
    return httpx.Timeout(float(value))


@dataclass
class ClientConfig:
    """Resolved client settings (constructor arguments, then environment variables).

    Environment variables: ``AGENTBANK_BASE_URL``, ``AGENTBANK_FACILITATOR_URL``,
    ``AGENTBANK_API_KEY``, ``AGENTBANK_SESSION_ID``, ``AGENTBANK_SESSION_KEY``,
    ``AGENTBANK_SPEND_KEY``, ``AGENTBANK_ACCOUNT_ID``.
    """

    base_url: str
    facilitator_url: str
    api_key: str | None
    session_id: str | None
    session_signer: EthSigner | None
    spend_signer: EthSigner | None
    account_id: str | None
    chain_id: int
    timeout: httpx.Timeout
    max_retries: int
    signature_lifetime_seconds: int
    default_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def resolve(
        cls,
        *,
        api_key: str | None,
        session_id: str | None,
        session_key: SignerLike | SessionKey | None,
        spend_key: SignerLike | SessionKey | None,
        account_id: str | None,
        base_url: str | None,
        facilitator_url: str | None,
        chain_id: int,
        timeout: float | httpx.Timeout | None,
        max_retries: int,
        signature_lifetime_seconds: int,
        default_headers: Mapping[str, str] | None,
    ) -> ClientConfig:
        """Merge explicit arguments with ``AGENTBANK_*`` environment variables."""
        assert_testnet(chain_id)
        if max_retries < 0:
            raise ConfigurationError("max_retries must be >= 0")
        resolved_base = (base_url or _env("AGENTBANK_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        resolved_facilitator = (
            facilitator_url or _env("AGENTBANK_FACILITATOR_URL") or resolved_base
        ).rstrip("/")
        for url in (resolved_base, resolved_facilitator):
            if not url.startswith(("http://", "https://")):
                raise ConfigurationError(f"Base URLs must be absolute http(s) URLs, got {url!r}")
        session_key = session_key if session_key is not None else _env("AGENTBANK_SESSION_KEY")
        spend_key = spend_key if spend_key is not None else _env("AGENTBANK_SPEND_KEY")
        session = session_id or _env("AGENTBANK_SESSION_ID")
        session_signer = to_signer(session_key) if session_key is not None else None
        if (session is None) != (session_signer is None):
            raise ConfigurationError(
                "Agent authentication needs both session_id and session_key "
                "(or AGENTBANK_SESSION_ID and AGENTBANK_SESSION_KEY)"
            )
        return cls(
            base_url=resolved_base,
            facilitator_url=resolved_facilitator,
            api_key=api_key or _env("AGENTBANK_API_KEY"),
            session_id=session,
            session_signer=session_signer,
            spend_signer=to_signer(spend_key) if spend_key is not None else None,
            account_id=account_id or _env("AGENTBANK_ACCOUNT_ID"),
            chain_id=chain_id,
            timeout=_timeout(timeout),
            max_retries=max_retries,
            signature_lifetime_seconds=signature_lifetime_seconds,
            default_headers=dict(default_headers or {}),
        )

    @property
    def user_agent(self) -> str:
        """``User-Agent`` sent with every request."""
        return (
            f"agentbank-python/{__version__} httpx/{httpx.__version__} "
            f"python/{platform.python_version()}"
        )

    # ------------------------------------------------------------------ auth

    def select_auth(self, operation: Operation) -> AuthMode | None:
        """Pick credentials for ``operation`` in the API's order of preference.

        Raises:
            ConfigurationError: The client has no credentials the operation accepts.
        """
        for kind in operation.auth:
            if kind in ("public", "seller"):
                return None
            if kind in ("principal", "approver") and self.api_key:
                return "principal"
            if kind == "agent" and self.session_signer is not None:
                return "agent"
        needs = {
            "principal": "an org API key (api_key)",
            "approver": "an approver's API key (api_key)",
            "agent": "an agent session (session_id + session_key)",
            "staff": "a staff token",
        }
        wanted = " or ".join(needs.get(kind, kind) for kind in operation.auth)
        raise ConfigurationError(f"{operation.operation_id} requires {wanted}")

    def auth_headers(self, prepared: PreparedRequest, url: str) -> dict[str, str]:
        """Headers that authenticate one attempt of ``prepared``.

        Agent signatures are computed here, per attempt, over the exact URL
        (``url``, as the HTTP client will send it), body bytes and idempotency
        key, with a fresh nonce.
        """
        if prepared.auth == "principal":
            return {"Authorization": f"Bearer {self.api_key}"}
        if prepared.auth == "agent":
            assert self.session_signer is not None
            assert self.session_id is not None
            signed = sign_request(
                prepared.method,
                url,
                prepared.headers,
                prepared.content,
                key_id=self.session_id,
                signer=self.session_signer,
                lifetime_seconds=self.signature_lifetime_seconds,
            )
            headers = {
                "Signature-Input": signed["signature-input"],
                "Signature": signed["signature"],
            }
            if "content-digest" in signed:
                headers["Content-Digest"] = signed["content-digest"]
            return headers
        return {}

    # ------------------------------------------------------------------ requests

    def build_url(
        self,
        operation: Operation,
        path_params: Mapping[str, str] | None,
        query: Mapping[str, Any] | None,
    ) -> str:
        """Absolute URL for ``operation`` with path parameters and query string."""
        path = operation.path
        for name in operation.path_params:
            value = (path_params or {}).get(name)
            if value is None or value == "":
                raise ValueError(f"{operation.operation_id}: missing path parameter {name!r}")
            path = path.replace("{" + name + "}", quote(str(value), safe=""))
        base = self.facilitator_url if operation.service == "facilitator" else self.base_url
        url = base + path
        params = [(k, _query_value(v)) for k, v in (query or {}).items() if v is not None]
        if params:
            url = str(httpx.URL(url, params=params))
        return url

    def prepare(
        self,
        operation: Operation,
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        idempotency_key: str | None = None,
        accept: str = "application/json",
        options: RequestOptions | None = None,
    ) -> PreparedRequest:
        """Build the :class:`PreparedRequest` for one logical operation."""
        opts: RequestOptions = options or {}
        auth = self.select_auth(operation)
        merged_query: dict[str, Any] = {**(query or {}), **(opts.get("extra_query") or {})}
        url = self.build_url(operation, path_params, merged_query)
        headers: dict[str, str] = {
            "Accept": accept,
            "User-Agent": self.user_agent,
            **self.default_headers,
            **(opts.get("extra_headers") or {}),
        }
        for reserved in ("authorization", "signature", "signature-input", "content-digest"):
            for key in [k for k in headers if k.lower() == reserved]:
                del headers[key]
        content: bytes | None = None
        if operation.has_body or body is not None:
            content = canonical_json({} if body is None else body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if operation.idempotent:
            key = idempotency_key or new_idempotency_key()
            if not 8 <= len(key) <= 255:
                raise ValueError("idempotency_key must be 8 to 255 characters")
            headers["Idempotency-Key"] = key
        timeout = _timeout(opts["timeout"]) if "timeout" in opts else self.timeout
        max_retries = opts.get("max_retries", self.max_retries)
        return PreparedRequest(
            operation=operation,
            method=operation.method,
            url=url,
            headers=headers,
            content=content,
            auth=auth,
            timeout=timeout,
            max_retries=max(0, max_retries),
        )


def _query_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def new_idempotency_key() -> str:
    """A fresh random idempotency key (UUID4)."""
    return str(uuid.uuid4())


def is_retryable_exception(prepared: PreparedRequest, error: httpx.TransportError) -> bool:
    """Whether a transport failure may be retried.

    Connection failures (the request never left) are always retryable; failures
    after the request may have been received are retried only for operations
    that cannot double-apply (reads, deletes, idempotency-keyed writes).
    """
    if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
        return True
    return prepared.operation.retry_safe


def is_retryable_response(prepared: PreparedRequest, response: httpx.Response) -> bool:
    """Whether an error response may be retried (429 always; 408/5xx when retry-safe)."""
    if response.status_code == 429:
        return True
    return response.status_code in RETRYABLE_STATUSES and prepared.operation.retry_safe


def retry_delay(attempt: int, response: httpx.Response | None = None) -> float:
    """Seconds to wait before retry number ``attempt + 1``.

    Honors ``Retry-After`` (seconds or HTTP date, capped at 60 s); otherwise
    exponential backoff from 0.5 s to 8 s with jitter.
    """
    if response is not None:
        header = response.headers.get("retry-after")
        if header:
            try:
                delay = float(header)
            except ValueError:
                try:
                    delay = email.utils.parsedate_to_datetime(header).timestamp() - time.time()
                except (TypeError, ValueError):
                    delay = -1.0
            if 0 <= delay <= MAX_RETRY_AFTER:
                return delay
    base: float = min(INITIAL_RETRY_DELAY * 2**attempt, MAX_RETRY_DELAY)
    return base * (1 - 0.25 * random.random())  # noqa: S311 - jitter, not cryptography


def parse_json(response: httpx.Response) -> Any:
    """Decode a JSON response body (``None`` for empty bodies)."""
    if not response.content:
        return None
    return response.json()


def parse_model(response: httpx.Response, cast_to: type[ModelT]) -> ModelT:
    """Validate a JSON response body into ``cast_to``."""
    return cast_to.model_validate(parse_json(response))
