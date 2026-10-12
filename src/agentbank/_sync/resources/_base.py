# Generated from src/agentbank/_async/resources/_base.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Base class of the synchronous resource namespaces."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel

from agentbank._base_client import RequestOptions
from agentbank._spec import Operation
from agentbank.eip712 import owner_authorize
from agentbank.errors import ConfigurationError
from agentbank.keys import SessionKey, SignerLike
from agentbank.owner_payloads import OwnerActionPayload

if TYPE_CHECKING:
    from agentbank._sync.client import AgentBank

__all__ = ["APIResource"]

ModelT = TypeVar("ModelT", bound=BaseModel)
PageT = TypeVar("PageT", bound=BaseModel)


class APIResource:
    """A group of related API operations bound to a client."""

    def __init__(self, client: AgentBank) -> None:
        self._client = client

    def _account(self, account_id: str | None) -> str:
        resolved = account_id or self._client.account_id
        if not resolved:
            raise ConfigurationError(
                "account_id is required: pass it, or create the client with account_id="
            )
        return resolved

    def _owner_authorization(
        self, owner: SignerLike | SessionKey, request: OwnerActionPayload
    ) -> dict[str, Any]:
        """Sign ``request`` with the owner key in the deployment's EIP-712 domain."""
        chain_id = self._client.owner_authorization_chain_id()
        return owner_authorize(owner, chain_id, request.action, request.subject, request.payload)

    def _request(
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
        return self._client._request_model(
            operation,
            cast_to,
            path_params=path_params,
            query=query,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def _paginate(
        self,
        operation: Operation,
        page_type: type[PageT],
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, Any] | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[PageT]:
        params = dict(query or {})
        while True:
            page = self._request(
                operation,
                page_type,
                path_params=path_params,
                query=params,
                request_options=request_options,
            )
            yield page
            cursor = getattr(page, "next_cursor", None)
            if not cursor:
                return
            params["cursor"] = cursor
