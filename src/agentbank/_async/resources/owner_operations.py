"""Owner operations: ``/v1/owner-operations`` and ``/v1/accounts/{id}/owner-swap``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact, owner_signature_idempotency_key
from agentbank.chains import assert_testnet
from agentbank.errors import AgentBankError
from agentbank.keys import SessionKey, SignerLike, personal_sign_hash, to_signer
from agentbank.models import ListOwnerOperationsResponse, OwnerOperation

__all__ = ["AsyncOwnerOperations"]

OwnerOperationStatus = Literal["requires_signature", "submitted", "succeeded", "failed", "expired"]

#: Statuses after which an owner operation will not change any more.
DONE_STATUSES = frozenset({"succeeded", "failed", "expired"})
DEFAULT_TIMEOUT = 120.0
DEFAULT_POLL_INTERVAL = 2.0


class AsyncOwnerOperations(AsyncAPIResource):
    """On-chain operations only the principal's owner key can authorize.

    Installing a session, configuring executors, early vault withdrawals,
    owner swaps and payments that policy routes to ``require_owner``. Agent
    Bank cannot sign them; the owner signs ``user_op_hash`` (EIP-191 personal
    sign of the raw hash bytes) and the API submits the operation.
    """

    async def list(
        self,
        *,
        account_id: str | None = None,
        status: OwnerOperationStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListOwnerOperationsResponse:
        """List owner operations (one page), e.g. those waiting for a signature."""
        return await self._request(
            ops.LIST_OWNER_OPERATIONS,
            ListOwnerOperationsResponse,
            query={"account_id": account_id, "status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        account_id: str | None = None,
        status: OwnerOperationStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[OwnerOperation]:
        """Iterate over every owner operation, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_OWNER_OPERATIONS,
            ListOwnerOperationsResponse,
            query={"account_id": account_id, "status": status, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def retrieve(
        self, operation_id: str, *, request_options: RequestOptions | None = None
    ) -> OwnerOperation:
        """Get an owner operation."""
        return await self._request(
            ops.GET_OWNER_OPERATION,
            OwnerOperation,
            path_params={"id": operation_id},
            request_options=request_options,
        )

    async def submit_signature(
        self,
        operation_id: str,
        *,
        signature: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> OwnerOperation:
        """Submit the owner-key signature over ``user_op_hash``."""
        return await self._request(
            ops.SUBMIT_OWNER_SIGNATURE,
            OwnerOperation,
            path_params={"id": operation_id},
            body=compact(signature=signature),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def sign_and_submit(
        self,
        operation: OwnerOperation | str,
        *,
        owner: SignerLike | SessionKey,
        wait: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> OwnerOperation:
        """Sign an owner operation's ``user_op_hash`` with the owner key and submit it.

        The owner key signs the raw 32 bytes of ``user_op_hash`` (EIP-191).
        Mainnet chain ids are refused. Intended for testnet development owners
        held in software; production owner keys live in hardware wallets: sign
        ``user_op_hash`` there and call :meth:`submit_signature`.

        Args:
            operation: The operation or its id.
            owner: The owner key.
            wait: Poll until the operation succeeded, failed or expired.
            timeout: Seconds to wait when ``wait`` is true.
            poll_interval: Seconds between status checks.
            idempotency_key: Key for the submission (default: derived from the
                operation id and hash, so re-running is safe).
            request_options: Per-request overrides.

        Raises:
            AgentBankError: ``operation_timeout`` when still pending after ``timeout``.
        """
        current = (
            operation
            if isinstance(operation, OwnerOperation)
            else await self.retrieve(operation, request_options=request_options)
        )
        if current.status == "requires_signature":
            assert_testnet(current.chain_id)
            signature = personal_sign_hash(to_signer(owner), current.user_op_hash)
            current = await self.submit_signature(
                current.id,
                signature=signature,
                idempotency_key=idempotency_key
                or owner_signature_idempotency_key(current.id, current.user_op_hash),
                request_options=request_options,
            )
        if wait:
            current = await self.wait(
                current,
                timeout=timeout,
                poll_interval=poll_interval,
                request_options=request_options,
            )
        return current

    async def wait(
        self,
        operation: OwnerOperation | str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        request_options: RequestOptions | None = None,
    ) -> OwnerOperation:
        """Poll an owner operation until it succeeded, failed or expired.

        Raises:
            AgentBankError: ``operation_timeout`` when still pending after ``timeout``.
        """
        current = (
            operation
            if isinstance(operation, OwnerOperation)
            else await self.retrieve(operation, request_options=request_options)
        )
        deadline = self._client._monotonic() + timeout
        while current.status not in DONE_STATUSES:
            if self._client._monotonic() >= deadline:
                raise AgentBankError(
                    "operation_timeout",
                    f"Owner operation {current.id} is still {current.status} after {timeout:g}s",
                )
            await self._client._sleep(poll_interval)
            current = await self.retrieve(current.id, request_options=request_options)
        return current

    async def prepare_owner_swap(
        self,
        account_id: str,
        *,
        new_owner_address: str,
        owner: SignerLike | SessionKey | None = None,
        wait: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> OwnerOperation:
        """Prepare the owner operation that swaps an account's owner (purpose ``owner.swap``).

        It swaps the Safe owner and the validator owner in one operation and must
        be signed by the **current** owner key. Do this for every account, then
        call ``orgs.rotate_owner``.

        Args:
            account_id: The account.
            new_owner_address: The new owner key's address.
            owner: The current owner key: sign and submit the operation right away.
            wait: With ``owner``, wait until the operation is done.
            timeout: Seconds to wait when ``wait`` is true.
            poll_interval: Seconds between status checks.
            idempotency_key: Optional key; generated when omitted (``.sign`` is
                appended for the signature submission).
            request_options: Per-request overrides.
        """
        operation = await self._request(
            ops.PREPARE_OWNER_SWAP,
            OwnerOperation,
            path_params={"id": account_id},
            body={"new_owner_address": new_owner_address},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
        if owner is None:
            return operation
        return await self.sign_and_submit(
            operation,
            owner=owner,
            wait=wait,
            timeout=timeout,
            poll_interval=poll_interval,
            idempotency_key=f"{idempotency_key}.sign" if idempotency_key else None,
            request_options=request_options,
        )
