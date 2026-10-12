# Generated from src/agentbank/_async/resources/owner_operations.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Owner operations: ``/v1/owner-operations``."""

from __future__ import annotations

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact, owner_signature_idempotency_key
from agentbank._sync.resources._base import APIResource
from agentbank.chains import assert_testnet
from agentbank.keys import SessionKey, SignerLike, personal_sign_hash, to_signer
from agentbank.models import OwnerOperation

__all__ = ["OwnerOperations"]


class OwnerOperations(APIResource):
    """On-chain operations only the principal's owner key can authorize.

    Installing a session, configuring executors, early vault withdrawals and
    payments that policy routes to ``require_owner``. Agent Bank cannot sign
    them; the owner signs ``user_op_hash`` (EIP-191 personal sign of the hash
    bytes) and the API submits the operation.
    """

    def retrieve(
        self, operation_id: str, *, request_options: RequestOptions | None = None
    ) -> OwnerOperation:
        """Get an owner operation."""
        return self._request(
            ops.GET_OWNER_OPERATION,
            OwnerOperation,
            path_params={"id": operation_id},
            request_options=request_options,
        )

    def submit_signature(
        self,
        operation_id: str,
        *,
        signature: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> OwnerOperation:
        """Submit the owner-key signature over ``user_op_hash``."""
        return self._request(
            ops.SUBMIT_OWNER_SIGNATURE,
            OwnerOperation,
            path_params={"id": operation_id},
            body=compact(signature=signature),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def sign_and_submit(
        self,
        operation_id: str,
        *,
        owner: SignerLike | SessionKey,
        request_options: RequestOptions | None = None,
    ) -> OwnerOperation:
        """Fetch an owner operation, sign its ``user_op_hash`` with the owner key, submit it.

        The owner key signs the raw 32 bytes of ``user_op_hash`` (EIP-191).
        Mainnet chain ids are refused. Intended for testnet development owners
        held in software; production owner keys live in hardware wallets: sign
        ``user_op_hash`` there and call :meth:`submit_signature`.
        """
        operation = self.retrieve(operation_id, request_options=request_options)
        if operation.status != "requires_signature":
            return operation
        assert_testnet(operation.chain_id)
        signature = personal_sign_hash(to_signer(owner), operation.user_op_hash)
        return self.submit_signature(
            operation_id,
            signature=signature,
            idempotency_key=owner_signature_idempotency_key(operation_id, operation.user_op_hash),
            request_options=request_options,
        )
