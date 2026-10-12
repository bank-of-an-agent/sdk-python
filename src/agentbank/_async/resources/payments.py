"""Payments: ``/v1/payments`` and ``/v1/payment-requests``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions, new_idempotency_key
from agentbank._resource_helpers import (
    TERMINAL_PAYMENT_STATUSES,
    compact,
    denied_error,
    destination,
    signature_idempotency_key,
)
from agentbank.errors import (
    AgentBankError,
    BadRequestError,
    PaymentError,
    PaymentFailedError,
)
from agentbank.models import (
    ListPaymentsResponse,
    Money,
    Payment,
    PaymentDestination,
    PaymentRequest,
    SigningRequest,
)
from agentbank.money import MoneyInput, coerce_money, parse_amount

__all__ = ["AsyncPaymentRequests", "AsyncPayments", "assert_payment_matches"]

PaymentStatus = Literal[
    "requires_approval",
    "requires_signature",
    "submitted",
    "settled",
    "denied",
    "failed",
    "canceled",
    "expired",
]

DEFAULT_SETTLEMENT_TIMEOUT = 120.0
DEFAULT_POLL_INTERVAL = 2.0


def assert_payment_matches(payment: Payment, amount: Money, to: Mapping[str, Any]) -> None:
    """Refuse to sign a payment the API created differently from the request.

    Checks the amount and, when the destination names them, the counterparty
    address and agent (same check as the TypeScript SDK).

    Raises:
        BadRequestError: ``invalid_request`` listing the differences.
    """
    problems: list[str] = []
    if parse_amount(payment.amount.amount) != parse_amount(amount.amount):
        problems.append(f"amount {payment.amount.amount} != {amount.amount}")
    address = to.get("address")
    if isinstance(address, str) and payment.counterparty.address.lower() != address.lower():
        problems.append("counterparty address differs")
    agent_id = to.get("agent_id")
    if (
        isinstance(agent_id, str)
        and payment.counterparty.agent_id is not None
        and payment.counterparty.agent_id != agent_id
    ):
        problems.append("counterparty agent differs")
    if problems:
        raise BadRequestError(
            "invalid_request",
            f"Refusing to sign payment {payment.id}: it does not match the request "
            f"({', '.join(problems)})",
        )


def _raise_if_unsuccessful(payment: Payment) -> None:
    if payment.status == "denied":
        raise denied_error(payment)
    if payment.status == "failed":
        reason = f": {payment.failure_reason}" if payment.failure_reason else ""
        raise PaymentFailedError(f"Payment {payment.id} failed{reason}", resource=payment)
    if payment.status in ("canceled", "expired"):
        raise PaymentError(
            f"payment_{payment.status}",
            f"Payment {payment.id} is {payment.status}",
            resource=payment,
        )


def _signing_request(payment: Payment) -> SigningRequest:
    if payment.signing_request is not None:
        return payment.signing_request
    if payment.owner_operation_id is not None:
        raise PaymentError(
            "requires_owner",
            f"Policy requires the owner key to sign payment {payment.id} "
            f"(owner operation {payment.owner_operation_id})",
            resource=payment,
        )
    raise AgentBankError("invalid_state", f"Payment {payment.id} has nothing to sign")


class AsyncPayments(AsyncAPIResource):
    """Agent payments: create, sign with the session key, submit, settle.

    The quickest path is :meth:`pay`, which runs the whole two-step flow::

        payment = await bank.payments.pay(to="0x...", amount="12.50", memo="dataset")
    """

    async def create(
        self,
        *,
        amount: MoneyInput,
        to: PaymentDestination | Mapping[str, Any] | str,
        account_id: str | None = None,
        memo: str | None = None,
        mandate_id: str | None = None,
        payment_request_id: str | None = None,
        metadata: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Payment:
        """Create a payment (step 1 of 2). Requires agent authentication.

        The API places a hold, evaluates policy and returns the payment as
        ``requires_signature`` (sign ``signing_request.user_op_hash``; see
        :meth:`sign_and_submit`), ``requires_approval`` or ``denied``.

        Args:
            amount: Decimal string (USDC), ``Decimal`` or ``Money``. Never a float.
            to: ``0x`` address, ``agt_`` agent id, ``acct_`` account id, or a
                mapping with exactly one of ``address``/``agent_id``/``account_id``.
            account_id: Paying account (defaults to the client's ``account_id``).
            memo: Free text (max 500 characters).
            mandate_id: Mandate the payment is made under.
            payment_request_id: The payment request being paid.
            metadata: Up to 20 string key/value pairs.
            idempotency_key: Reuse the same key to retry safely; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            account_id=self._account(account_id),
            amount=coerce_money(amount),
            to=destination(to),
            memo=memo,
            mandate_id=mandate_id,
            payment_request_id=payment_request_id,
            metadata=metadata,
        )
        return await self._request(
            ops.CREATE_PAYMENT,
            Payment,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def list(
        self,
        *,
        account_id: str | None = None,
        status: PaymentStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListPaymentsResponse:
        """List payments (one page), newest first."""
        return await self._request(
            ops.LIST_PAYMENTS,
            ListPaymentsResponse,
            query={"account_id": account_id, "status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        account_id: str | None = None,
        status: PaymentStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Payment]:
        """Iterate over every payment, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_PAYMENTS,
            ListPaymentsResponse,
            query={"account_id": account_id, "status": status, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def retrieve(
        self, payment_id: str, *, request_options: RequestOptions | None = None
    ) -> Payment:
        """Get a payment."""
        return await self._request(
            ops.GET_PAYMENT,
            Payment,
            path_params={"id": payment_id},
            request_options=request_options,
        )

    async def submit_signature(
        self,
        payment_id: str,
        *,
        signature: str,
        session_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Payment:
        """Submit the session-key signature (step 2 of 2).

        The co-signer re-checks policy against its own history, co-signs, and the
        API submits the operation (``submitted``).
        """
        body = compact(session_id=session_id or self._client.session_id, signature=signature)
        return await self._request(
            ops.SUBMIT_PAYMENT_SIGNATURE,
            Payment,
            path_params={"id": payment_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def cancel(
        self,
        payment_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Payment:
        """Cancel a payment that has not been submitted; its hold is released."""
        return await self._request(
            ops.CANCEL_PAYMENT,
            Payment,
            path_params={"id": payment_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def sign(self, payment: Payment) -> str:
        """Sign ``payment.signing_request.user_op_hash`` with the session key.

        Returns the ``0x`` signature: EIP-191 personal sign over the **raw 32
        bytes** of the hash, as the Smart Sessions validator verifies.

        Raises:
            AgentBankError: ``invalid_state`` if the payment has nothing to sign.
            ConfigurationError: The client has no session key, or another session
                must sign.
            MainnetLockedError: The operation targets a mainnet chain.
        """
        if payment.signing_request is None:
            raise AgentBankError("invalid_state", f"Payment {payment.id} has nothing to sign")
        return self._client._sign_operation(payment.signing_request)[1]

    async def sign_and_submit(
        self, payment: Payment, *, request_options: RequestOptions | None = None
    ) -> Payment:
        """Sign the payment's signing request and submit it (idempotently).

        Raises:
            PaymentError: ``requires_owner`` when policy routed the payment to the
                owner key (see ``owner_operation_id``).
        """
        signing_request = _signing_request(payment)
        session_id, signature = self._client._sign_operation(signing_request)
        return await self.submit_signature(
            payment.id,
            signature=signature,
            session_id=session_id,
            idempotency_key=signature_idempotency_key(payment.id, signing_request),
            request_options=request_options,
        )

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
        """Pay in one call: create, check, sign ``user_op_hash`` with the session key, submit.

        Before signing, the SDK checks that the API created the payment that was
        asked for (amount and counterparty). Safe to re-run with the same
        ``idempotency_key``: the API returns the original payment and the
        signature is resubmitted under a deterministic key.

        Args:
            to: ``0x`` address, ``agt_`` agent id, ``acct_`` account id, or a mapping.
            amount: Decimal string (USDC), ``Decimal`` or ``Money``. Never a float.
            account_id: Paying account (defaults to the client's ``account_id``).
            memo: Free text (max 500 characters).
            mandate_id: Mandate the payment is made under.
            payment_request_id: The payment request being paid.
            metadata: Up to 20 string key/value pairs.
            idempotency_key: Key for the payment; generated when omitted. Pass your
                own to make retries of your task safe.
            wait_for_approval: If policy queues the payment for a human approver,
                wait for the decision (then sign) instead of returning it as
                ``requires_approval``.
            wait_for_settlement: Wait until the payment settles on-chain.
            timeout: Seconds to wait in total when waiting.
            poll_interval: Seconds between status checks.
            request_options: Per-request overrides.

        Returns:
            The payment: ``submitted`` (or ``requires_approval``) without waiting,
            ``settled`` when waiting for settlement.

        Raises:
            PaymentDeniedError: Denied by policy or by the co-signer
                (also a :class:`~agentbank.PolicyDeniedError`).
            PaymentFailedError: Failed on-chain.
            PaymentError: Canceled, expired, needs the owner key
                (``requires_owner``), or still pending at the timeout.
            BadRequestError: The created payment does not match the request.
        """
        money = coerce_money(amount)
        target = destination(to)
        payment = await self.create(
            amount=money,
            to=target,
            account_id=account_id,
            memo=memo,
            mandate_id=mandate_id,
            payment_request_id=payment_request_id,
            metadata=metadata,
            idempotency_key=idempotency_key or new_idempotency_key(),
            request_options=request_options,
        )
        assert_payment_matches(payment, money, target)
        return await self.complete(
            payment,
            wait_for_approval=wait_for_approval,
            wait_for_settlement=wait_for_settlement,
            timeout=timeout,
            poll_interval=poll_interval,
            request_options=request_options,
        )

    async def complete(
        self,
        payment: Payment | str,
        *,
        wait_for_approval: bool = False,
        wait_for_settlement: bool = False,
        timeout: float = DEFAULT_SETTLEMENT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        request_options: RequestOptions | None = None,
    ) -> Payment:
        """Drive an existing payment to completion; safe to call again on the same payment.

        Optionally waits for a human approval, signs and submits when the payment
        ``requires_signature``, then optionally waits for settlement.

        Raises:
            PaymentDeniedError: Denied by policy or by the co-signer.
            PaymentFailedError: Failed on-chain.
            PaymentError: Canceled, expired, ``requires_owner`` or ``settlement_timeout``.
        """
        current = (
            payment
            if isinstance(payment, Payment)
            else await self.retrieve(payment, request_options=request_options)
        )
        deadline = self._client._monotonic() + timeout
        if current.status == "requires_approval" and wait_for_approval:
            current = await self._poll(
                current.id,
                lambda p: p.status != "requires_approval",
                deadline=deadline,
                timeout=timeout,
                poll_interval=poll_interval,
                request_options=request_options,
            )
        _raise_if_unsuccessful(current)
        if current.status == "requires_signature":
            current = await self.sign_and_submit(current, request_options=request_options)
            _raise_if_unsuccessful(current)
        if (
            wait_for_settlement
            and current.status not in TERMINAL_PAYMENT_STATUSES
            and current.status != "requires_approval"
        ):
            current = await self._poll(
                current.id,
                lambda p: p.status in TERMINAL_PAYMENT_STATUSES,
                deadline=deadline,
                timeout=timeout,
                poll_interval=poll_interval,
                request_options=request_options,
            )
        _raise_if_unsuccessful(current)
        return current

    async def wait_for_settlement(
        self,
        payment: Payment | str,
        *,
        timeout: float = DEFAULT_SETTLEMENT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        request_options: RequestOptions | None = None,
    ) -> Payment:
        """Poll a payment until it settles (it does not sign; see :meth:`complete`).

        Raises:
            PaymentDeniedError: Denied by policy or by the co-signer.
            PaymentFailedError: Failed on-chain.
            PaymentError: Canceled, expired, or still pending at the timeout
                (``settlement_timeout``).
        """
        payment_id = payment.id if isinstance(payment, Payment) else payment
        settled = await self._poll(
            payment_id,
            lambda p: p.status in TERMINAL_PAYMENT_STATUSES,
            deadline=self._client._monotonic() + timeout,
            timeout=timeout,
            poll_interval=poll_interval,
            request_options=request_options,
        )
        _raise_if_unsuccessful(settled)
        return settled

    async def _poll(
        self,
        payment_id: str,
        done: Callable[[Payment], bool],
        *,
        deadline: float,
        timeout: float,
        poll_interval: float,
        request_options: RequestOptions | None,
    ) -> Payment:
        while True:
            current = await self.retrieve(payment_id, request_options=request_options)
            if done(current):
                return current
            if self._client._monotonic() >= deadline:
                raise PaymentError(
                    "settlement_timeout",
                    f"Payment {current.id} is still {current.status} after {timeout:g}s",
                    resource=current,
                )
            await self._client._sleep(poll_interval)


class AsyncPaymentRequests(AsyncAPIResource):
    """Requests for another agent or a human to pay this account."""

    async def create(
        self,
        *,
        amount: MoneyInput,
        account_id: str | None = None,
        memo: str | None = None,
        reference: str | None = None,
        expires_in_seconds: int | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> PaymentRequest:
        """Ask someone to pay ``amount`` into an account; share ``pay_link``.

        Args:
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            account_id: Receiving account (defaults to the client's ``account_id``).
            memo: Free text shown to the payer.
            reference: Your own reference (max 200 characters).
            expires_in_seconds: 60 s to 30 days (server default 7 days).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            account_id=self._account(account_id),
            amount=coerce_money(amount),
            memo=memo,
            reference=reference,
            expires_in_seconds=expires_in_seconds,
        )
        return await self._request(
            ops.CREATE_PAYMENT_REQUEST,
            PaymentRequest,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def retrieve(
        self, payment_request_id: str, *, request_options: RequestOptions | None = None
    ) -> PaymentRequest:
        """Get a payment request."""
        return await self._request(
            ops.GET_PAYMENT_REQUEST,
            PaymentRequest,
            path_params={"id": payment_request_id},
            request_options=request_options,
        )
