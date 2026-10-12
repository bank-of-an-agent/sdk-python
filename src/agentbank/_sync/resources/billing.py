# Generated from src/agentbank/_async/resources/billing.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Plans, subscription and fees: ``/v1/billing``."""

from __future__ import annotations

from typing import Literal

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.models import FeeSummary, ListPlansResponse, Subscription

__all__ = ["Billing"]


class Billing(APIResource):
    """Subscription plans (billed monthly in USDC from the treasury) and fees."""

    def list_plans(self, *, request_options: RequestOptions | None = None) -> ListPlansResponse:
        """List plans (public)."""
        return self._request(ops.LIST_PLANS, ListPlansResponse, request_options=request_options)

    def get_subscription(self, *, request_options: RequestOptions | None = None) -> Subscription:
        """Get the org's subscription."""
        return self._request(ops.GET_SUBSCRIPTION, Subscription, request_options=request_options)

    def change_plan(
        self,
        *,
        plan: Literal["free", "pro", "business", "enterprise"],
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Subscription:
        """Change the org's plan."""
        return self._request(
            ops.CHANGE_PLAN,
            Subscription,
            body=compact(plan=plan),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def get_fees(self, *, period: str, request_options: RequestOptions | None = None) -> FeeSummary:
        """Fees charged in a period (``YYYY-MM``), by kind."""
        return self._request(
            ops.GET_FEES, FeeSummary, query={"period": period}, request_options=request_options
        )
