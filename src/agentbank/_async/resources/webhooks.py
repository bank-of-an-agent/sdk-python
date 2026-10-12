"""Webhook endpoints and events: ``/v1/webhook-endpoints``, ``/v1/events``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.models import (
    Event,
    ListEventsResponse,
    ListWebhookEndpointsResponse,
    WebhookEndpoint,
    WebhookEndpointWithSecret,
)
from agentbank.webhooks import (
    DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    WebhookEvent,
    WebhookEventType,
    construct_event,
    verify_webhook,
)

__all__ = ["AsyncWebhooks"]


class AsyncWebhooks(AsyncAPIResource):
    """Webhook endpoints, the event log, and signature verification helpers."""

    async def create_endpoint(
        self,
        *,
        url: str,
        events: Sequence[WebhookEventType],
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> WebhookEndpointWithSecret:
        """Register a webhook endpoint. The signing ``secret`` is returned once."""
        return await self._request(
            ops.CREATE_WEBHOOK_ENDPOINT,
            WebhookEndpointWithSecret,
            body=compact(url=url, events=tuple(events)),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def list_endpoints(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListWebhookEndpointsResponse:
        """List webhook endpoints (one page)."""
        return await self._request(
            ops.LIST_WEBHOOK_ENDPOINTS,
            ListWebhookEndpointsResponse,
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_endpoints_all(
        self, *, limit: int | None = None, request_options: RequestOptions | None = None
    ) -> AsyncIterator[WebhookEndpoint]:
        """Iterate over every webhook endpoint, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_WEBHOOK_ENDPOINTS,
            ListWebhookEndpointsResponse,
            query={"limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def delete_endpoint(
        self, endpoint_id: str, *, request_options: RequestOptions | None = None
    ) -> WebhookEndpoint:
        """Disable a webhook endpoint."""
        return await self._request(
            ops.DELETE_WEBHOOK_ENDPOINT,
            WebhookEndpoint,
            path_params={"id": endpoint_id},
            request_options=request_options,
        )

    async def list_events(
        self,
        *,
        type: WebhookEventType | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListEventsResponse:
        """List events (one page), optionally of one type."""
        return await self._request(
            ops.LIST_EVENTS,
            ListEventsResponse,
            query={"type": type, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_events_all(
        self,
        *,
        type: WebhookEventType | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Event]:
        """Iterate over every event, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_EVENTS,
            ListEventsResponse,
            query={"type": type, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    @staticmethod
    def verify(
        secret: str,
        body: str | bytes,
        header: str | None,
        tolerance: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    ) -> int:
        """Verify a delivery's ``AgentBank-Signature`` (see :func:`agentbank.verify_webhook`)."""
        return verify_webhook(secret, body, header, tolerance)

    @staticmethod
    def construct_event(
        secret: str,
        body: str | bytes,
        header: str | None,
        tolerance: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    ) -> WebhookEvent:
        """Verify a delivery and parse its body (see :func:`agentbank.construct_event`)."""
        return construct_event(secret, body, header, tolerance)
