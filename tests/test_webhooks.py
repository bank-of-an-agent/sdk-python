"""Webhook signature verification."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentbank import SignatureVerificationError, construct_event, sign_webhook, verify_webhook
from agentbank._async.resources.webhooks import AsyncWebhooks
from agentbank.webhooks import WEBHOOK_EVENT_TYPES, WEBHOOK_RETRY_SCHEDULE_SECONDS, WebhookEvent

NOW = 1_790_000_000
SECRET = "whsec_test"
BODY = '{"id":"evt_1","type":"payment.settled","data":{"id":"pay_1"}}'


def test_signs_and_verifies_with_tolerance() -> None:
    header = sign_webhook(SECRET, BODY, NOW)
    assert verify_webhook(SECRET, BODY, header, now=NOW + 10) == NOW
    assert verify_webhook(SECRET, BODY.encode(), header, now=NOW - 10) == NOW
    with pytest.raises(SignatureVerificationError, match="mismatch"):
        verify_webhook(SECRET, BODY.replace("pay_1", "pay_2"), header, now=NOW)
    with pytest.raises(SignatureVerificationError, match="mismatch"):
        verify_webhook("whsec_other", BODY, header, now=NOW)
    with pytest.raises(SignatureVerificationError, match="tolerance"):
        verify_webhook(SECRET, BODY, header, now=NOW + 3600)
    assert verify_webhook(SECRET, BODY, header, tolerance=3600, now=NOW + 3600) == NOW


def test_missing_header_or_timestamp() -> None:
    with pytest.raises(SignatureVerificationError, match="Missing") as missing:
        verify_webhook(SECRET, "{}", None)
    assert missing.value.code == "signature_invalid"
    with pytest.raises(SignatureVerificationError, match="timestamp"):
        verify_webhook(SECRET, "{}", "v1=abc")
    with pytest.raises(SignatureVerificationError, match="timestamp"):
        verify_webhook(SECRET, "{}", "t=soon,v1=abc")


def test_rotation_prefixes_and_garbage_candidates() -> None:
    good = sign_webhook(SECRET, BODY, NOW).split("v1=")[1]
    header = f"t={NOW}, v1=zz, v1=abc, v1=0x{good}, =junk, novalue"
    assert verify_webhook(SECRET, BODY, header, now=NOW) == NOW
    upper = f"t={NOW},v1={good.upper()}"
    assert verify_webhook(SECRET, BODY, upper, now=NOW) == NOW


def test_construct_event_parses_the_envelope() -> None:
    header = sign_webhook(SECRET, BODY, NOW)
    event = construct_event(SECRET, BODY, header, now=NOW)
    assert isinstance(event, WebhookEvent)
    assert event.type == "payment.settled"
    assert event.data == {"id": "pay_1"}
    full = json.dumps(
        {
            "id": "evt_2",
            "object": "event",
            "type": "agent.frozen",
            "org_id": "org_1",
            "data": {},
            "created_at": "2026-10-11T00:00:00Z",
            "api_version": "0.1.0",
        }
    )
    parsed = construct_event(SECRET, full, sign_webhook(SECRET, full, NOW), now=NOW)
    assert parsed.created_at is not None
    assert parsed.model_extra == {"api_version": "0.1.0"}
    bad = '{"type":"x"}'
    with pytest.raises(ValidationError):
        construct_event(SECRET, bad, sign_webhook(SECRET, bad, NOW), now=NOW)


def test_default_timestamp_is_now() -> None:
    header = sign_webhook(SECRET, BODY)
    assert verify_webhook(SECRET, BODY, header) > NOW


def test_resource_helpers_delegate() -> None:
    header = sign_webhook(SECRET, BODY)
    assert AsyncWebhooks.verify(SECRET, BODY, header) > 0
    assert AsyncWebhooks.construct_event(SECRET, BODY, header).id == "evt_1"


def test_event_types_and_retry_schedule() -> None:
    assert "payment.settled" in WEBHOOK_EVENT_TYPES
    assert len(WEBHOOK_EVENT_TYPES) == 24
    assert WEBHOOK_RETRY_SCHEDULE_SECONDS[-1] == 72 * 3600
