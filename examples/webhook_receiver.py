"""Receive Agent Bank webhooks and verify their signatures (standard library server).

    export AGENTBANK_WEBHOOK_SECRET=whsec_...   # shown once by webhooks.create_endpoint
    uv run python examples/webhook_receiver.py

Always verify against the raw body bytes, before parsing them.
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from agentbank import SignatureVerificationError, construct_event


class WebhookHandler(BaseHTTPRequestHandler):
    """Accepts ``POST /webhooks/agentbank`` deliveries."""

    secret = os.environ.get("AGENTBANK_WEBHOOK_SECRET", "")

    def do_POST(self) -> None:
        """Verify and handle one delivery."""
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        try:
            event = construct_event(self.secret, body, self.headers.get("agentbank-signature"))
        except SignatureVerificationError as err:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(err.detail.encode())
            return
        # Deliveries are retried for 72 hours: make handling idempotent on event.id.
        print(f"{event.type} {event.id}: {event.data}")
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8787), WebhookHandler).serve_forever()
