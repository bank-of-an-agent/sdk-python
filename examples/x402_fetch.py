"""Pay-per-call with x402: fetch a resource that answers HTTP 402.

    export AGENTBANK_SESSION_ID=ses_...
    export AGENTBANK_ACCOUNT_ID=acct_...
    uv run python examples/x402_fetch.py https://api.example-data.com/v1/report

The x402 client parses the 402 challenge, refuses anything above
``max_amount`` (or off the allowlist), asks Agent Bank to authorize the payment
within policy, checks the returned EIP-3009 authorization against the challenge,
signs it with the spend key and retries with the ``PAYMENT-SIGNATURE`` header.
"""

from __future__ import annotations

import sys
from pathlib import Path

from agentbank import AgentBank, SessionKey, X402Error, format_amount, x402_receipt


def main(url: str) -> int:
    keys = Path(".agentbank")
    agent = AgentBank(
        session_key=SessionKey.load(keys / "session.json"),
        spend_key=SessionKey.load(keys / "spend.json"),
    )
    # Reuse one x402 client for many calls; each 402 is paid at most once.
    with agent, agent.x402.client(max_amount="0.10", timeout=30) as http:
        try:
            response = http.get(url)
        except X402Error as err:
            print(f"Not paid ({err.code}): {err.detail}")
            return 1

    print(f"HTTP {response.status_code}, {len(response.content)} bytes")
    receipt = x402_receipt(response)
    if receipt is not None:
        price = format_amount(receipt.requirement.amount, receipt.requirement.asset.decimals)
        print(f"Paid {price} USDC to {receipt.requirement.pay_to} ({receipt.payment.id})")
        if receipt.settlement:
            print(f"Settled in {receipt.settlement.get('transaction')}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: x402_fetch.py URL")
    sys.exit(main(sys.argv[1]))
