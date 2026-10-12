"""Async usage: concurrent reads, a payment and paid x402 calls with ``AsyncAgentBank``.

Run it after ``principal_setup.py``:

    export AGENTBANK_SESSION_ID=ses_...
    export AGENTBANK_ACCOUNT_ID=acct_...
    uv run python examples/async_usage.py 0xPAYEE...
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from agentbank import AsyncAgentBank, PaymentError, SessionKey

REPORT_URLS = [
    "https://api.example-data.com/v1/report?ticker=ACME",
    "https://api.example-data.com/v1/report?ticker=INITECH",
]


async def main(payee: str) -> int:
    keys = Path(".agentbank")
    async with AsyncAgentBank(
        session_key=SessionKey.load(keys / "session.json"),
        spend_key=SessionKey.load(keys / "spend.json"),
    ) as agent:
        balances, policy_page = await asyncio.gather(
            agent.accounts.balances(),
            agent.payments.list(account_id=agent.account_id, limit=5),
        )
        print(f"Available {balances.available} USDC; {len(policy_page.data)} recent payments")

        try:
            payment = await agent.pay(to=payee, amount="0.50", wait_for_settlement=True)
            print(f"Settled {payment.id}")
        except PaymentError as err:
            print(f"Payment failed ({err.code}): {err.detail}")
            return 1

        # One x402 client, many concurrent paid calls (each capped at 0.05 USDC).
        async with agent.x402.client(max_amount="0.05") as http:
            responses = await asyncio.gather(*(http.get(url) for url in REPORT_URLS))
        for url, response in zip(REPORT_URLS, responses, strict=True):
            print(f"{url}: HTTP {response.status_code}")

        # Auto-pagination works with ``async for``.
        async for entry in agent.ledger.list_entries_all(limit=50):
            print(
                entry.id,
                entry.ref_type,
                [(line.ledger_account, line.amount) for line in entry.lines],
            )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: async_usage.py PAYEE_ADDRESS")
    sys.exit(asyncio.run(main(sys.argv[1])))
