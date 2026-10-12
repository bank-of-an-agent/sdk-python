"""Agent payment: check the balance, dry-run policy, then pay and wait for settlement.

    export AGENTBANK_SESSION_ID=ses_...   # printed by principal_setup.py
    export AGENTBANK_ACCOUNT_ID=acct_...
    uv run python examples/agent_pay.py 0xPAYEE... 1.00

The agent authenticates every request with an RFC 9421 signature by its
session key; it holds no API key and cannot loosen its own limits.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

from agentbank import AgentBank, PaymentError, PolicyDeniedError, SessionKey


def main(payee: str, amount: str) -> int:
    session_key = SessionKey.load(Path(".agentbank/session.json"))
    with AgentBank(session_key=session_key) as agent:  # session id and account from env
        balances = agent.accounts.balances()
        print(f"Available: {balances.available} {balances.asset}")

        decision = agent.policies.check(
            intent={"kind": "transfer", "amount": amount, "to_address": payee}
        )
        print(f"Policy says: {decision.outcome}")
        for hit in decision.rule_hits:
            print(f"  {hit.rule}: {hit.effect} ({hit.detail})")
        if decision.outcome == "deny":
            return 1

        try:
            payment = agent.pay(
                to=payee,
                amount=amount,
                memo="example payment",
                # Reuse the same key if you retry this task: the bank pays at most once.
                idempotency_key=f"example-{uuid.uuid4()}",
                wait_for_approval=True,  # if policy asks a human, wait for the decision
                wait_for_settlement=True,
                timeout=300,
            )
        except PolicyDeniedError as err:  # API 422 or a denied payment (PaymentDeniedError)
            print(f"Denied by policy: {err.detail}")
            return 1
        except PaymentError as err:  # failed on-chain, expired, or still pending at the timeout
            print(f"Payment did not settle ({err.code}): {err.detail}")
            return 1

    print(f"Paid {payment.amount.amount} {payment.amount.asset}: {payment.id} ({payment.status})")
    print(f"Fee {payment.fee.amount}, transaction {payment.tx_hash}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: agent_pay.py PAYEE_ADDRESS AMOUNT")
    sys.exit(main(sys.argv[1], sys.argv[2]))
