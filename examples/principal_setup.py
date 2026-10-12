"""Principal setup: create an agent, its smart account, keys, session and policy.

Run against a sandbox (Base Sepolia) API:

    export AGENTBANK_BASE_URL=http://localhost:8080
    export AGENTBANK_API_KEY=abk_test_...
    export AGENTBANK_OWNER_KEY=0x...   # a *testnet development* owner key only
    uv run python examples/principal_setup.py

Production owner keys live in hardware wallets or passkeys: sign
``owner_authorization_typed_data(...)`` there and pass ``owner_authorization=``
instead of ``owner=``.

The agent's session and spend keys are generated here, client-side, and saved
to ``.agentbank/`` (git-ignored, mode 0600). Agent Bank never sees them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentbank import AgentBank, SessionKey, generate_session_key, generate_spend_key

KEY_DIR = Path(".agentbank")


def main() -> None:
    owner = SessionKey.from_env("AGENTBANK_OWNER_KEY")
    with AgentBank() as bank:  # AGENTBANK_API_KEY and AGENTBANK_BASE_URL from the environment
        org = bank.orgs.retrieve()
        print(f"Org {org.id} ({org.legal_name}), KYC {org.kyc_status}")

        agent = bank.agents.create(
            name="research-agent",
            description="Buys datasets and pays for API calls",
            metadata={"team": "research"},
        )

        session_key = generate_session_key()
        spend_key = generate_spend_key()
        account = bank.accounts.create(agent.id, spend_key_address=spend_key.address)
        print(f"Agent {agent.id} has account {account.address} on {account.chain}")

        # Spending rules: tightening changes apply at once; the owner signs the rest.
        # Owner authorizations use the deployment's EIP-712 chain id from GET /v1/meta.
        bank.policies.put(
            agent.id,
            policy={
                "limits": {"per_tx": "5.00", "per_day": "50.00"},
                "counterparties": {"mode": "open", "new_cooldown_minutes": 10},
                "approvals": [{"above": "25.00", "approvers": 1}],
            },
            owner=owner,
        )

        # A 24-hour session key, enforced on-chain by Smart Sessions plus the co-signer.
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = bank.sessions.create(
            account_id=account.id,
            public_key=session_key.address,
            scope={"max_per_tx": "5.00", "max_per_day": "50.00", "expires_at": expires_at},
            owner=owner,
        )
        session = bank.sessions.install(session.id)
        if session.install_operation_id is not None:
            bank.owner_operations.sign_and_submit(session.install_operation_id, owner=owner)

        KEY_DIR.mkdir(exist_ok=True)
        session_key.save(KEY_DIR / "session.json", overwrite=True)
        spend_key.save(KEY_DIR / "spend.json", overwrite=True)

    print("\nFor the agent examples:")
    print(f"export AGENTBANK_SESSION_ID={session.id}")
    print(f"export AGENTBANK_ACCOUNT_ID={account.id}")
    print(f"Fund the account ({account.address}) and the spend key ({spend_key.address})")
    print("with Base Sepolia test USDC.")


if __name__ == "__main__":
    main()
