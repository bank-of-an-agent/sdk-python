"""Principal setup: create an agent, its policy, smart account, spend key and session.

Run against a sandbox (Base Sepolia) API:

    export AGENTBANK_BASE_URL=http://localhost:8080
    export AGENTBANK_API_KEY=abk_test_...
    export AGENTBANK_OWNER_KEY=0x...   # a *testnet development* owner key only
    uv run python examples/principal_setup.py

Production owner keys live in hardware wallets or passkeys: sign
``owner_authorization_typed_data(...)`` there and pass ``owner_authorization=``
instead of ``owner=``.

The agent's session and spend keys are generated here, client-side, and saved
to ``.agentbank/`` (git-ignored, mode 0600) before the API learns their
addresses. Agent Bank never sees the private keys.
"""

from __future__ import annotations

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

        session_key = generate_session_key()
        spend_key = generate_spend_key()
        KEY_DIR.mkdir(exist_ok=True)
        session_key.save(KEY_DIR / "session.json", overwrite=True)
        spend_key.save(KEY_DIR / "spend.json", overwrite=True)

        # The smart account, x402 spend key and first session, in the order the
        # contracts need: create the account -> the spend key signs the USDC
        # float-recovery permit for the account's address (ADR 0001) -> the owner
        # authorizes the spend key (spend_key.set) -> grant a 24-hour session
        # whose on-chain install, signed by the owner, also executes the permit.
        # The idempotency key makes every step safe to re-run after a failure.
        result = bank.setup_agent_account(
            agent_id=agent.id,
            owner=owner,
            chain="base-sepolia",
            spend_key=spend_key,
            session={
                "public_key": session_key.address,
                "scope": {"max_per_tx": "5.00", "max_per_day": "50.00"},
                "wait_for_install": True,
            },
            idempotency_key=f"setup-{agent.id}",
        )
        account, session = result.account, result.session
        if session is None:
            raise RuntimeError("setup_agent_account did not grant the session")
        print(f"Agent {agent.id} has account {account.address} on {account.chain}")
        print(f"Spend key {account.spend_key_address} (permit {account.spend_key_permit})")
        print(f"Session {session.id} ({session.status})")

    print("\nFor the agent examples:")
    print(f"export AGENTBANK_SESSION_ID={session.id}")
    print(f"export AGENTBANK_ACCOUNT_ID={account.id}")
    print(f"Fund the account ({account.address}) and the spend key ({spend_key.address})")
    print("with Base Sepolia test USDC (on the simulated chain or Anvil, use")
    print('bank.sandbox.faucet(amount="10.00", account_id=...) instead).')


if __name__ == "__main__":
    main()
