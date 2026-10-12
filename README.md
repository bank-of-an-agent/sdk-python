# agentbank

The Python SDK for [Agent Bank](https://github.com/bank-of-an-agent): give an AI agent a
non-custodial USDC account with hard spending limits, pay other agents and HTTP APIs with
[x402](https://x402.org), and verify webhooks, from sync or async Python.

[![CI](https://github.com/bank-of-an-agent/sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/bank-of-an-agent/sdk-python/actions/workflows/ci.yml)
![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-3776AB)
![Typed](https://img.shields.io/badge/typing-mypy%20strict-blue)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)

> [!NOTE]
> Pre-release, testnet only (Base Sepolia). Not yet published to PyPI: install from this
> repository.

## Features

- `AgentBank` and `AsyncAgentBank` clients for every REST operation, with Pydantic models
  generated from the API's OpenAPI document.
- Agent requests signed with the session key (RFC 9421), automatic idempotency keys reused
  across retries, backoff on network errors, 429 and 5xx, and typed errors with `.code`,
  `.status` and `.detail`.
- Payments end to end: create, sign the user operation with the session key, submit, wait for
  approval or settlement.
- An x402 transport for `httpx` (sync and async) that pays HTTP 402 challenges within policy,
  signing with the agent's spend key and refusing anything above `max_amount`.
- Principal helpers: owner authorizations, `setup_agent_account` (account, spend key and its
  float-recovery permit, first session), owner operations, key rotation.
- Webhook verification. Byte-for-byte compatible with the TypeScript SDK (shared test vectors).

## Install

```bash
uv add "agentbank @ git+https://github.com/bank-of-an-agent/sdk-python"
# or
pip install "agentbank @ git+https://github.com/bank-of-an-agent/sdk-python"
```

Requires Python 3.10 or later.

## Usage

### Pay as an agent

```python
from agentbank import AgentBank, PolicyDeniedError, SessionKey

# AGENTBANK_SESSION_ID and AGENTBANK_ACCOUNT_ID come from the environment.
agent = AgentBank(session_key=SessionKey.load(".agentbank/session.json"))

decision = agent.policies.check(intent={"kind": "transfer", "amount": "12.50", "to_address": payee})
try:
    payment = agent.pay(to=payee, amount="12.50", memo="dataset", wait_for_settlement=True)
except PolicyDeniedError as err:
    print(f"Denied by policy: {err.detail}")
```

### Pay per call with x402

```python
agent = AgentBank(
    session_key=SessionKey.load(".agentbank/session.json"),
    spend_key=SessionKey.load(".agentbank/spend.json"),
)
with agent, agent.x402.client(max_amount="0.10") as http:
    response = http.get("https://api.example-data.com/v1/report")  # answers a 402 within policy
```

### Set up an agent (principal)

```python
from agentbank import AgentBank, SessionKey

# A testnet owner key; production owner keys stay in hardware wallets or passkeys.
owner = SessionKey.from_env("AGENTBANK_OWNER_KEY")
with AgentBank() as bank:  # AGENTBANK_API_KEY and AGENTBANK_BASE_URL from the environment
    agent = bank.agents.create(name="research-agent")
    # See examples/principal_setup.py for the policy, spend key, permit and session steps.
```

Runnable scripts are in [`examples/`](examples): principal setup, agent payment, x402 fetch,
async usage, a LangChain tool and a webhook receiver.

| Variable | Meaning |
| --- | --- |
| `AGENTBANK_BASE_URL` | API base URL (e.g. `http://localhost:8080`) |
| `AGENTBANK_API_KEY` | Org API key (principals) |
| `AGENTBANK_SESSION_ID`, `AGENTBANK_ACCOUNT_ID` | The agent's session and account |
| `AGENTBANK_SESSION_KEY`, `AGENTBANK_SPEND_KEY` | The agent's keys, if not passed explicitly |
| `AGENTBANK_FACILITATOR_URL` | x402 facilitator (defaults to the API base URL) |

## Development

```bash
uv sync
uv run pytest                      # 563 tests, ≥ 90% coverage enforced (currently ~99%)
uv run ruff check && uv run ruff format --check
uv run mypy                        # --strict
scripts/refresh_openapi.sh         # copy ../agent-bank/docs/openapi.json and regenerate models
```

The async client in `src/agentbank/_async` is the source of truth; `scripts/unasync.py` generates
the sync client, and CI fails if they drift.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). The only private keys in this
repository are public Anvil development keys used in test vectors.

## License

Apache-2.0. See [LICENSE](LICENSE).
