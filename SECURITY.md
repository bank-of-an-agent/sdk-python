# Security policy

The `agentbank` SDK signs requests and payments with keys that control money.
We take reports seriously and appreciate coordinated disclosure.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
[private vulnerability reporting](https://github.com/bank-of-an-agent/sdk-python/security/advisories/new)
for this repository. Include:

- the affected version or commit,
- a description of the issue and its impact,
- steps or a proof of concept to reproduce it (on testnet only), and
- any suggested fix.

We aim to acknowledge reports within 3 business days, share an initial
assessment within 10 business days, and coordinate a fix and disclosure date
with you. We credit reporters who wish to be credited.

## Supported versions

Agent Bank is pre-1.0 and testnet-only. Security fixes are released for the
latest minor version.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## In scope

- Request signing (RFC 9421), canonical JSON, EIP-712 owner authorizations and
  EIP-3009 signing producing signatures other than the ones intended.
- The x402 client paying more than `max_amount`, paying a host outside
  `allowed_domains`, paying the wrong payee, asset or chain, or signing an
  authorization that does not match the challenge.
- Any way to make the SDK sign for a mainnet chain id.
- Leaking private keys, API keys or signatures (logs, `repr`, exceptions,
  files with loose permissions).
- Replay or idempotency flaws that could make a retried request pay twice.
- Webhook signature verification bypasses.

Vulnerabilities in the Agent Bank API, co-signer, contracts or other services
belong to their own repositories; if unsure, report here and we will route it.

## Handling keys safely

- The SDK never needs the owner key for agent operations. Keep owner keys in
  hardware wallets or passkeys and sign `owner_authorization_typed_data(...)`
  there; `owner=` helpers are meant for testnet development keys.
- Session and spend keys are generated client-side. Store them in a secret
  manager; `SessionKey.save()` writes files readable only by the current user.
- Never commit keys or `.env` files. The only private keys in this repository
  are the publicly known Anvil development keys used by the test vectors; never
  use them for real funds.
- Agent Bank is testnet-only (Base Sepolia). The SDK refuses mainnet chain ids.
