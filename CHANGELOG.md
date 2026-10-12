# Changelog

All notable changes to the `agentbank` Python SDK are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, minor
versions may contain breaking changes.

## [Unreleased]

## [0.1.0] - Unreleased

First release, built against Agent Bank API 0.1.0 (`openapi.json`, 91
operations) and aligned with the TypeScript SDK (`@agentbank/sdk`). Testnet
(Base Sepolia) only.

### Added

- `AgentBank` (sync) and `AsyncAgentBank` (async) clients. The async client is
  the single source of truth; the sync client is generated from it by
  `scripts/unasync.py`.
- Principal authentication with org API keys and agent authentication with
  RFC 9421 HTTP Message Signatures by the session key (`eip191-secp256k1`,
  label `agentbank`), computed per attempt over the exact bytes sent.
- Automatic `Idempotency-Key` on idempotent operations, retries with backoff on
  network errors, 408, 429 and 5xx under the same key (honoring `Retry-After`,
  and never retrying sooner than the server asked), timeouts, and RFC 9457
  problem details mapped to an `AgentBankError` hierarchy with `.code`,
  `.status` and `.detail`. Malformed success responses raise
  `APIResponseValidationError`.
- Resource namespaces for every API operation except the staff-only
  `getRevenueReport`, with the TypeScript SDK's method names: `orgs`,
  `api_keys`, `members`, `agents`, `accounts`, `sessions`, `owner_operations`,
  `mandates`, `policies`, `payments`, `payment_requests`, `x402`, `escrows`,
  `streams`, `approvals`, `ledger`, `vaults`, `treasury`, `webhooks`, `billing`,
  `sandbox`, plus `health()`, `meta()` (cached) and a low-level
  `call(operation_id, ...)`. Lists (including sessions, mandates, owner
  operations, escrows, streams and auto top-up rules) have `list_all()`
  auto-pagination.
- `payments.pay()` (also `client.pay()`): create, check that the API created the
  payment that was asked for, sign `signing_request.user_op_hash` (EIP-191 over
  the raw 32 bytes) with the session key, submit; optionally wait for a human
  approval and for settlement. `payments.complete()` resumes a payment and
  `payments.wait_for_settlement()` polls one. Denials raise `PaymentDeniedError`
  (also a `PolicyDeniedError`), on-chain failures `PaymentFailedError`.
- `escrows.lock()`, `streams.start()` and `sign_and_submit()`: escrow and stream
  operations are signed only while `pending_action` is set and the signing
  request has not expired.
- Owner authorizations: `owner_authorize()`, `owner_authorization_typed_data()`
  (for hardware wallets), `verify_owner_authorization()` and `owner_payloads`
  (canonical subject and payload per action, schema defaults applied, as in
  `ownerPayloads` of `@agentbank/core`). `owner=` arguments sign session grants,
  policy loosening, mandates, unfreezing, owner rotation, spend-key attachment,
  treasury, auto top-up and sweep in the deployment's EIP-712 domain
  (`owner_authorization_chain_id` from `GET /v1/meta`).
- Early withdrawal from a locked vault, which `TimeLockVaults` authorizes with
  its own EIP-712 `EarlyWithdrawal` signature rather than an owner
  authorization: `withdraw_vault()` answers the API's `owner_signature_required`
  challenge (after checking its contract, chain, vault, amount and deadline
  against the vault and `GET /v1/meta`), resends the withdrawal and signs the
  owner operation that carries it. `vaults.withdraw(owner=...)` answers the
  challenge only; `vaults.early_withdrawal_typed_data()`,
  `early_withdrawal_typed_data()` and `sign_early_withdrawal()` cover hardware
  wallets.
- Spend-key float recovery (ADR 0001): `sign_spend_key_permit()` and
  `spend_key_permit_typed_data()` sign the EIP-2612 USDC permit (owner = the
  spend key, spender = the agent's smart account, value and deadline max uint256
  by default) in the USDC domain from `GET /v1/meta`;
  `accounts.attach_spend_key()` sends it with a `spend_key.set` authorization.
- Principal helpers matching the TypeScript SDK: `provision_spend_key()`,
  `grant_session()` (24-hour default expiry, at most 7 days) and
  `setup_agent_account()`, which creates the account, signs the permit for its
  address, attaches the spend key, then grants and installs the first session,
  with per-step idempotency keys so a failed setup can be re-run.
- Owner key rotation: `owner_operations.prepare_owner_swap()` (signed by the
  current owner, optionally waited on with `owner_operations.wait()`), then
  `orgs.rotate_owner()` (`owner.rotate`).
- `sandbox.faucet()` mints test USDC on the simulated chain and Anvil.
- x402 pay-per-call: `X402Transport` / `AsyncX402Transport` for `httpx`, and
  `client.x402.client()` / `fetch()`. Parses x402 v2 `PAYMENT-REQUIRED` headers
  and v1 JSON bodies, picks the cheapest `exact` USDC (EIP-3009) option on the
  network it pays on, enforces a client-side `max_amount` (default 1.00 USDC)
  and optional domain allowlist, checks the EIP-3009 authorization returned by
  the API against the challenge (and the USDC EIP-712 domain) before the spend
  key signs it, and retries with `PAYMENT-SIGNATURE` (v2) or `X-PAYMENT` (v1).
  `X402Error.reason` uses the TypeScript SDK's reasons (`payment_rejected` when
  the seller refuses).
- x402 pays on the deployment's network and USDC by default: without an
  explicit `network=`, `client.x402.settings()` resolves them from
  `GET /v1/meta` (`caip2`, `usdc.address`, `usdc.eip712_name`,
  `usdc.eip712_version`) on the first 402, cached on the client, so a local
  sandbox on the simulated chain (`eip155:1337`) or Anvil works without
  configuration. An explicit `network=` still wins; mainnets are refused either
  way.
- `generate_session_key()`, `generate_spend_key()` and `SessionKey` (0600 key
  files, environment loading, private key hidden from `repr`).
- Webhook verification: `verify_webhook()`, `construct_event()`, `sign_webhook()`.
- Canonical JSON (`canonical_json`, `canonical_keccak`, `canonical_sha256`) and
  money helpers (`money`, `parse_amount`, `format_amount`); money is never a float.
- Pydantic v2 models generated from `openapi.json` (`agentbank.models`) and a
  generated operation table; `scripts/generate_models.sh` regenerates both and
  `scripts/refresh_openapi.sh` refreshes the spec from the monorepo.
- Mainnet chain ids are refused everywhere the SDK signs.
- Cross-language test vectors shared with `@agentbank/core`, plus viem-generated
  EIP-3009, EIP-2612 permit, `EarlyWithdrawal` and user-operation signatures;
  all reproduce byte for byte. Permit and early-withdrawal digests are also
  checked against hand-built FiatToken and `TimeLockVaults` digests.

[Unreleased]: https://github.com/bank-of-an-agent/sdk-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bank-of-an-agent/sdk-python/releases/tag/v0.1.0
