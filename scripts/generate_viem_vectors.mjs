// Generate tests/viem_vectors.json: signatures produced by viem, the library the
// TypeScript services use, so the Python SDK is checked against an independent
// implementation for the signatures that are not in tests/vectors.json:
//
//   * the EIP-3009 TransferWithAuthorization signed by the x402 spend key,
//   * the EIP-2612 USDC permit signed by the spend key (float recovery),
//   * the EIP-191 personal signature over raw user-operation hash bytes, and
//   * the TimeLockVaults EarlyWithdrawal signed by the owner key (early vault withdrawal).
//
// Usage (viem must be resolvable; e.g. point VIEM_DIR at the monorepo's copy):
//   VIEM_DIR=../agent-bank/node_modules/.pnpm/viem@<version>/node_modules/viem \
//     node scripts/generate_viem_vectors.mjs > tests/viem_vectors.json
//
// Keys are public Anvil development keys; never use them for real funds.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const base = process.env.VIEM_DIR ? pathToFileURL(resolve(process.env.VIEM_DIR)).href : null;
const { privateKeyToAccount } = await import(base ? `${base}/_esm/accounts/index.js` : "viem/accounts");
const { hashTypedData, keccak256, toHex } = await import(base ? `${base}/_esm/index.js` : "viem");

const spendKey = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const spend = privateKeyToAccount(spendKey);
const domain = {
  name: "USDC",
  version: "2",
  chainId: 84532,
  verifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
};
const authorization = {
  from: spend.address,
  to: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  value: "10000",
  validAfter: "0",
  validBefore: "1790000060",
  nonce: keccak256(toHex("pay_01JABCDEFGHJKMNPQRSTVWXYZ0")),
};
const types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};
const signature = await spend.signTypedData({
  domain,
  types,
  primaryType: "TransferWithAuthorization",
  message: {
    ...authorization,
    value: BigInt(authorization.value),
    validAfter: BigInt(authorization.validAfter),
    validBefore: BigInt(authorization.validBefore),
  },
});

// EIP-2612 USDC permit signed by the spend key (float recovery, ADR 0001):
// owner = spend key, spender = the agent's smart account, max value and deadline.
const maxUint256 = 2n ** 256n - 1n;
const permit = {
  owner: spend.address,
  spender: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  value: maxUint256,
  nonce: 0n,
  deadline: maxUint256,
};
const permitSignature = await spend.signTypedData({
  domain,
  types: {
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  },
  primaryType: "Permit",
  message: permit,
});

// TimeLockVaults EarlyWithdrawal signed by the owner key: before a locked vault's
// unlock date only the vault owner can release funds (TimeLockVaults.withdrawWithSignature).
const ownerKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const owner = privateKeyToAccount(ownerKey);
const earlyWithdrawalTypedData = {
  domain: {
    name: "AgentBank TimeLockVaults",
    version: "1",
    chainId: 84532,
    verifyingContract: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  },
  types: {
    EarlyWithdrawal: [
      { name: "vaultId", type: "uint256" },
      { name: "amount", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  },
  primaryType: "EarlyWithdrawal",
  message: { vaultId: 7n, amount: 15000000n, nonce: 3n, deadline: 1790000900n },
};
const earlyWithdrawalSignature = await owner.signTypedData(earlyWithdrawalTypedData);

const sessionKey = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const session = privateKeyToAccount(sessionKey);
const userOpHash = keccak256(toHex("user-op-vector"));
const userOpSignature = await session.signMessage({ message: { raw: userOpHash } });

console.log(
  JSON.stringify(
    {
      description:
        "Generated with viem (scripts/generate_viem_vectors.mjs). Anvil dev keys only; never use for real funds.",
      eip3009: { spend_private_key: spendKey, spend_address: spend.address, domain, authorization, signature },
      permit: {
        spend_private_key: spendKey,
        domain,
        message: {
          ...permit,
          value: permit.value.toString(),
          nonce: permit.nonce.toString(),
          deadline: permit.deadline.toString(),
        },
        signature: permitSignature,
      },
      user_op: {
        session_private_key: sessionKey,
        session_address: session.address,
        user_op_hash: userOpHash,
        signature: userOpSignature,
      },
      early_withdrawal: {
        owner_private_key: ownerKey,
        owner_address: owner.address,
        domain: earlyWithdrawalTypedData.domain,
        message: Object.fromEntries(
          Object.entries(earlyWithdrawalTypedData.message).map(([k, v]) => [k, v.toString()]),
        ),
        digest: hashTypedData(earlyWithdrawalTypedData),
        signature: earlyWithdrawalSignature,
      },
    },
    null,
    2,
  ),
);
