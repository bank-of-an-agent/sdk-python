// Generate tests/viem_vectors.json: signatures produced by viem, the library the
// TypeScript services use, so the Python SDK is checked against an independent
// implementation for the two signatures that are not in tests/vectors.json:
//
//   * the EIP-3009 TransferWithAuthorization signed by the x402 spend key, and
//   * the EIP-191 personal signature over raw user-operation hash bytes.
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
const { keccak256, toHex } = await import(base ? `${base}/_esm/index.js` : "viem");

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
      user_op: {
        session_private_key: sessionKey,
        session_address: session.address,
        user_op_hash: userOpHash,
        signature: userOpSignature,
      },
    },
    null,
    2,
  ),
);
