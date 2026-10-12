"""Supported networks and assets. Agent Bank is testnet-only.

Mainnet chain ids are listed so the SDK can refuse them explicitly: the SDK will
not sign owner authorizations, x402 payments or anything else for a locked
mainnet chain (mirrors ``assertTestnet`` in ``@agentbank/core``).
"""

from __future__ import annotations

from dataclasses import dataclass

from agentbank.errors import AgentBankError, MainnetLockedError

__all__ = [
    "BASE_SEPOLIA",
    "CHAINS",
    "DEFAULT_CHAIN_ID",
    "LOCKED_MAINNET_CHAIN_IDS",
    "USDC",
    "AssetInfo",
    "ChainInfo",
    "assert_testnet",
    "chain_by_id",
    "chain_by_name",
    "chain_for_network",
    "find_asset",
]


@dataclass(frozen=True)
class AssetInfo:
    """A token deployment on one chain.

    Attributes:
        code: Asset code, e.g. ``"USDC"``.
        chain_id: EVM chain id.
        address: Checksummed token contract address.
        decimals: Token decimals (USDC: 6).
        eip712_name: EIP-712 domain ``name`` used by EIP-3009 authorizations.
        eip712_version: EIP-712 domain ``version`` used by EIP-3009 authorizations.
    """

    code: str
    chain_id: int
    address: str
    decimals: int
    eip712_name: str
    eip712_version: str


@dataclass(frozen=True)
class ChainInfo:
    """A supported (testnet) network.

    Attributes:
        name: Agent Bank chain name, e.g. ``"base-sepolia"``.
        id: EVM chain id.
        caip2: CAIP-2 identifier used by x402 v2, e.g. ``"eip155:84532"``.
        x402_network: Network name used by x402 v1, e.g. ``"base-sepolia"``.
        display_name: Human-readable name.
    """

    name: str
    id: int
    caip2: str
    x402_network: str
    display_name: str


BASE_SEPOLIA = ChainInfo("base-sepolia", 84532, "eip155:84532", "base-sepolia", "Base Sepolia")

#: Every chain the SDK will operate on, keyed by Agent Bank chain name.
CHAINS: dict[str, ChainInfo] = {
    "base-sepolia": BASE_SEPOLIA,
    "anvil": ChainInfo("anvil", 31337, "eip155:31337", "anvil", "Local Anvil"),
    "simulated": ChainInfo("simulated", 1337, "eip155:1337", "simulated", "Simulated chain"),
}

#: The default chain: Base Sepolia.
DEFAULT_CHAIN_ID = BASE_SEPOLIA.id

#: Chain ids the SDK refuses outright (Ethereum, Base, Optimism, Arbitrum, Polygon).
LOCKED_MAINNET_CHAIN_IDS: frozenset[int] = frozenset({1, 8453, 10, 42161, 137})

#: USDC deployments known to the SDK.
USDC: dict[int, AssetInfo] = {
    84532: AssetInfo("USDC", 84532, "0x036CbD53842c5426634e7929541eC2318f3dCF7e", 6, "USDC", "2"),
    1337: AssetInfo("USDC", 1337, "0x5dc0000000000000000000000000000000005dc0", 6, "USDC", "2"),
}


def assert_testnet(chain_id: int) -> ChainInfo:
    """Return the chain for ``chain_id``, refusing mainnets and unknown chains.

    Raises:
        MainnetLockedError: ``chain_id`` is a mainnet (code ``mainnet_locked``).
        AgentBankError: ``chain_id`` is not a supported testnet (``unsupported_chain``).
    """
    if chain_id in LOCKED_MAINNET_CHAIN_IDS:
        raise MainnetLockedError(
            "mainnet_locked",
            f"Chain {chain_id} is a mainnet. Agent Bank is testnet-only.",
        )
    for chain in CHAINS.values():
        if chain.id == chain_id:
            return chain
    raise AgentBankError("unsupported_chain", f"Chain {chain_id} is not supported")


def chain_by_id(chain_id: int) -> ChainInfo:
    """Alias of :func:`assert_testnet`."""
    return assert_testnet(chain_id)


def chain_by_name(name: str) -> ChainInfo:
    """Look up a chain by its Agent Bank name (``base-sepolia``, ``anvil``, ``simulated``)."""
    try:
        return CHAINS[name]
    except KeyError:
        raise AgentBankError("unsupported_chain", f"Unknown chain {name!r}") from None


def chain_for_network(network: str) -> ChainInfo:
    """Resolve an x402 network (CAIP-2 ``eip155:<id>`` or a v1 name) to a testnet chain.

    Raises:
        MainnetLockedError: The network is a mainnet (e.g. ``eip155:8453``, ``base``).
        AgentBankError: The network is unknown (``unsupported_chain``).
    """
    if network.startswith("eip155:"):
        reference = network.removeprefix("eip155:")
        if not reference.isdigit():
            raise AgentBankError("unsupported_chain", f"Invalid CAIP-2 network {network!r}")
        return assert_testnet(int(reference))
    if network in {"base", "ethereum", "mainnet", "optimism", "arbitrum", "polygon"}:
        raise MainnetLockedError("mainnet_locked", f"Network {network!r} is a mainnet")
    for chain in CHAINS.values():
        if chain.x402_network == network:
            return chain
    raise AgentBankError("unsupported_chain", f"Unknown network {network!r}")


def find_asset(chain_id: int, address: str) -> AssetInfo | None:
    """Return the known asset deployed at ``address`` on ``chain_id``, if any."""
    asset = USDC.get(chain_id)
    if asset is not None and asset.address.lower() == address.lower():
        return asset
    return None
