"""Session keys, spend keys and signers.

Agents never hold the owner key. They hold two short-lived or low-value keys,
both generated client-side by the SDK:

* the **session key** (secp256k1) signs API requests (RFC 9421) and the user
  operations the co-signer co-signs; it is useless without the co-signer;
* the **spend key** (secp256k1 EOA) holds a small USDC float and signs EIP-3009
  authorizations for x402 pay-per-call.

Private keys are never printed: :class:`SessionKey` hides them from ``repr``.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from eth_account import Account
from eth_account.datastructures import SignedMessage
from eth_account.messages import SignableMessage, encode_defunct, encode_typed_data
from eth_account.signers.local import LocalAccount

__all__ = [
    "EthSigner",
    "SessionKey",
    "SignerLike",
    "generate_session_key",
    "generate_spend_key",
    "personal_sign_hash",
    "personal_sign_text",
    "sign_typed_data",
    "to_signer",
]


@runtime_checkable
class EthSigner(Protocol):
    """Anything that can sign like an ``eth_account`` account.

    ``eth_account.LocalAccount`` satisfies it; so can hardware-wallet or KMS
    adapters that implement ``address`` and ``sign_message``.
    """

    @property
    def address(self) -> str:
        """Checksummed address of the key."""
        ...

    def sign_message(self, signable_message: SignableMessage) -> SignedMessage:
        """Sign an EIP-191 ``SignableMessage`` (personal message or typed data)."""
        ...


#: A signer, or a raw private key (``0x``-prefixed hex string or 32 bytes).
SignerLike = EthSigner | str | bytes


@dataclass(frozen=True)
class SessionKey:
    """A secp256k1 key pair generated client-side (session key or spend key).

    Attributes:
        private_key: ``0x``-prefixed hex private key. Hidden from ``repr``.
        address: Checksummed address (the key's public identity).
    """

    private_key: str = field(repr=False)
    address: str

    @classmethod
    def generate(cls) -> SessionKey:
        """Generate a fresh key from the operating system's CSPRNG."""
        account: LocalAccount = Account.create()
        return cls(private_key="0x" + bytes(account.key).hex(), address=account.address)

    @classmethod
    def from_private_key(cls, private_key: str | bytes) -> SessionKey:
        """Load a key from a ``0x``-hex string or 32 raw bytes."""
        account: LocalAccount = Account.from_key(private_key)
        return cls(private_key="0x" + bytes(account.key).hex(), address=account.address)

    @classmethod
    def from_env(cls, variable: str = "AGENTBANK_SESSION_KEY") -> SessionKey:
        """Load a key from an environment variable (populated by your secret manager)."""
        value = os.environ.get(variable)
        if not value:
            raise KeyError(f"Environment variable {variable} is not set")
        return cls.from_private_key(value.strip())

    @property
    def account(self) -> LocalAccount:
        """The key as an ``eth_account`` ``LocalAccount`` (an :class:`EthSigner`)."""
        account: LocalAccount = Account.from_key(self.private_key)
        return account

    def save(self, path: str | os.PathLike[str], *, overwrite: bool = False) -> None:
        """Write the key to ``path`` as JSON, readable only by the current user (0600).

        For production use a secret manager; this is for local development and
        sandbox agents.

        Raises:
            FileExistsError: ``path`` exists and ``overwrite`` is false.
        """
        target = Path(path)
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
        fd = os.open(target, flags, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"address": self.address, "private_key": self.private_key}, handle)
            handle.write("\n")
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> SessionKey:
        """Read a key written by :meth:`save` and check its address.

        Raises:
            ValueError: The stored address does not match the private key.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        key = cls.from_private_key(data["private_key"])
        if str(data.get("address", key.address)).lower() != key.address.lower():
            raise ValueError("Stored address does not match the private key")
        return key


def generate_session_key() -> SessionKey:
    """Generate a session key. Register ``key.address`` as the session ``public_key``."""
    return SessionKey.generate()


def generate_spend_key() -> SessionKey:
    """Generate an x402 spend key.

    Register ``key.address`` as the account's ``spend_key_address`` when creating
    the account, and fund it with a small USDC float.
    """
    return SessionKey.generate()


def to_signer(signer: SignerLike | SessionKey) -> EthSigner:
    """Normalize a signer, :class:`SessionKey` or raw private key into an :class:`EthSigner`."""
    if isinstance(signer, SessionKey):
        return signer.account
    if isinstance(signer, (str, bytes)):
        account: LocalAccount = Account.from_key(signer)
        return account
    return signer


def _hex(signature: bytes) -> str:
    return "0x" + bytes(signature).hex()


def personal_sign_text(signer: EthSigner, message: str) -> bytes:
    """EIP-191 personal-sign a UTF-8 text message; returns the 65-byte signature."""
    return bytes(signer.sign_message(encode_defunct(text=message)).signature)


def personal_sign_hash(signer: EthSigner, hash_hex: str) -> str:
    r"""EIP-191 personal-sign raw 32 bytes (e.g. a user operation hash); returns ``0x`` hex.

    This is what ``signing_request.user_op_hash`` and owner operations expect:
    the *bytes* of the hash are signed (``"\x19Ethereum Signed Message:\n32" || hash``),
    as Safe/Smart Sessions validators verify, not its hex text.
    """
    raw = bytes.fromhex(hash_hex.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError("Expected a 32-byte hash")
    return _hex(signer.sign_message(encode_defunct(primitive=raw)).signature)


def sign_typed_data(signer: EthSigner, typed_data: dict[str, object]) -> str:
    """Sign a full EIP-712 message (``types`` incl. ``EIP712Domain``); returns ``0x`` hex."""
    signable = encode_typed_data(full_message=typed_data)
    return _hex(signer.sign_message(signable).signature)
