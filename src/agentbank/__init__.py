"""Python SDK for Agent Bank: non-custodial, programmable bank accounts for AI agents.

Testnet only (Base Sepolia). Quick tour::

    from agentbank import AgentBank, generate_session_key

    # Principal (org API key): manage agents, accounts, sessions and policies.
    bank = AgentBank(api_key="abk_test_...")
    agent = bank.agents.create(name="research-agent")

    # Agent (session key): pay, check balances, pay x402 resources.
    agent_bank = AgentBank(session_id="ses_...", session_key="0x...", account_id="acct_...")
    payment = agent_bank.pay(to="0x...", amount="12.50", memo="dataset")

Everything is also available asynchronously via :class:`AsyncAgentBank`.
"""

from agentbank import models, owner_payloads
from agentbank._async.client import AsyncAgentBank
from agentbank._async.x402 import AsyncX402Transport
from agentbank._base_client import RequestOptions
from agentbank._sync.client import AgentBank
from agentbank._sync.x402 import X402Transport
from agentbank._version import __version__
from agentbank.canonical import canonical_json, canonical_keccak, canonical_sha256
from agentbank.chains import BASE_SEPOLIA, assert_testnet
from agentbank.eip712 import (
    OWNER_ACTIONS,
    OwnerAction,
    owner_authorization_typed_data,
    owner_authorize,
    verify_owner_authorization,
)
from agentbank.errors import (
    AgentBankError,
    APIConnectionError,
    APIResponseValidationError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    ConfigurationError,
    ConflictError,
    FrozenError,
    IdempotencyConflictError,
    InsufficientFundsError,
    InternalServerError,
    MainnetLockedError,
    NotFoundError,
    OwnerSignatureRequiredError,
    PaymentDeniedError,
    PaymentError,
    PaymentFailedError,
    PermissionDeniedError,
    PolicyDeniedError,
    RateLimitError,
    ServiceUnavailableError,
    SignatureVerificationError,
    UnprocessableEntityError,
    X402Error,
)
from agentbank.http_signatures import content_digest, sign_request, verify_request
from agentbank.keys import EthSigner, SessionKey, generate_session_key, generate_spend_key
from agentbank.money import format_amount, money, parse_amount
from agentbank.webhooks import WebhookEvent, construct_event, sign_webhook, verify_webhook
from agentbank.x402 import X402Receipt, x402_receipt

__all__ = [
    "BASE_SEPOLIA",
    "OWNER_ACTIONS",
    "APIConnectionError",
    "APIResponseValidationError",
    "APITimeoutError",
    "AgentBank",
    "AgentBankError",
    "AsyncAgentBank",
    "AsyncX402Transport",
    "AuthenticationError",
    "BadRequestError",
    "ConfigurationError",
    "ConflictError",
    "EthSigner",
    "FrozenError",
    "IdempotencyConflictError",
    "InsufficientFundsError",
    "InternalServerError",
    "MainnetLockedError",
    "NotFoundError",
    "OwnerAction",
    "OwnerSignatureRequiredError",
    "PaymentDeniedError",
    "PaymentError",
    "PaymentFailedError",
    "PermissionDeniedError",
    "PolicyDeniedError",
    "RateLimitError",
    "RequestOptions",
    "ServiceUnavailableError",
    "SessionKey",
    "SignatureVerificationError",
    "UnprocessableEntityError",
    "WebhookEvent",
    "X402Error",
    "X402Receipt",
    "X402Transport",
    "__version__",
    "assert_testnet",
    "canonical_json",
    "canonical_keccak",
    "canonical_sha256",
    "construct_event",
    "content_digest",
    "format_amount",
    "generate_session_key",
    "generate_spend_key",
    "models",
    "money",
    "owner_authorization_typed_data",
    "owner_authorize",
    "owner_payloads",
    "parse_amount",
    "sign_request",
    "sign_webhook",
    "verify_owner_authorization",
    "verify_request",
    "verify_webhook",
    "x402_receipt",
]
