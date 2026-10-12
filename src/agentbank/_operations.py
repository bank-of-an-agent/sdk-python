"""Operation table generated from ``openapi.json``. Do not edit by hand.

Regenerate with ``scripts/generate_models.sh``.
API version: 0.1.0.
"""

from __future__ import annotations

from typing import Final

from agentbank._spec import Operation

API_VERSION: Final = "0.1.0"

CREATE_ORG: Final = Operation(
    operation_id="createOrg",
    method="POST",
    path="/v1/orgs",
    auth=("public",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_CURRENT_ORG: Final = Operation(
    operation_id="getCurrentOrg",
    method="GET",
    path="/v1/orgs/me",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

START_KYB: Final = Operation(
    operation_id="startKyb",
    method="POST",
    path="/v1/orgs/me/kyb",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

FREEZE_ORG: Final = Operation(
    operation_id="freezeOrg",
    method="POST",
    path="/v1/orgs/me/freeze",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

UNFREEZE_ORG: Final = Operation(
    operation_id="unfreezeOrg",
    method="POST",
    path="/v1/orgs/me/unfreeze",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CREATE_TREASURY_ACCOUNT: Final = Operation(
    operation_id="createTreasuryAccount",
    method="POST",
    path="/v1/orgs/me/treasury-accounts",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

SET_TREASURY: Final = Operation(
    operation_id="setTreasury",
    method="PUT",
    path="/v1/orgs/me/treasury",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_API_KEYS: Final = Operation(
    operation_id="listApiKeys",
    method="GET",
    path="/v1/api-keys",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_API_KEY: Final = Operation(
    operation_id="createApiKey",
    method="POST",
    path="/v1/api-keys",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

REVOKE_API_KEY: Final = Operation(
    operation_id="revokeApiKey",
    method="DELETE",
    path="/v1/api-keys/{id}",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

LIST_MEMBERS: Final = Operation(
    operation_id="listMembers",
    method="GET",
    path="/v1/members",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_MEMBER: Final = Operation(
    operation_id="createMember",
    method="POST",
    path="/v1/members",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_AGENTS: Final = Operation(
    operation_id="listAgents",
    method="GET",
    path="/v1/agents",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
        "status",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_AGENT: Final = Operation(
    operation_id="createAgent",
    method="POST",
    path="/v1/agents",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_AGENT: Final = Operation(
    operation_id="getAgent",
    method="GET",
    path="/v1/agents/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

FREEZE_AGENT: Final = Operation(
    operation_id="freezeAgent",
    method="POST",
    path="/v1/agents/{id}/freeze",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

UNFREEZE_AGENT: Final = Operation(
    operation_id="unfreezeAgent",
    method="POST",
    path="/v1/agents/{id}/unfreeze",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CREATE_ACCOUNT: Final = Operation(
    operation_id="createAccount",
    method="POST",
    path="/v1/agents/{id}/accounts",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_ACCOUNTS: Final = Operation(
    operation_id="listAccounts",
    method="GET",
    path="/v1/accounts",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
        "agent_id",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

GET_ACCOUNT: Final = Operation(
    operation_id="getAccount",
    method="GET",
    path="/v1/accounts/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

GET_BALANCES: Final = Operation(
    operation_id="getBalances",
    method="GET",
    path="/v1/accounts/{id}/balances",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_SESSION: Final = Operation(
    operation_id="createSession",
    method="POST",
    path="/v1/sessions",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_SESSION: Final = Operation(
    operation_id="getSession",
    method="GET",
    path="/v1/sessions/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

REVOKE_SESSION: Final = Operation(
    operation_id="revokeSession",
    method="DELETE",
    path="/v1/sessions/{id}",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

INSTALL_SESSION: Final = Operation(
    operation_id="installSession",
    method="POST",
    path="/v1/sessions/{id}/install",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

GET_OWNER_OPERATION: Final = Operation(
    operation_id="getOwnerOperation",
    method="GET",
    path="/v1/owner-operations/{id}",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

SUBMIT_OWNER_SIGNATURE: Final = Operation(
    operation_id="submitOwnerSignature",
    method="POST",
    path="/v1/owner-operations/{id}/signature",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CREATE_MANDATE: Final = Operation(
    operation_id="createMandate",
    method="POST",
    path="/v1/mandates",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_MANDATE: Final = Operation(
    operation_id="getMandate",
    method="GET",
    path="/v1/mandates/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

REVOKE_MANDATE: Final = Operation(
    operation_id="revokeMandate",
    method="DELETE",
    path="/v1/mandates/{id}",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

GET_POLICY: Final = Operation(
    operation_id="getPolicy",
    method="GET",
    path="/v1/agents/{id}/policy",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

PUT_POLICY: Final = Operation(
    operation_id="putPolicy",
    method="PUT",
    path="/v1/agents/{id}/policy",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CHECK_POLICY: Final = Operation(
    operation_id="checkPolicy",
    method="POST",
    path="/v1/policy/check",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_PAYMENTS: Final = Operation(
    operation_id="listPayments",
    method="GET",
    path="/v1/payments",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
        "account_id",
        "status",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_PAYMENT: Final = Operation(
    operation_id="createPayment",
    method="POST",
    path="/v1/payments",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_PAYMENT: Final = Operation(
    operation_id="getPayment",
    method="GET",
    path="/v1/payments/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

SUBMIT_PAYMENT_SIGNATURE: Final = Operation(
    operation_id="submitPaymentSignature",
    method="POST",
    path="/v1/payments/{id}/signature",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CANCEL_PAYMENT: Final = Operation(
    operation_id="cancelPayment",
    method="POST",
    path="/v1/payments/{id}/cancel",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_PAYMENT_REQUEST: Final = Operation(
    operation_id="createPaymentRequest",
    method="POST",
    path="/v1/payment-requests",
    auth=(
        "agent",
        "principal",
    ),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_PAYMENT_REQUEST: Final = Operation(
    operation_id="getPaymentRequest",
    method="GET",
    path="/v1/payment-requests/{id}",
    auth=(
        "agent",
        "principal",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

X402_PAY: Final = Operation(
    operation_id="x402Pay",
    method="POST",
    path="/v1/x402/pay",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

X402_VERIFY: Final = Operation(
    operation_id="x402Verify",
    method="POST",
    path="/v1/x402/verify",
    auth=(
        "seller",
        "public",
    ),
    idempotent=False,
    service="facilitator",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

X402_SETTLE: Final = Operation(
    operation_id="x402Settle",
    method="POST",
    path="/v1/x402/settle",
    auth=(
        "seller",
        "public",
    ),
    idempotent=False,
    service="facilitator",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

X402_SUPPORTED: Final = Operation(
    operation_id="x402Supported",
    method="GET",
    path="/v1/x402/supported",
    auth=("public",),
    idempotent=False,
    service="facilitator",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

REGISTER_X402_PAYEE: Final = Operation(
    operation_id="registerX402Payee",
    method="POST",
    path="/v1/x402/payees",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CREATE_ESCROW: Final = Operation(
    operation_id="createEscrow",
    method="POST",
    path="/v1/escrows",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_ESCROW: Final = Operation(
    operation_id="getEscrow",
    method="GET",
    path="/v1/escrows/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

SUBMIT_ESCROW_SIGNATURE: Final = Operation(
    operation_id="submitEscrowSignature",
    method="POST",
    path="/v1/escrows/{id}/signature",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

RELEASE_ESCROW: Final = Operation(
    operation_id="releaseEscrow",
    method="POST",
    path="/v1/escrows/{id}/release",
    auth=(
        "agent",
        "principal",
    ),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

REFUND_ESCROW: Final = Operation(
    operation_id="refundEscrow",
    method="POST",
    path="/v1/escrows/{id}/refund",
    auth=(
        "agent",
        "principal",
    ),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

DISPUTE_ESCROW: Final = Operation(
    operation_id="disputeEscrow",
    method="POST",
    path="/v1/escrows/{id}/dispute",
    auth=(
        "agent",
        "principal",
    ),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CREATE_STREAM: Final = Operation(
    operation_id="createStream",
    method="POST",
    path="/v1/streams",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_STREAM: Final = Operation(
    operation_id="getStream",
    method="GET",
    path="/v1/streams/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

SUBMIT_STREAM_SIGNATURE: Final = Operation(
    operation_id="submitStreamSignature",
    method="POST",
    path="/v1/streams/{id}/signature",
    auth=("agent",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

CANCEL_STREAM: Final = Operation(
    operation_id="cancelStream",
    method="POST",
    path="/v1/streams/{id}/cancel",
    auth=(
        "agent",
        "principal",
    ),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

LIST_APPROVALS: Final = Operation(
    operation_id="listApprovals",
    method="GET",
    path="/v1/approvals",
    auth=(
        "approver",
        "principal",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
        "status",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

GET_APPROVAL: Final = Operation(
    operation_id="getApproval",
    method="GET",
    path="/v1/approvals/{id}",
    auth=(
        "approver",
        "principal",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

DECIDE_APPROVAL: Final = Operation(
    operation_id="decideApproval",
    method="POST",
    path="/v1/approvals/{id}/decide",
    auth=("approver",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_ENTRIES: Final = Operation(
    operation_id="listEntries",
    method="GET",
    path="/v1/accounts/{id}/entries",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(
        "cursor",
        "limit",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

GET_STATEMENT: Final = Operation(
    operation_id="getStatement",
    method="GET",
    path="/v1/statements",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "account_id",
        "period",
        "format",
    ),
    has_body=False,
    response_media_types=(
        "application/json",
        "text/csv",
    ),
)

LIST_VAULTS: Final = Operation(
    operation_id="listVaults",
    method="GET",
    path="/v1/vaults",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
        "account_id",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_VAULT: Final = Operation(
    operation_id="createVault",
    method="POST",
    path="/v1/vaults",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_VAULT: Final = Operation(
    operation_id="getVault",
    method="GET",
    path="/v1/vaults/{id}",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

DEPOSIT_VAULT: Final = Operation(
    operation_id="depositVault",
    method="POST",
    path="/v1/vaults/{id}/deposit",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

WITHDRAW_VAULT: Final = Operation(
    operation_id="withdrawVault",
    method="POST",
    path="/v1/vaults/{id}/withdraw",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_AUTO_TOP_UP: Final = Operation(
    operation_id="getAutoTopUp",
    method="GET",
    path="/v1/agents/{id}/auto-topup",
    auth=(
        "principal",
        "agent",
    ),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

PUT_AUTO_TOP_UP: Final = Operation(
    operation_id="putAutoTopUp",
    method="PUT",
    path="/v1/agents/{id}/auto-topup",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_FUNDS: Final = Operation(
    operation_id="listFunds",
    method="GET",
    path="/v1/funds",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

PUT_SWEEP_RULE: Final = Operation(
    operation_id="putSweepRule",
    method="PUT",
    path="/v1/accounts/{id}/sweep-rule",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

LIST_WEBHOOK_ENDPOINTS: Final = Operation(
    operation_id="listWebhookEndpoints",
    method="GET",
    path="/v1/webhook-endpoints",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

CREATE_WEBHOOK_ENDPOINT: Final = Operation(
    operation_id="createWebhookEndpoint",
    method="POST",
    path="/v1/webhook-endpoints",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=201,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

DELETE_WEBHOOK_ENDPOINT: Final = Operation(
    operation_id="deleteWebhookEndpoint",
    method="DELETE",
    path="/v1/webhook-endpoints/{id}",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=("id",),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

LIST_EVENTS: Final = Operation(
    operation_id="listEvents",
    method="GET",
    path="/v1/events",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(
        "cursor",
        "limit",
        "type",
    ),
    has_body=False,
    response_media_types=("application/json",),
)

LIST_PLANS: Final = Operation(
    operation_id="listPlans",
    method="GET",
    path="/v1/billing/plans",
    auth=("public",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

GET_SUBSCRIPTION: Final = Operation(
    operation_id="getSubscription",
    method="GET",
    path="/v1/billing/subscription",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

CHANGE_PLAN: Final = Operation(
    operation_id="changePlan",
    method="PUT",
    path="/v1/billing/subscription",
    auth=("principal",),
    idempotent=True,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=True,
    response_media_types=("application/json",),
)

GET_FEES: Final = Operation(
    operation_id="getFees",
    method="GET",
    path="/v1/billing/fees",
    auth=("principal",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=("period",),
    has_body=False,
    response_media_types=("application/json",),
)

GET_REVENUE_REPORT: Final = Operation(
    operation_id="getRevenueReport",
    method="GET",
    path="/v1/admin/revenue",
    auth=("staff",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=("period",),
    has_body=False,
    response_media_types=("application/json",),
)

HEALTH: Final = Operation(
    operation_id="health",
    method="GET",
    path="/healthz",
    auth=("public",),
    idempotent=False,
    service="api",
    success_status=200,
    path_params=(),
    query_params=(),
    has_body=False,
    response_media_types=("application/json",),
)

OPERATIONS: Final[dict[str, Operation]] = {
    "createOrg": CREATE_ORG,
    "getCurrentOrg": GET_CURRENT_ORG,
    "startKyb": START_KYB,
    "freezeOrg": FREEZE_ORG,
    "unfreezeOrg": UNFREEZE_ORG,
    "createTreasuryAccount": CREATE_TREASURY_ACCOUNT,
    "setTreasury": SET_TREASURY,
    "listApiKeys": LIST_API_KEYS,
    "createApiKey": CREATE_API_KEY,
    "revokeApiKey": REVOKE_API_KEY,
    "listMembers": LIST_MEMBERS,
    "createMember": CREATE_MEMBER,
    "listAgents": LIST_AGENTS,
    "createAgent": CREATE_AGENT,
    "getAgent": GET_AGENT,
    "freezeAgent": FREEZE_AGENT,
    "unfreezeAgent": UNFREEZE_AGENT,
    "createAccount": CREATE_ACCOUNT,
    "listAccounts": LIST_ACCOUNTS,
    "getAccount": GET_ACCOUNT,
    "getBalances": GET_BALANCES,
    "createSession": CREATE_SESSION,
    "getSession": GET_SESSION,
    "revokeSession": REVOKE_SESSION,
    "installSession": INSTALL_SESSION,
    "getOwnerOperation": GET_OWNER_OPERATION,
    "submitOwnerSignature": SUBMIT_OWNER_SIGNATURE,
    "createMandate": CREATE_MANDATE,
    "getMandate": GET_MANDATE,
    "revokeMandate": REVOKE_MANDATE,
    "getPolicy": GET_POLICY,
    "putPolicy": PUT_POLICY,
    "checkPolicy": CHECK_POLICY,
    "listPayments": LIST_PAYMENTS,
    "createPayment": CREATE_PAYMENT,
    "getPayment": GET_PAYMENT,
    "submitPaymentSignature": SUBMIT_PAYMENT_SIGNATURE,
    "cancelPayment": CANCEL_PAYMENT,
    "createPaymentRequest": CREATE_PAYMENT_REQUEST,
    "getPaymentRequest": GET_PAYMENT_REQUEST,
    "x402Pay": X402_PAY,
    "x402Verify": X402_VERIFY,
    "x402Settle": X402_SETTLE,
    "x402Supported": X402_SUPPORTED,
    "registerX402Payee": REGISTER_X402_PAYEE,
    "createEscrow": CREATE_ESCROW,
    "getEscrow": GET_ESCROW,
    "submitEscrowSignature": SUBMIT_ESCROW_SIGNATURE,
    "releaseEscrow": RELEASE_ESCROW,
    "refundEscrow": REFUND_ESCROW,
    "disputeEscrow": DISPUTE_ESCROW,
    "createStream": CREATE_STREAM,
    "getStream": GET_STREAM,
    "submitStreamSignature": SUBMIT_STREAM_SIGNATURE,
    "cancelStream": CANCEL_STREAM,
    "listApprovals": LIST_APPROVALS,
    "getApproval": GET_APPROVAL,
    "decideApproval": DECIDE_APPROVAL,
    "listEntries": LIST_ENTRIES,
    "getStatement": GET_STATEMENT,
    "listVaults": LIST_VAULTS,
    "createVault": CREATE_VAULT,
    "getVault": GET_VAULT,
    "depositVault": DEPOSIT_VAULT,
    "withdrawVault": WITHDRAW_VAULT,
    "getAutoTopUp": GET_AUTO_TOP_UP,
    "putAutoTopUp": PUT_AUTO_TOP_UP,
    "listFunds": LIST_FUNDS,
    "putSweepRule": PUT_SWEEP_RULE,
    "listWebhookEndpoints": LIST_WEBHOOK_ENDPOINTS,
    "createWebhookEndpoint": CREATE_WEBHOOK_ENDPOINT,
    "deleteWebhookEndpoint": DELETE_WEBHOOK_ENDPOINT,
    "listEvents": LIST_EVENTS,
    "listPlans": LIST_PLANS,
    "getSubscription": GET_SUBSCRIPTION,
    "changePlan": CHANGE_PLAN,
    "getFees": GET_FEES,
    "getRevenueReport": GET_REVENUE_REPORT,
    "health": HEALTH,
}
"""Every operation in the API, keyed by ``operationId``."""
