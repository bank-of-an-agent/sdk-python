"""Pydantic v2 models for the Agent Bank REST API.

Generated from ``openapi.json`` by ``scripts/generate_models.sh``; do not edit
by hand. API version: 0.1.0.

Money amounts are decimal strings (``str``), never floats; timestamps are
timezone-aware datetimes.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from agentbank._models_base import AgentBankModel
from pydantic import AwareDatetime, ConfigDict, Field
from typing_extensions import TypeAliasType


class Money(AgentBankModel):
    """
    An amount of an asset. Amount is a decimal string.
    """

    amount: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    asset: Literal["USDC"]
    """
    Asset code. USDC only in v1.
    """


class OwnerAuthorization(AgentBankModel):
    """
    EIP-712 OwnerAuthorization signature by the org owner key over the canonical request payload. Required for loosening changes and session installs.
    """

    signer: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    Owner key address that produced the signature
    """
    signature: Annotated[str, Field(pattern="^0x([a-fA-F0-9]{2})*$")]
    issued_at: Annotated[int, Field(ge=0, le=9007199254740991)]
    """
    Unix seconds
    """
    expires_at: Annotated[int, Field(gt=0, le=9007199254740991)]
    """
    Unix seconds
    """


MinorUnitsInt = TypeAliasType(
    "MinorUnitsInt",
    Annotated[int, Field(ge=0, le=9007199254740991, title="MinorUnitsInt")],
)


MinorUnitsString = TypeAliasType(
    "MinorUnitsString",
    Annotated[str, Field(pattern="^(0|[1-9][0-9]{0,18})$", title="MinorUnitsString")],
)


class AmountRangeConstraint(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["payment.amount_range"]
    currency: Literal["USD", "USDC"]
    max: MinorUnitsInt | MinorUnitsString
    min: MinorUnitsInt | MinorUnitsString | None = None


class MandatePayee(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[str, Field(min_length=1)]
    """
    Address, Agent Bank agent id (agt_…), ERC-8004 id or x402 domain
    """
    name: Annotated[str, Field(min_length=1)]
    website: str | None = None


class AllowedPayeesConstraint(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["payment.allowed_payees"]
    allowed: Annotated[list[MandatePayee], Field(max_length=1000, min_length=1)]


class BudgetConstraint(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["payment.budget"]
    currency: Literal["USD", "USDC"]
    max: MinorUnitsInt | MinorUnitsString


class RecurrenceConstraint(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["payment.agent_recurrence"]
    frequency: Literal[
        "ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"
    ]
    max_occurrences: Annotated[int | None, Field(gt=0, le=9007199254740991)] = None


class ExecutionDateConstraint(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["payment.execution_date"]
    not_before: AwareDatetime | None = None
    not_after: AwareDatetime | None = None


Hostname = TypeAliasType(
    "Hostname",
    Annotated[
        str,
        Field(
            max_length=253,
            min_length=1,
            pattern="^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*$",
            title="Hostname",
        ),
    ],
)
"""
Lowercase hostname, e.g. api.example-data.com
"""


class X402DomainsConstraint(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["agentbank.x402_domains"]
    allowed: Annotated[list[Hostname], Field(max_length=1000, min_length=1)]


class Secp256k1Jwk(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kty: Literal["EC"]
    crv: Literal["secp256k1"]
    x: Annotated[str, Field(min_length=1)]
    y: Annotated[str, Field(min_length=1)]


class JwkKeyBinding(AgentBankModel):
    """
    Key the mandate is bound to (the agent's session key). Optional in v1.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    jwk: Annotated[Secp256k1Jwk, Field(title="Secp256k1Jwk")]


class EthAddressKeyBinding(AgentBankModel):
    """
    Key the mandate is bound to (the agent's session key). Optional in v1.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    eth_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """


class OpenPaymentMandate(AgentBankModel):
    """
    AP2 v0.2 open Payment Mandate (Agent Bank profile).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    vct: Literal["mandate.payment.open.1"]
    constraints: Annotated[
        list[
            AmountRangeConstraint
            | AllowedPayeesConstraint
            | BudgetConstraint
            | RecurrenceConstraint
            | ExecutionDateConstraint
            | X402DomainsConstraint
        ],
        Field(max_length=50, min_length=1),
    ]
    cnf: JwkKeyBinding | EthAddressKeyBinding | None = None
    """
    Key the mandate is bound to (the agent's session key). Optional in v1.
    """
    iat: Annotated[int, Field(ge=0, le=9007199254740991)]
    exp: Annotated[int, Field(gt=0, le=9007199254740991)]
    agent_id: Annotated[str, Field(min_length=1)]
    """
    Agent Bank extension: agent the mandate is granted to
    """
    description: Annotated[str | None, Field(max_length=2000)] = None
    """
    Agent Bank extension: natural-language intent shown to the principal
    """


class PolicyLimits(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    per_tx: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    per_day: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    per_week: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    per_month: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """


Address = TypeAliasType(
    "Address",
    Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ],
)
"""
EVM address
"""


AgentId = TypeAliasType("AgentId", Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")])


Erc8004Id = TypeAliasType("Erc8004Id", Annotated[str, Field(pattern="^[\\x21-\\x7E]{1,200}$")])


class CounterpartyDenyList(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    addresses: Annotated[list[Address] | None, Field(max_length=1000)] = None
    agent_ids: Annotated[list[AgentId] | None, Field(max_length=1000)] = None
    erc8004_ids: Annotated[list[Erc8004Id] | None, Field(max_length=1000)] = None
    x402_domains: Annotated[list[Hostname] | None, Field(max_length=1000)] = None


class CounterpartyMatch(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
        regex_engine="python-re",
    )
    address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    EVM address
    """
    agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")] = None
    erc8004_id: Annotated[str | None, Field(pattern="^[\\x21-\\x7E]{1,200}$")] = None
    x402_domain: Annotated[
        str | None,
        Field(
            max_length=253,
            min_length=1,
            pattern="^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*$",
        ),
    ] = None
    """
    Lowercase hostname, e.g. api.example-data.com
    """


class CounterpartyCap(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    match: Annotated[CounterpartyMatch, Field(title="CounterpartyMatch")]
    per_tx: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    per_day: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    per_month: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """


class PolicyCounterparties(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mode: Literal["open", "allowlist", "denylist"] = "open"
    addresses: Annotated[list[Address] | None, Field(max_length=1000)] = None
    agent_ids: Annotated[list[AgentId] | None, Field(max_length=1000)] = None
    erc8004_ids: Annotated[list[Erc8004Id] | None, Field(max_length=1000)] = None
    x402_domains: Annotated[list[Hostname] | None, Field(max_length=1000)] = None
    deny: Annotated[CounterpartyDenyList | None, Field(title="CounterpartyDenyList")] = None
    new_cooldown_minutes: Annotated[int | None, Field(ge=0, le=10080)] = None
    caps: Annotated[list[CounterpartyCap] | None, Field(max_length=100)] = None


class PolicyVelocity(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_per_minute: Annotated[int | None, Field(ge=1, le=9007199254740991)] = None
    max_per_hour: Annotated[int | None, Field(ge=1, le=9007199254740991)] = None
    max_per_day: Annotated[int | None, Field(ge=1, le=9007199254740991)] = None


class TimeWindow(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    days: Annotated[
        list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]],
        Field(min_length=1),
    ]
    start: Annotated[str, Field(pattern="^([01][0-9]|2[0-3]):[0-5][0-9]$")]
    end: Annotated[str, Field(pattern="^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$")]
    timezone: Annotated[str, Field(min_length=1)] = "UTC"


class ApprovalThreshold(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    above: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    approvers: Annotated[int, Field(ge=1, le=5)]


class IncomeSplit(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bps: Annotated[int, Field(ge=1, le=10000)]
    to: Annotated[str, Field(pattern="^(treasury|vault:vlt_[0-9A-HJKMNP-TV-Z]{26})$")]


class ExcessSweep(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    to: Annotated[str, Field(pattern="^(treasury|vault:vlt_[0-9A-HJKMNP-TV-Z]{26})$")]


class RoundUp(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    to_nearest: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    to: Annotated[str, Field(pattern="^(treasury|vault:vlt_[0-9A-HJKMNP-TV-Z]{26})$")]


class ScheduledSave(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    every: Literal["day", "week", "month"]
    to: Annotated[str, Field(pattern="^(treasury|vault:vlt_[0-9A-HJKMNP-TV-Z]{26})$")]


class AutoSave(AgentBankModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    income_split: Annotated[IncomeSplit | None, Field(title="IncomeSplit")] = None
    excess_sweep: Annotated[ExcessSweep | None, Field(title="ExcessSweep")] = None
    round_up: Annotated[RoundUp | None, Field(title="RoundUp")] = None
    scheduled: Annotated[list[ScheduledSave] | None, Field(max_length=10)] = None


class PolicyDocument(AgentBankModel):
    """
    Owner-defined spending rules for one agent. Tightening applies immediately; loosening requires an owner signature and a 1-hour delay.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    field_schema: Annotated[Literal["agentbank.policy.v1"] | None, Field(alias="$schema")] = None
    agent: str | None = None
    """
    Agent id; must match the path when present
    """
    asset: Literal["USDC"] = "USDC"
    """
    Asset code. USDC only in v1.
    """
    limits: Annotated[
        PolicyLimits,
        Field(title="PolicyLimits", default_factory=lambda: PolicyLimits.model_validate({})),
    ]
    counterparties: Annotated[
        PolicyCounterparties,
        Field(
            title="PolicyCounterparties",
            default_factory=lambda: PolicyCounterparties.model_validate({"mode": "open"}),
        ),
    ]
    velocity: Annotated[PolicyVelocity | None, Field(title="PolicyVelocity")] = None
    time_windows: Annotated[list[TimeWindow] | None, Field(max_length=20, min_length=1)] = None
    max_balance: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    approvals: Annotated[list[ApprovalThreshold] | None, Field(max_length=5)] = None
    require_owner_above: Annotated[
        str | None,
        Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ] = None
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    allowed_kinds: Annotated[
        list[Literal["transfer", "x402", "escrow", "stream", "payout", "refill"]] | None,
        Field(min_length=1),
    ] = None
    auto_save: Annotated[AutoSave | None, Field(title="AutoSave")] = None


class RuleHit(AgentBankModel):
    rule: str
    """
    Rule identifier, e.g. "limits.per_day"
    """
    effect: Literal["allow", "deny", "require_approval", "require_owner", "info"]
    detail: str


class PolicyDecision(AgentBankModel):
    """
    Deterministic decision of the policy engine.
    """

    id: str | None = None
    outcome: Literal["allow", "deny", "require_approval", "require_owner"]
    rule_hits: list[RuleHit]
    approvers_required: Annotated[int, Field(ge=0, le=9007199254740991)]
    policy_version: Annotated[int, Field(ge=0, le=9007199254740991)]
    evaluated_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    retry_at: AwareDatetime | None = None
    """
    When a time-based denial (cooling period, time window) lifts
    """


AllowedRecipient = TypeAliasType(
    "AllowedRecipient",
    Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ],
)
"""
EVM address
"""


AllowedContract = TypeAliasType(
    "AllowedContract",
    Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ],
)
"""
EVM address
"""


class SessionScope(AgentBankModel):
    """
    On-chain enforced scope of a session key.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    asset: Literal["USDC"] = "USDC"
    """
    Asset code. USDC only in v1.
    """
    max_per_tx: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    max_per_day: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    allowed_recipients: Annotated[list[AllowedRecipient] | None, Field(max_length=100)] = None
    allowed_contracts: Annotated[list[AllowedContract] | None, Field(max_length=20)] = None
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class Org(AgentBankModel):
    """
    A verified principal (human or company) that owns agents.
    """

    id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["org"]
    legal_name: str
    kind: Literal["individual", "company"]
    country: Annotated[str, Field(max_length=2, min_length=2)]
    kyc_status: Literal["pending", "in_review", "approved", "rejected"]
    tier: Literal["free", "pro", "business", "enterprise"]
    status: Literal["active", "frozen"]
    owner_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    The principal's owner key. Can always exit; never held by Agent Bank.
    """
    treasury_account_id: Annotated[str | None, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateOrgRequest(AgentBankModel):
    legal_name: Annotated[str, Field(max_length=200, min_length=1)]
    kind: Literal["individual", "company"]
    country: Annotated[str, Field(max_length=2, min_length=2)]
    contact_email: str
    owner_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """


class ApiKey(AgentBankModel):
    id: Annotated[str, Field(pattern="^key_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["api_key"]
    name: str
    prefix: str
    """
    First characters of the key, for display
    """
    scopes: list[str]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    revoked_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """


class ApiKeyWithSecret(AgentBankModel):
    id: Annotated[str, Field(pattern="^key_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["api_key"]
    name: str
    prefix: str
    """
    First characters of the key, for display
    """
    scopes: list[str]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    revoked_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """
    secret: str
    """
    Shown once. Store it in your secret manager.
    """


class CreateOrgResponse(AgentBankModel):
    org: Org
    api_key: ApiKeyWithSecret


class CreateApiKeyRequest(AgentBankModel):
    name: Annotated[str, Field(max_length=100, min_length=1)]
    scopes: Annotated[
        list[
            Literal[
                "admin",
                "agents:write",
                "payments:read",
                "approvals:decide",
                "ledger:read",
                "webhooks:write",
            ]
        ],
        Field(min_length=1),
    ] = ["admin"]


class KybSession(AgentBankModel):
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    provider: str
    status: Literal["pending", "in_review", "approved", "rejected"]
    verification_url: str | None


class FreezeRequest(AgentBankModel):
    reason: Annotated[str, Field(max_length=500, min_length=1)]


class UnfreezeRequest(AgentBankModel):
    """
    Unfreezing is a loosening change: owner signature plus 1-hour delay.
    """

    reason: Annotated[str, Field(max_length=500, min_length=1)]
    owner_authorization: OwnerAuthorization


class SetTreasuryRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    owner_authorization: OwnerAuthorization


class Member(AgentBankModel):
    id: Annotated[str, Field(pattern="^mem_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["member"]
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    email: str
    role: Literal["admin", "approver", "viewer"]
    passkey_count: Annotated[int, Field(ge=0, le=9007199254740991)]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateMemberRequest(AgentBankModel):
    email: str
    role: Literal["admin", "approver", "viewer"]


MetadataAdditionalProperty = TypeAliasType(
    "MetadataAdditionalProperty", Annotated[str, Field(max_length=500)]
)


class Agent(AgentBankModel):
    """
    A software identity acting for a principal.
    """

    id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["agent"]
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    name: str
    description: str | None
    did: str | None
    """
    did:pkh of the agent's primary account once created
    """
    erc8004_id: str | None
    agent_card_url: str | None
    status: Literal["active", "frozen"]
    frozen_reason: str | None
    pending_unfreeze_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """
    metadata: dict[str, MetadataAdditionalProperty]
    """
    Up to 20 string key/value pairs for your own references.
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateAgentRequest(AgentBankModel):
    name: Annotated[str, Field(max_length=100, min_length=1)]
    description: Annotated[str | None, Field(max_length=1000)] = None
    erc8004_id: Annotated[str | None, Field(max_length=200)] = None
    agent_card_url: str | None = None
    metadata: dict[str, MetadataAdditionalProperty] | None = None
    """
    Up to 20 string key/value pairs for your own references.
    """


class Account(AgentBankModel):
    """
    One ERC-7579 smart account per agent per chain.
    """

    id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["account"]
    agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    """
    Null for an org treasury account
    """
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    role: Literal["agent", "treasury"]
    chain: Literal["base-sepolia", "anvil", "simulated"]
    chain_id: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    Counterfactual (CREATE2) smart account address; can receive funds before deployment
    """
    deployed: bool
    owner_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    spend_key_address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    Per-agent x402 spend key holding a small float (see ADR 0001)
    """
    module_versions: dict[str, str]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateAccountRequest(AgentBankModel):
    chain: Literal["base-sepolia", "anvil", "simulated"] = "base-sepolia"
    spend_key_address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    Address of the agent's x402 spend key, generated client-side by the SDK
    """


class CreateTreasuryAccountRequest(AgentBankModel):
    chain: Literal["base-sepolia", "anvil", "simulated"] = "base-sepolia"


class VaultBalance(AgentBankModel):
    vault_id: Annotated[str, Field(pattern="^vlt_[0-9A-HJKMNP-TV-Z]{26}$")]
    name: str
    balance: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """


class Balances(AgentBankModel):
    object: Literal["balances"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    asset: Literal["USDC"]
    """
    Asset code. USDC only in v1.
    """
    available: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Spendable now (operating pocket)
    """
    reserved: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Held for pending payments
    """
    escrow: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Locked in escrow contracts
    """
    fees: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Fees accrued and owed
    """
    savings: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Goal and locked vaults
    """
    spend_float: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Float held by the x402 spend key
    """
    vaults: list[VaultBalance]
    total: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    as_of: AwareDatetime
    """
    ISO 8601 timestamp
    """


class OwnerOperation(AgentBankModel):
    """
    An on-chain operation only the principal's owner key can authorize (installing a session, configuring executors, early vault withdrawal). Agent Bank cannot sign it.
    """

    id: Annotated[str, Field(pattern="^oop_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["owner_operation"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    purpose: Literal[
        "session.install",
        "session.revoke",
        "topup.configure",
        "sweep.configure",
        "vault.withdraw",
        "payment",
        "account.deploy",
    ]
    subject_id: str
    """
    The session, payment, vault or rule this operation applies to
    """
    status: Literal["requires_signature", "submitted", "succeeded", "failed", "expired"]
    user_op_hash: Annotated[str, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    """
    Sign the raw 32 bytes of this hash with the owner key (EIP-191 personal sign)
    """
    chain_id: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    tx_hash: Annotated[str | None, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class SubmitOwnerSignatureRequest(AgentBankModel):
    signature: Annotated[str, Field(pattern="^0x([a-fA-F0-9]{2})*$")]
    """
    Owner key signature over user_op_hash
    """


class Session(AgentBankModel):
    """
    A short-lived, scoped agent key. Useless without the co-signer.
    """

    id: Annotated[str, Field(pattern="^ses_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["session"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    public_key: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    Session key address (secp256k1), generated client-side
    """
    scope: SessionScope
    status: Literal["pending_install", "active", "expired", "revoked"]
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    revoked_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """
    onchain_tx: Annotated[str | None, Field(pattern="^0x([a-fA-F0-9]{2})*$")]
    install_operation_id: Annotated[str | None, Field(pattern="^oop_[0-9A-HJKMNP-TV-Z]{26}$")]
    """
    Owner operation that installs the session on-chain (Smart Sessions)
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateSessionRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    public_key: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    scope: SessionScope
    owner_authorization: OwnerAuthorization
    """
    OwnerAuthorization with action "session.grant" over {account_id, public_key, scope}
    """


class Mandate(AgentBankModel):
    """
    An AP2 open Payment Mandate signed by the principal.
    """

    id: Annotated[str, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["mandate"]
    agent_id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    signer: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    mandate: OpenPaymentMandate
    status: Literal["active", "expired", "revoked"]
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    spent: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Cumulative spend under this mandate (for payment.budget)
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateMandateRequest(AgentBankModel):
    agent_id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    mandate: OpenPaymentMandate
    owner_authorization: OwnerAuthorization
    """
    OwnerAuthorization with action "mandate.issue" over the mandate object
    """


class PolicyVersion(AgentBankModel):
    id: Annotated[str, Field(pattern="^pol_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["policy"]
    agent_id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    version: Annotated[int, Field(gt=0, le=9007199254740991)]
    rules: PolicyDocument
    change_kind: Literal["initial", "tighten", "loosen", "mixed", "unchanged"]
    effective_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    signed_by: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class AgentPolicy(AgentBankModel):
    object: Literal["agent_policy"]
    agent_id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    current: PolicyVersion | None
    pending: PolicyVersion | None
    """
    A loosening change waiting out its 1-hour delay
    """


class PutPolicyRequest(AgentBankModel):
    policy: PolicyDocument
    owner_authorization: OwnerAuthorization | None = None
    """
    Required when the change loosens any rule: action "policy.loosen" over the policy document
    """


class PaymentIntent(AgentBankModel):
    """
    What a payment would do, for dry-run policy checks.
    """

    model_config = ConfigDict(
        regex_engine="python-re",
    )
    kind: Literal["transfer", "x402", "escrow", "stream", "payout", "refill"] = "transfer"
    amount: Money
    to_address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    EVM address
    """
    to_agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")] = None
    erc8004_id: str | None = None
    x402_domain: Annotated[
        str | None,
        Field(
            max_length=253,
            min_length=1,
            pattern="^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*$",
        ),
    ] = None
    """
    Lowercase hostname, e.g. api.example-data.com
    """
    contract: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    Contract the payment interacts with (escrow, streams), for session allowed_contracts
    """
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")] = None


class PolicyCheckRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    intent: PaymentIntent


class Counterparty(AgentBankModel):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    type: Literal["address", "agent", "x402", "escrow", "stream"]
    address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    x402_domain: Annotated[
        str | None,
        Field(
            max_length=253,
            min_length=1,
            pattern="^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*$",
        ),
    ]
    """
    Lowercase hostname, e.g. api.example-data.com
    """


class SigningRequest(AgentBankModel):
    """
    What the agent's session key must sign to submit the operation.
    """

    session_id: Annotated[str | None, Field(pattern="^ses_[0-9A-HJKMNP-TV-Z]{26}$")]
    user_op_hash: Annotated[str, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    """
    Sign the raw 32 bytes of this hash with the session key (EIP-191 personal sign)
    """
    chain_id: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class Payment(AgentBankModel):
    id: Annotated[str, Field(pattern="^pay_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["payment"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    kind: Literal["transfer", "x402", "escrow", "stream", "payout", "refill"]
    status: Literal[
        "requires_approval",
        "requires_signature",
        "submitted",
        "settled",
        "denied",
        "failed",
        "canceled",
        "expired",
    ]
    amount: Money
    fee: Money
    counterparty: Counterparty
    memo: str | None
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")]
    payment_request_id: Annotated[str | None, Field(pattern="^preq_[0-9A-HJKMNP-TV-Z]{26}$")]
    decision: PolicyDecision | None
    approval_id: Annotated[str | None, Field(pattern="^apr_[0-9A-HJKMNP-TV-Z]{26}$")]
    signing_request: SigningRequest | None
    owner_operation_id: Annotated[str | None, Field(pattern="^oop_[0-9A-HJKMNP-TV-Z]{26}$")]
    """
    Set when policy requires the owner key to sign this payment itself
    """
    user_op_hash: Annotated[str | None, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    tx_hash: Annotated[str | None, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    failure_reason: str | None
    metadata: dict[str, MetadataAdditionalProperty]
    """
    Up to 20 string key/value pairs for your own references.
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    updated_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    settled_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """


class PaymentDestination(AgentBankModel):
    address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    EVM address
    """
    agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")] = None
    account_id: Annotated[str | None, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")] = None


class CreatePaymentRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    amount: Money
    to: Annotated[PaymentDestination, Field(title="PaymentDestination")]
    memo: Annotated[str | None, Field(max_length=500)] = None
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")] = None
    payment_request_id: Annotated[str | None, Field(pattern="^preq_[0-9A-HJKMNP-TV-Z]{26}$")] = None
    metadata: dict[str, MetadataAdditionalProperty] | None = None
    """
    Up to 20 string key/value pairs for your own references.
    """


class SubmitSignatureRequest(AgentBankModel):
    session_id: Annotated[str, Field(pattern="^ses_[0-9A-HJKMNP-TV-Z]{26}$")]
    signature: Annotated[str, Field(pattern="^0x([a-fA-F0-9]{2})*$")]
    """
    Session key signature over signing_request.user_op_hash
    """


class PaymentRequest(AgentBankModel):
    """
    A request for another agent or a human to pay.
    """

    id: Annotated[str, Field(pattern="^preq_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["payment_request"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    pay_to: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    amount: Money
    memo: str | None
    reference: str | None
    status: Literal["open", "paid", "expired", "canceled"]
    pay_link: str
    paid_by_payment_id: Annotated[str | None, Field(pattern="^pay_[0-9A-HJKMNP-TV-Z]{26}$")]
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreatePaymentRequestRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    amount: Money
    memo: Annotated[str | None, Field(max_length=500)] = None
    reference: Annotated[str | None, Field(max_length=200)] = None
    expires_in_seconds: Annotated[int, Field(ge=60, le=2592000)] = 604800


class X402PaymentRequirements(AgentBankModel):
    """
    x402 v2 PaymentRequirements
    """

    scheme: str
    network: str
    """
    CAIP-2 network, e.g. "eip155:84532"
    """
    asset: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    amount: Annotated[str, Field(pattern="^[0-9]+$")]
    """
    Atomic token units
    """
    payTo: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    maxTimeoutSeconds: Annotated[int, Field(gt=0, le=9007199254740991)]
    extra: dict[str, Any] = {}


class X402ResourceInfo(AgentBankModel):
    model_config = ConfigDict(
        extra="allow",
    )
    url: str
    description: str | None = None
    mimeType: str | None = None


class X402PaymentPayload(AgentBankModel):
    """
    x402 v2 PaymentPayload
    """

    x402Version: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    resource: X402ResourceInfo | None = None
    accepted: X402PaymentRequirements
    payload: dict[str, Any]
    extensions: dict[str, Any] | None = None


class Eip3009Authorization(AgentBankModel):
    from_: Annotated[
        str,
        Field(
            alias="from",
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    to: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    value: Annotated[str, Field(pattern="^[0-9]+$")]
    validAfter: Annotated[str, Field(pattern="^[0-9]+$")]
    validBefore: Annotated[str, Field(pattern="^[0-9]+$")]
    nonce: Annotated[str, Field(pattern="^0x[a-fA-F0-9]{64}$")]


class X402PayRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    resource: X402ResourceInfo
    requirements: X402PaymentRequirements
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")] = None


class Eip712Domain(AgentBankModel):
    name: str
    version: str
    chainId: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    verifyingContract: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """


class X402PayResponse(AgentBankModel):
    object: Literal["x402_authorization"]
    payment: Payment
    authorization: Eip3009Authorization | None
    """
    When status is requires_signature: sign this EIP-3009 authorization with the spend key
    """
    eip712_domain: Eip712Domain | None


class X402VerifyRequest(AgentBankModel):
    x402Version: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    paymentPayload: X402PaymentPayload
    paymentRequirements: X402PaymentRequirements


class X402VerifyResponse(AgentBankModel):
    isValid: bool
    invalidReason: str | None = None
    invalidMessage: str | None = None
    payer: str | None = None


class X402SettleResponse(AgentBankModel):
    success: bool
    errorReason: str | None = None
    errorMessage: str | None = None
    payer: str | None = None
    transaction: str
    network: str
    amount: str | None = None


class X402SupportedKind(AgentBankModel):
    x402Version: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    scheme: str
    network: str
    extra: dict[str, Any] | None = None


class X402SupportedResponse(AgentBankModel):
    kinds: list[X402SupportedKind]
    extensions: list[str]
    signers: dict[str, list[str]]


class X402Payee(AgentBankModel):
    """
    Seller configuration for charging per call (x402 receive).
    """

    object: Literal["x402_payee"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    pay_to: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    domains: list[Hostname]
    facilitator_url: str
    fee_bps: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class RegisterX402PayeeRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    domains: Annotated[list[Hostname], Field(max_length=50, min_length=1)]


class EscrowValidator(AgentBankModel):
    registry: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    request_hash: Annotated[str, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    min_response: Annotated[int, Field(ge=0, le=100)]


class Escrow(AgentBankModel):
    id: Annotated[str, Field(pattern="^esc_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["escrow"]
    payer_account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    payee: Counterparty
    amount: Money
    fee: Money
    status: Literal[
        "requires_signature",
        "locking",
        "locked",
        "released",
        "refunded",
        "disputed",
        "resolved",
        "failed",
        "canceled",
    ]
    release: Literal["payer", "arbiter", "validator"]
    arbiter: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    validator: EscrowValidator | None
    terms_hash: Annotated[str | None, Field(pattern="^0x[a-fA-F0-9]{64}$")]
    contract_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    onchain_id: str | None
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    pending_action: Literal["lock", "release", "refund", "dispute"] | None
    """
    On-chain action waiting for the session signature, if any
    """
    signing_request: SigningRequest | None
    memo: str | None
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    updated_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class EscrowPayee(AgentBankModel):
    address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    EVM address
    """
    agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")] = None


class EscrowValidatorParam(EscrowValidator):
    pass


class CreateEscrowRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    payee: Annotated[EscrowPayee, Field(title="EscrowPayee")]
    amount: Money
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    release: Literal["payer", "arbiter", "validator"] = "payer"
    arbiter: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ] = None
    """
    EVM address
    """
    validator: Annotated[EscrowValidatorParam | None, Field(title="EscrowValidatorParam")] = None
    terms: Annotated[str | None, Field(max_length=10000)] = None
    """
    Free-text terms; only their hash goes on-chain
    """
    memo: Annotated[str | None, Field(max_length=500)] = None
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")] = None


class DisputeEscrowRequest(AgentBankModel):
    reason: Annotated[str, Field(max_length=2000, min_length=1)]


class Stream(AgentBankModel):
    """
    Pre-funded per-second stream or recurring payment, settled on an interval.
    """

    id: Annotated[str, Field(pattern="^str_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["stream"]
    payer_account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    payee: Counterparty
    kind: Literal["streaming", "recurring"]
    amount_per_interval: Money
    interval_seconds: Annotated[int, Field(gt=0, le=9007199254740991)]
    deposit: Money
    settled: Money
    settle_every_seconds: Annotated[int, Field(gt=0, le=9007199254740991)]
    start_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    stop_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """
    status: Literal["requires_signature", "active", "paused", "completed", "canceled", "failed"]
    contract_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    onchain_id: str | None
    pending_action: Literal["create", "cancel", "top_up"] | None
    """
    On-chain action waiting for the session signature, if any
    """
    signing_request: SigningRequest | None
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class StreamPayee(EscrowPayee):
    pass


class CreateStreamRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    payee: Annotated[StreamPayee, Field(title="StreamPayee")]
    kind: Literal["streaming", "recurring"] = "streaming"
    amount_per_interval: Money
    interval_seconds: Annotated[int, Field(gt=0, le=9007199254740991)]
    """
    1 for per-second streaming
    """
    deposit: Money
    settle_every_seconds: Annotated[int, Field(ge=60, le=9007199254740991)] = 3600
    start_at: AwareDatetime | None = None
    """
    ISO 8601 timestamp
    """
    stop_at: AwareDatetime | None = None
    """
    ISO 8601 timestamp
    """
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")] = None


class ApprovalDecision(AgentBankModel):
    member_id: Annotated[str, Field(pattern="^mem_[0-9A-HJKMNP-TV-Z]{26}$")]
    decision: Literal["approve", "deny"]
    decided_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class Approval(AgentBankModel):
    """
    A payment waiting for human approval. Expires after 15 minutes.
    """

    id: Annotated[str, Field(pattern="^apr_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["approval"]
    payment_id: Annotated[str, Field(pattern="^pay_[0-9A-HJKMNP-TV-Z]{26}$")]
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    agent_id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    amount: Money
    counterparty: Counterparty
    required_approvers: Annotated[int, Field(ge=1, le=9007199254740991)]
    decisions: list[ApprovalDecision]
    status: Literal["pending", "approved", "denied", "expired"]
    expires_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class DecideApprovalRequest(AgentBankModel):
    decision: Literal["approve", "deny"]
    webauthn_assertion: dict[str, Any] | None = None
    """
    Passkey assertion for the approval challenge (required for console members)
    """


class LedgerLine(AgentBankModel):
    ledger_account: str
    """
    e.g. "pocket:operating" or "sys:revenue"
    """
    account_id: Annotated[str | None, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    amount: Annotated[
        str,
        Field(examples=["-25.00"], pattern="^-?(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ]
    """
    Signed decimal string in major units.
    """
    asset: Literal["USDC"]
    """
    Asset code. USDC only in v1.
    """


class LedgerEntry(AgentBankModel):
    """
    An immutable, balanced journal entry.
    """

    id: Annotated[str, Field(pattern="^ent_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["ledger_entry"]
    ref_type: str
    ref_id: str | None
    memo: str | None
    payment_id: Annotated[str | None, Field(pattern="^pay_[0-9A-HJKMNP-TV-Z]{26}$")]
    agent_id: Annotated[str | None, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    mandate_id: Annotated[str | None, Field(pattern="^mdt_[0-9A-HJKMNP-TV-Z]{26}$")]
    decision_id: Annotated[str | None, Field(pattern="^dec_[0-9A-HJKMNP-TV-Z]{26}$")]
    reverses_entry_id: Annotated[str | None, Field(pattern="^ent_[0-9A-HJKMNP-TV-Z]{26}$")]
    lines: list[LedgerLine]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class StatementLine(AgentBankModel):
    entry_id: Annotated[str, Field(pattern="^ent_[0-9A-HJKMNP-TV-Z]{26}$")]
    date: AwareDatetime
    """
    ISO 8601 timestamp
    """
    description: str
    amount: Annotated[
        str,
        Field(examples=["-25.00"], pattern="^-?(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ]
    """
    Signed decimal string in major units.
    """
    balance: Annotated[
        str,
        Field(examples=["-25.00"], pattern="^-?(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$"),
    ]
    """
    Signed decimal string in major units.
    """
    ref_type: str
    ref_id: str | None


class Statement(AgentBankModel):
    """
    Monthly statement generated from the ledger.
    """

    id: str
    object: Literal["statement"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    period: Annotated[str, Field(pattern="^[0-9]{4}-[0-9]{2}$")]
    asset: Literal["USDC"]
    """
    Asset code. USDC only in v1.
    """
    opening_balance: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    closing_balance: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    total_in: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    total_out: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    fees: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    entry_count: Annotated[int, Field(ge=0, le=9007199254740991)]
    lines: list[StatementLine]
    generated_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class Vault(AgentBankModel):
    """
    Goal vaults are ledger-only; locked vaults use the TimeLockVaults contract.
    """

    id: Annotated[str, Field(pattern="^vlt_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["vault"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    kind: Literal["goal", "locked"]
    name: str
    target: Money | None
    unlock_at: AwareDatetime | None
    """
    ISO 8601 timestamp
    """
    balance: Money
    contract_address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    onchain_id: str | None
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class CreateVaultRequest(AgentBankModel):
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    kind: Literal["goal", "locked"]
    name: Annotated[str, Field(max_length=100, min_length=1)]
    target: Money | None = None
    unlock_at: AwareDatetime | None = None
    """
    ISO 8601 timestamp
    """


class VaultTransferRequest(AgentBankModel):
    amount: Money
    owner_authorization: OwnerAuthorization | None = None


class AutoTopUpRule(AgentBankModel):
    """
    Refill an agent from the org treasury when its balance drops.
    """

    id: Annotated[str, Field(pattern="^atu_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["auto_topup_rule"]
    agent_id: Annotated[str, Field(pattern="^agt_[0-9A-HJKMNP-TV-Z]{26}$")]
    treasury_account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    refill_to: Money
    when_below: Money
    max_per_day: Money
    status: Literal["active", "disabled"]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class PutAutoTopUpRequest(AgentBankModel):
    refill_to: Money
    when_below: Money
    max_per_day: Money
    owner_authorization: OwnerAuthorization


class FundEligibility(AgentBankModel):
    investor_types: list[str]
    jurisdictions: str
    minimum: Money


class Fund(AgentBankModel):
    """
    Neutral eligibility list entry. Agent Bank makes no recommendation.
    """

    id: Annotated[str, Field(pattern="^fnd_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["fund"]
    name: str
    issuer: str
    token_address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    chain_id: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    settlement: Literal["same_day", "next_day"]
    eligibility: Annotated[FundEligibility, Field(title="FundEligibility")]
    disclosure: str


class SweepRule(AgentBankModel):
    id: Annotated[str, Field(pattern="^swp_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["sweep_rule"]
    account_id: Annotated[str, Field(pattern="^acct_[0-9A-HJKMNP-TV-Z]{26}$")]
    fund_id: Annotated[str, Field(pattern="^fnd_[0-9A-HJKMNP-TV-Z]{26}$")]
    floor: Money
    threshold: Money
    max_share_bps: Annotated[int, Field(ge=0, le=10000)]
    status: Literal["pending_install", "active", "disabled"]
    install_operation_id: Annotated[str | None, Field(pattern="^oop_[0-9A-HJKMNP-TV-Z]{26}$")]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class PutSweepRuleRequest(AgentBankModel):
    fund_id: Annotated[str, Field(pattern="^fnd_[0-9A-HJKMNP-TV-Z]{26}$")]
    floor: Money | None = None
    """
    Default: two days of trailing seven-day spend
    """
    threshold: Money
    max_share_bps: Annotated[int, Field(ge=0, le=10000)]
    owner_authorization: OwnerAuthorization


class WebhookEndpoint(AgentBankModel):
    id: Annotated[str, Field(pattern="^whe_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["webhook_endpoint"]
    url: str
    events: list[
        Literal[
            "payment.created",
            "payment.requires_approval",
            "payment.submitted",
            "payment.settled",
            "payment.failed",
            "payment.denied",
            "approval.requested",
            "approval.decided",
            "escrow.locked",
            "escrow.released",
            "escrow.refunded",
            "escrow.disputed",
            "stream.created",
            "stream.settled",
            "stream.canceled",
            "deposit.received",
            "reconciliation.mismatch",
            "agent.frozen",
            "agent.unfrozen",
            "org.frozen",
            "policy.updated",
            "session.revoked",
            "balance.low",
            "statement.ready",
        ]
    ]
    status: Literal["enabled", "disabled"]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class WebhookEndpointWithSecret(AgentBankModel):
    id: Annotated[str, Field(pattern="^whe_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["webhook_endpoint"]
    url: str
    events: list[
        Literal[
            "payment.created",
            "payment.requires_approval",
            "payment.submitted",
            "payment.settled",
            "payment.failed",
            "payment.denied",
            "approval.requested",
            "approval.decided",
            "escrow.locked",
            "escrow.released",
            "escrow.refunded",
            "escrow.disputed",
            "stream.created",
            "stream.settled",
            "stream.canceled",
            "deposit.received",
            "reconciliation.mismatch",
            "agent.frozen",
            "agent.unfrozen",
            "org.frozen",
            "policy.updated",
            "session.revoked",
            "balance.low",
            "statement.ready",
        ]
    ]
    status: Literal["enabled", "disabled"]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """
    secret: str
    """
    HMAC signing secret. Shown once.
    """


class CreateWebhookEndpointRequest(AgentBankModel):
    url: str
    events: Annotated[
        list[
            Literal[
                "payment.created",
                "payment.requires_approval",
                "payment.submitted",
                "payment.settled",
                "payment.failed",
                "payment.denied",
                "approval.requested",
                "approval.decided",
                "escrow.locked",
                "escrow.released",
                "escrow.refunded",
                "escrow.disputed",
                "stream.created",
                "stream.settled",
                "stream.canceled",
                "deposit.received",
                "reconciliation.mismatch",
                "agent.frozen",
                "agent.unfrozen",
                "org.frozen",
                "policy.updated",
                "session.revoked",
                "balance.low",
                "statement.ready",
            ]
        ],
        Field(min_length=1),
    ]


class Event(AgentBankModel):
    id: Annotated[str, Field(pattern="^evt_[0-9A-HJKMNP-TV-Z]{26}$")]
    object: Literal["event"]
    type: Literal[
        "payment.created",
        "payment.requires_approval",
        "payment.submitted",
        "payment.settled",
        "payment.failed",
        "payment.denied",
        "approval.requested",
        "approval.decided",
        "escrow.locked",
        "escrow.released",
        "escrow.refunded",
        "escrow.disputed",
        "stream.created",
        "stream.settled",
        "stream.canceled",
        "deposit.received",
        "reconciliation.mismatch",
        "agent.frozen",
        "agent.unfrozen",
        "org.frozen",
        "policy.updated",
        "session.revoked",
        "balance.low",
        "statement.ready",
    ]
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    data: dict[str, Any]
    created_at: AwareDatetime
    """
    ISO 8601 timestamp
    """


class Plan(AgentBankModel):
    code: Literal["free", "pro", "business", "enterprise"]
    name: str
    monthly_price: Money
    max_agents: Annotated[int | None, Field(ge=-9007199254740991, le=9007199254740991)]
    features: list[str]


class Subscription(AgentBankModel):
    object: Literal["subscription"]
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    plan: Plan
    status: Literal["active", "past_due", "canceled"]
    current_period_start: AwareDatetime
    """
    ISO 8601 timestamp
    """
    current_period_end: AwareDatetime
    """
    ISO 8601 timestamp
    """


class ChangePlanRequest(AgentBankModel):
    plan: Literal["free", "pro", "business", "enterprise"]


ByKindAdditionalProperty = TypeAliasType(
    "ByKindAdditionalProperty",
    Annotated[str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")],
)
"""
Decimal string in major units, e.g. "25.00". Never a JSON number.
"""


class FeeSummary(AgentBankModel):
    object: Literal["fee_summary"]
    org_id: Annotated[str, Field(pattern="^org_[0-9A-HJKMNP-TV-Z]{26}$")]
    period: str
    by_kind: dict[str, ByKindAdditionalProperty]
    total: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """


RevenueByStreamAdditionalProperty = TypeAliasType(
    "RevenueByStreamAdditionalProperty",
    Annotated[str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")],
)
"""
Decimal string in major units, e.g. "25.00". Never a JSON number.
"""


VolumeByKindAdditionalProperty = TypeAliasType(
    "VolumeByKindAdditionalProperty",
    Annotated[str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")],
)
"""
Decimal string in major units, e.g. "25.00". Never a JSON number.
"""


PayingOrgsAdditionalProperty = TypeAliasType(
    "PayingOrgsAdditionalProperty",
    Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)],
)


class RevenueReport(AgentBankModel):
    """
    Revenue by stream, gross margin and volume per org.
    """

    object: Literal["revenue_report"]
    period: str
    revenue_by_stream: dict[str, RevenueByStreamAdditionalProperty]
    total_revenue: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    variable_costs: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """
    gross_margin_bps: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    volume_by_kind: dict[str, VolumeByKindAdditionalProperty]
    paying_orgs: dict[str, PayingOrgsAdditionalProperty]
    volume_per_org: Annotated[
        str, Field(examples=["25.00"], pattern="^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$")
    ]
    """
    Decimal string in major units, e.g. "25.00". Never a JSON number.
    """


class MetaUsdc(AgentBankModel):
    address: Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    decimals: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    eip712_name: str
    eip712_version: str


ContractsAdditionalProperty = TypeAliasType(
    "ContractsAdditionalProperty",
    Annotated[
        str,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ],
)
"""
EVM address
"""


class Meta(AgentBankModel):
    """
    Deployment facts clients need: chain, USDC, contract addresses, feature flags.
    """

    object: Literal["meta"]
    api_version: str
    chain: Literal["base-sepolia", "anvil", "simulated"]
    chain_id: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    caip2: str
    owner_authorization_chain_id: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    """
    EIP-712 domain chain id to use for OwnerAuthorization signatures
    """
    usdc: Annotated[MetaUsdc, Field(title="MetaUsdc")]
    contracts: dict[str, ContractsAdditionalProperty]
    """
    Agent Bank contract addresses on this chain
    """
    cosigner_address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    revenue_address: Annotated[
        str | None,
        Field(
            examples=["0x1111111111111111111111111111111111111111"],
            pattern="^0x[a-fA-F0-9]{40}$",
        ),
    ]
    """
    EVM address
    """
    facilitator_url: str | None
    features: dict[str, bool]


class Problem(AgentBankModel):
    """
    RFC 9457 problem details
    """

    model_config = ConfigDict(
        extra="allow",
    )
    type: str
    title: str
    status: Annotated[int, Field(ge=-9007199254740991, le=9007199254740991)]
    detail: str | None = None
    instance: str | None = None
    code: str


class ListApiKeysResponse(AgentBankModel):
    data: list[ApiKey]
    next_cursor: str | None


class ListMembersResponse(AgentBankModel):
    data: list[Member]
    next_cursor: str | None


class ListAgentsResponse(AgentBankModel):
    data: list[Agent]
    next_cursor: str | None


class ListAccountsResponse(AgentBankModel):
    data: list[Account]
    next_cursor: str | None


class ListPaymentsResponse(AgentBankModel):
    data: list[Payment]
    next_cursor: str | None


class ListApprovalsResponse(AgentBankModel):
    data: list[Approval]
    next_cursor: str | None


class ListEntriesResponse(AgentBankModel):
    data: list[LedgerEntry]
    next_cursor: str | None


class ListVaultsResponse(AgentBankModel):
    data: list[Vault]
    next_cursor: str | None


GetAutoTopUpResponse = TypeAliasType(
    "GetAutoTopUpResponse",
    Annotated[AutoTopUpRule | None, Field(title="GetAutoTopUpResponse")],
)


class ListFundsResponse(AgentBankModel):
    data: list[Fund]


class ListWebhookEndpointsResponse(AgentBankModel):
    data: list[WebhookEndpoint]
    next_cursor: str | None


class ListEventsResponse(AgentBankModel):
    data: list[Event]
    next_cursor: str | None


class ListPlansResponse(AgentBankModel):
    data: list[Plan]


class HealthResponse(AgentBankModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, str]


__all__ = [
    "Account",
    "Address",
    "Agent",
    "AgentId",
    "AgentPolicy",
    "AllowedContract",
    "AllowedPayeesConstraint",
    "AllowedRecipient",
    "AmountRangeConstraint",
    "ApiKey",
    "ApiKeyWithSecret",
    "Approval",
    "ApprovalDecision",
    "ApprovalThreshold",
    "AutoSave",
    "AutoTopUpRule",
    "Balances",
    "BudgetConstraint",
    "ByKindAdditionalProperty",
    "ChangePlanRequest",
    "ContractsAdditionalProperty",
    "Counterparty",
    "CounterpartyCap",
    "CounterpartyDenyList",
    "CounterpartyMatch",
    "CreateAccountRequest",
    "CreateAgentRequest",
    "CreateApiKeyRequest",
    "CreateEscrowRequest",
    "CreateMandateRequest",
    "CreateMemberRequest",
    "CreateOrgRequest",
    "CreateOrgResponse",
    "CreatePaymentRequest",
    "CreatePaymentRequestRequest",
    "CreateSessionRequest",
    "CreateStreamRequest",
    "CreateTreasuryAccountRequest",
    "CreateVaultRequest",
    "CreateWebhookEndpointRequest",
    "DecideApprovalRequest",
    "DisputeEscrowRequest",
    "Eip3009Authorization",
    "Eip712Domain",
    "Erc8004Id",
    "Escrow",
    "EscrowPayee",
    "EscrowValidator",
    "EscrowValidatorParam",
    "EthAddressKeyBinding",
    "Event",
    "ExcessSweep",
    "ExecutionDateConstraint",
    "FeeSummary",
    "FreezeRequest",
    "Fund",
    "FundEligibility",
    "GetAutoTopUpResponse",
    "HealthResponse",
    "Hostname",
    "IncomeSplit",
    "JwkKeyBinding",
    "KybSession",
    "LedgerEntry",
    "LedgerLine",
    "ListAccountsResponse",
    "ListAgentsResponse",
    "ListApiKeysResponse",
    "ListApprovalsResponse",
    "ListEntriesResponse",
    "ListEventsResponse",
    "ListFundsResponse",
    "ListMembersResponse",
    "ListPaymentsResponse",
    "ListPlansResponse",
    "ListVaultsResponse",
    "ListWebhookEndpointsResponse",
    "Mandate",
    "MandatePayee",
    "Member",
    "Meta",
    "MetaUsdc",
    "MetadataAdditionalProperty",
    "MinorUnitsInt",
    "MinorUnitsString",
    "Money",
    "OpenPaymentMandate",
    "Org",
    "OwnerAuthorization",
    "OwnerOperation",
    "PayingOrgsAdditionalProperty",
    "Payment",
    "PaymentDestination",
    "PaymentIntent",
    "PaymentRequest",
    "Plan",
    "PolicyCheckRequest",
    "PolicyCounterparties",
    "PolicyDecision",
    "PolicyDocument",
    "PolicyLimits",
    "PolicyVelocity",
    "PolicyVersion",
    "Problem",
    "PutAutoTopUpRequest",
    "PutPolicyRequest",
    "PutSweepRuleRequest",
    "RecurrenceConstraint",
    "RegisterX402PayeeRequest",
    "RevenueByStreamAdditionalProperty",
    "RevenueReport",
    "RoundUp",
    "RuleHit",
    "ScheduledSave",
    "Secp256k1Jwk",
    "Session",
    "SessionScope",
    "SetTreasuryRequest",
    "SigningRequest",
    "Statement",
    "StatementLine",
    "Stream",
    "StreamPayee",
    "SubmitOwnerSignatureRequest",
    "SubmitSignatureRequest",
    "Subscription",
    "SweepRule",
    "TimeWindow",
    "UnfreezeRequest",
    "Vault",
    "VaultBalance",
    "VaultTransferRequest",
    "VolumeByKindAdditionalProperty",
    "WebhookEndpoint",
    "WebhookEndpointWithSecret",
    "X402DomainsConstraint",
    "X402PayRequest",
    "X402PayResponse",
    "X402Payee",
    "X402PaymentPayload",
    "X402PaymentRequirements",
    "X402ResourceInfo",
    "X402SettleResponse",
    "X402SupportedKind",
    "X402SupportedResponse",
    "X402VerifyRequest",
    "X402VerifyResponse",
]
