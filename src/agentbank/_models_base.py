"""Base class shared by every generated API model."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AgentBankModel(BaseModel):
    """Base for the generated models in :mod:`agentbank.models`.

    * ``regex_engine="python-re"``: some API patterns (hostnames) use
      look-around assertions that the default Rust engine does not support.
    * ``populate_by_name``: fields whose wire name is not a valid identifier
      (``$schema``) can be set by their Python name as well as their alias.
    """

    model_config = ConfigDict(
        regex_engine="python-re",
        populate_by_name=True,
        protected_namespaces=(),
    )
