"""Import surface for the dynamic, pre-admission cross-case prerequisite binder.

The implementation lives in :mod:`myfuzz.scenario.source_actions`, next to the
bounded cross-case effect tracker whose retained index it reads and the
``Prerequisite`` contract it injects; this module only re-exports that appended
surface so a caller can name the capability without importing the whole action
module.

Safety boundary (full text in
:class:`~myfuzz.scenario.source_actions.DynamicPrerequisiteBinder`): the binder
consumes only the ``(memory_id, byte_offset)`` pairs and writer kinds of one
declared :class:`TrustedRamByteDeclaration`, pins a retained ``ram_byte_version``
as a *prerequisite* of a later case's action, and never turns a committed RAM
byte into a fuzzable CPU input.
"""

from __future__ import annotations

from .source_actions import (
    BOUND_REASON, BOUND_WITNESS_SCHEMA_VERSION, DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION,
    DYNAMIC_PREREQUISITE_BINDER_SCHEMA_VERSION, LATEST_EFFECT_ORDER,
    SELECTION_STRATEGY, TRUSTED_RAM_DECLARATION_SCHEMA_VERSION, UNBOUND_NO_WITNESS,
    UNBOUND_PROVENANCE, UNBOUND_VALUE, UNBOUND_WRITER_KIND, BoundWitness,
    DynamicBindingError, DynamicBindingRefused, DynamicBindingUnbound,
    DynamicEffectBinding, DynamicPrerequisiteBinder, TrustedRamByteDeclaration,
    bind_latest_effect,
)

__all__ = [
    "BOUND_REASON", "BOUND_WITNESS_SCHEMA_VERSION",
    "DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION",
    "DYNAMIC_PREREQUISITE_BINDER_SCHEMA_VERSION", "LATEST_EFFECT_ORDER",
    "SELECTION_STRATEGY", "TRUSTED_RAM_DECLARATION_SCHEMA_VERSION",
    "UNBOUND_NO_WITNESS", "UNBOUND_PROVENANCE", "UNBOUND_VALUE",
    "UNBOUND_WRITER_KIND", "BoundWitness", "DynamicBindingError",
    "DynamicBindingRefused", "DynamicBindingUnbound", "DynamicEffectBinding",
    "DynamicPrerequisiteBinder", "TrustedRamByteDeclaration",
    "bind_latest_effect",
]
