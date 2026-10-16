# Ordinary APB observations in register Session save and replay

The ordinary native GPIO target command and Runner journal association packages are the baseline. This increment connects their observation-only evidence to the existing declarative register Session schemas 16 and 17. It does not establish GPIO storage semantics, functional coverage, retirement, or a verified capability level.

## Installation

`ScenarioSession.configure_ordinary_apb_access_evidence(*, max_records=256)` is an explicit, default-off hook. Capacity must be an exact integer in 1..65536. The Session and Runner must be fresh, created, not begun or finished, with no cases or events. Declare instruction slots before configuring: the collector binds the actual persistent-memory slot declaration.

The hook can run before or after attaching `RegisterProgramRuntime`; it checks an already attached adapter before and after installation. All actual generated native GPIO targets receive command observations, followed by installation of the actual Runner collector. Target constructors are validated before publishing modes. A failed collector installation rolls back the newly installed target helpers and projector caches while no commands or events have occurred. An already installed target observation mode or collector is rejected rather than silently adopted.

## Saved shape

Only enabled register plans add `register_programs.ordinary_apb_access_evidence`:

```json
{
  "schema_version": "ordinary_apb_access_session.v1",
  "configuration": "actual startup collector configuration object",
  "state": "actual collector snapshot object"
}
```

The placeholders above describe objects, not string-valued production fields. The configuration schema is `ordinary_apb_access_evidence_configuration.v1`; the snapshot schema is `ordinary_apb_access_evidence_state.v1`. The snapshot contains the fixed configuration and its exact collector serialization SHA, status/reason, bounded counts, and detached association records. All records keep verification, storage, and functional grants false.

Schema 16 remains the successful register-program plan. Schema 17 retains the actual failed attempt and Session terminal prefix; its ordinary snapshot may be incomplete. Export preserves that snapshot rather than trying to authorize more commands or repair a failure. The default-off schema layouts receive no new fields.

`validate_ordinary_apb_access_session_document(document)` checks only closed saved comparison data: exact keys and versions, strict scalar types, capacities, configuration SHA, per-target bindings, memory-region declarations and byte-granular `(memory_id, offset)` instruction slots, bounded unique references, record status/count consistency, and false grants. It does not install any provider or accept saved references as authority. The register-plan validator calls it before a trusted factory is invoked.

## Identity and fresh replay

The online manifest adds only enabled startup fields:

- `ordinary_apb_access_evidence_configuration`
- `ordinary_apb_access_source_files`

The terminal snapshot is excluded from startup identity. `_ordinary_apb_access_source_files()` derives a sorted, deduplicated code-owned import closure from `local_harness.build._host_sources()` plus the Session, collector, target helper, and critical journal/protocol files. It never follows paths from a saved plan. Installation discovers the closure; subsequent Session guards hash the pinned paths without parsing the import graph at every RTL step. Existing capability source-file layout remains independent. Command guards validate the actual collector and compare its cached startup configuration digest without copying the full memory slot document. Saved manifests and terminal exports retain the full detached configuration. Export alone may tolerate an existing incomplete observation status; it still rejects configuration and source drift, and does not authorize a further command.

The trusted register runtime callback installs the fresh observation mode through the Session hook. Replay compares its actual startup configuration and manifest before `begin()`, recompiles each original register request in the actual fresh context, executes the resulting admissions and schedule, then compares the complete ordinary snapshot along with the existing register/gate/admission/reset/event/plan identities. No snapshot restoration API is introduced.

## Software validation scope

Tests use real rendered CPU, GPIO, router, ledger, compiler, gate, parser, normalizer, checker, and journal objects with a strict parsed software transport. They exercise default-off layout, both installation orders, nonempty confirmed association save/replay, closed malformed documents, startup source drift, atomic failed installation, and an authentic CPU callback failure retained in schema 17. These tests are not RTL execution evidence. A subsequent fresh actual native gate remains separate.
