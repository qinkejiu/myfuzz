# PULP SPI Local Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Verify the pinned PULP APB SPI source/profile facts and provide an independently tested native mode-0 pin peer, without claiming generated runtime acceptance.

**Architecture:** Keep a full-top local profile with the existing seven regular-file content pin. A separate source-fact verifier authenticates both source-lock records and their elaboration closure, then checks the union profile; this does not bypass the artifact source gate's locator mismatch. A peer maps the existing mode-0 bit engine to four PULP CS pins and SDI1, advancing only on observed pin edges and recording observed event bits.

**Files:** Add `configs/peripherals/pulp_spi/local_component_profile.json`, `src/myfuzz/local_harness/pulp_spi_contract.py`, `src/myfuzz/scenario/pulp_spi_peer.py`, dedicated tests, and an evidence/acceptance report. No core renderer/build/session changes or source-lock edits.

## Task 1: Source/profile facts

- [x] Write failing tests for the local full-top profile and source verification API.
- [x] Add the union-pin profile, with explicit full-top selection and no claimed interrupt level.
- [x] Verify lock-owned selected bytes, seven-file closure, parameters, profile pin and binding APB contract. Test mismatched source/parameters fail closed.
- [x] Record that `verify_local_source_lock` refuses the union locator. Do not grant build acceptance.

## Task 2: Native peer

- [x] Write failing tests for SDI1 mapping, selected rising-edge capture, falling-edge MISO update, incomplete CS frames, reset persistence, unsupported quad/multi-CS and raw IRQ observation.
- [x] Add a strict single-CS mode-0 wrapper over `SpiPeer`; unused SDI sources are explicitly zero. Accept actual pre/post pin snapshots only; no cycle-based expected completion or fabricated IRQ.
- [x] Run dedicated and existing peer regressions.

## Task 3: Executable acceptance roadmap

- [x] Re-elaborate pinned RTL and bind all 25 top ports; select existing APB3 full-word contract by actual fields.
- [x] Record test commands, source identities, source-gate gap, peer/runtime ownership, and hardware acceptance cases: TX/RX shifts, header/dummy framing, actual event pulses, repeated commands, retry/replay and reset.
- [x] Commit independently without push. Levels remain source/elaboration and contract/peer unit verification; new local SPI runtime is not Generated, RTL-operational or cross-component accepted.
