"""The first certified semantic family: stable APB3 storage registers.

The registered source contracts in
:mod:`myfuzz.local_harness.apb_storage_source_contract` describe the reviewed
stable storage rows (PULP timer ``TIMER0_CTRL``, PULP SPI ``SPICMD`` and PULP
GPIO ``PADDIR``).  This module turns one already-validated row into a closed
:class:`SemanticContract`; it does not enumerate them in code.
It never widens that row into "the whole timer/SPI", never treats APB3 as a
storage protocol, and carries no runtime authority.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from ..contracts import GenericRuntimeRefused, canonical_json_bytes
from .contracts import STORAGE_RW, SemanticContract

_ROOT = Path(__file__).resolve().parents[4]
_SOURCE_VERIFIER_ID = "apb-storage-source.v1"
_ISSUER_ID = "ApbStorageRegisterVersionAuthority"
_ISSUER_VERSION = "1"

_VERIFIER_FILES = (
    "src/myfuzz/local_harness/apb_storage_source_contract.py",
    "src/myfuzz/local_harness/apb_storage_probe_verification.py",
    "src/myfuzz/runtime/semantics/contracts.py",
    "src/myfuzz/runtime/semantics/storage.py",
)
_ISSUER_FILES = ("src/myfuzz/scenario/apb_storage_register_version.py",)


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        raise GenericRuntimeRefused(
            "generic-source-unverified", "/source/verifier",
            {"reason": "implementation-unreadable", "file": relative}) from error


def _pin(files: tuple[str, ...]) -> str:
    return sha256(canonical_json_bytes(
        {name: _file_sha(name) for name in files})).hexdigest()


def verifier_identity() -> dict:
    return {"id": _SOURCE_VERIFIER_ID, "version": "1",
            "implementation_sha256": _pin(_VERIFIER_FILES)}


def issuer_identity() -> dict:
    return {"issuer_id": _ISSUER_ID, "version": _ISSUER_VERSION,
            "implementation_sha256": _pin(_ISSUER_FILES)}


def storage_semantic_contract(*, registered: dict, endpoint_id: str,
                              template: tuple[str, str, str],
                              observation_scope: str) -> SemanticContract:
    """Derive the closed storage semantics of one validated source contract."""
    try:
        contract_id = registered["contract_id"]
        source = registered["source"]
        register = registered["register"]
        decode = registered["decode"]
        reset = registered["reset"]
        effects_scope = registered["writers"]["scope"]
    except (KeyError, TypeError) as error:
        raise GenericRuntimeRefused(
            "generic-semantic-unsupported", "/source_contract",
            {"reason": "registered-contract-shape"}) from error
    for name in ("name", "canonical_offset", "width", "read_mask", "write_mask"):
        if name not in register:
            raise GenericRuntimeRefused("generic-semantic-unsupported",
                                        "/register/" + name)
    if register["width"] != 32:
        raise GenericRuntimeRefused("generic-semantic-unsupported", "/register/width",
                                    {"expected": 32, "actual": register["width"]})
    document = {
        "schema_version": "semantic_contract.v1",
        "kind": STORAGE_RW,
        "source": {
            "contract_id": contract_id,
            "root": source["root"],
            "revision": source["revision"],
            "top_module": source["top_module"],
            "files": dict(sorted(source["files"].items())),
            "verifier": verifier_identity(),
            "identity_basis": source["identity_basis"],
        },
        "endpoint": {
            "endpoint_id": endpoint_id,
            "role": "target",
            "protocol": ["apb", "3"],
            "template": list(template),
            "semantic_kind": STORAGE_RW,
        },
        "decode": {
            "address_width": decode["address_width"],
            "address_units": "byte",
            "alignment_bytes": decode["host_alignment_bytes"],
            "mask": decode["mask"],
            "value": decode["value"],
            "alias_period_bytes": decode["alias_period_bytes"],
            "expression": decode["expression"],
        },
        "operations": [
            {
                "operation": "read",
                "width_bits": register["width"],
                "read_mask": register["read_mask"],
                "write_mask": 0,
                "byte_enable": False,
                "value_origin": "target_register_read",
            },
            {
                "operation": "write",
                "width_bits": register["width"],
                "read_mask": register["read_mask"],
                "write_mask": register["write_mask"],
                "byte_enable": False,
                "value_origin": "cpu_transaction_wdata",
            },
        ],
        "reset": {
            "declared": True,
            "port": reset["port"],
            "polarity": reset["polarity"],
            "observed": False,
            "evidence_ref": None,
            "case_begin_is_reset": False,
        },
        "side_effects": [{"kind": "stable_storage",
                          "scope": effects_scope + " (registered row only)"}],
        "observations": [
            {"name": "storage_probes",
             "layer": "component_semantic_effect",
             "native": True,
             "reference": observation_scope}
        ],
        "issuer_contract": {
            "issuer_id": _ISSUER_ID,
            "version": _ISSUER_VERSION,
            "implementation_sha256": _pin(_ISSUER_FILES),
            "token_scope": "existing_process_local_single_use",
            "single_use": True,
            "authority": False,
        },
    }
    return SemanticContract.freeze(document)


def storage_register_facts(contract: SemanticContract) -> dict:
    """Facts a provider may rely on after rechecking the whole contract."""
    if type(contract) is not SemanticContract or contract.kind != STORAGE_RW:
        raise GenericRuntimeRefused("generic-semantic-unsupported", "/semantic",
                                    {"expected": STORAGE_RW})
    document = contract.document()
    reads = [row for row in document["operations"]
             if row["operation"] == "read"]
    writes = [row for row in document["operations"]
              if row["operation"] == "write"]
    if len(reads) != 1 or len(writes) != 1:
        raise GenericRuntimeRefused("generic-semantic-unsupported", "/operations")
    if {row["kind"] for row in document["side_effects"]} != {"stable_storage"}:
        raise GenericRuntimeRefused("generic-semantic-unsupported", "/side_effects")
    return {
        "contract_id": contract.sha256_hex,
        "source_contract_id": document["source"]["contract_id"],
        "endpoint_id": document["endpoint"]["endpoint_id"],
        "protocol": tuple(document["endpoint"]["protocol"]),
        "template": tuple(document["endpoint"]["template"]),
        "register_width": reads[0]["width_bits"],
        "read_mask": reads[0]["read_mask"],
        "write_mask": writes[0]["write_mask"],
        "byte_enable": writes[0]["byte_enable"],
        "address_width": document["decode"]["address_width"],
        "address_units": document["decode"]["address_units"],
        "alignment_bytes": document["decode"]["alignment_bytes"],
        "decode_mask": document["decode"]["mask"],
        "decode_value": document["decode"]["value"],
        "alias_period_bytes": document["decode"]["alias_period_bytes"],
        "expression": document["decode"]["expression"],
        "reset_port": document["reset"]["port"],
        "reset_observed": document["reset"]["observed"],
        "observations": tuple(row["name"] for row in document["observations"]),
    }


def address_matches(contract: SemanticContract, address: int) -> bool:
    """Raw storage alias predicate over a byte address (no transport check)."""
    facts = storage_register_facts(contract)
    if type(address) is not int or not 0 <= address < (1 << facts["address_width"]):
        raise GenericRuntimeRefused("generic-contract-type", "/address",
                                    {"expected": "byte address within width"})
    return address & facts["decode_mask"] == facts["decode_value"]


def aligned_offset(contract: SemanticContract, address: int) -> int:
    """Canonical register word offset for one alias address."""
    if not address_matches(contract, address):
        raise GenericRuntimeRefused("generic-route-refused", "/address",
                                    {"reason": "not-a-storage-alias"})
    facts = storage_register_facts(contract)
    if address % facts["alignment_bytes"]:
        raise GenericRuntimeRefused("generic-route-refused", "/address",
                                    {"reason": "transport-alignment",
                                     "alignment_bytes": facts["alignment_bytes"]})
    return address & ~(facts["alignment_bytes"] - 1)
