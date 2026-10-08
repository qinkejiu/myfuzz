"""Persistent RAM service for the standalone RVX completion-memory bus."""
from __future__ import annotations

import copy
from collections.abc import Mapping

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService

from .session import GeneratedLocalSession


_ROLES = {
    "addr": ("output", 32),
    "read_request": ("output", 1),
    "read_response": ("input", 1),
    "read_data": ("input", 32),
    "write_request": ("output", 1),
    "write_response": ("input", 1),
    "write_data": ("output", 32),
    "write_strobe": ("output", 4),
}


class GeneratedRvxMemorySession(GeneratedLocalSession):
    """One persistent RTL process with exact-once byte-addressed RAM service.

    RVX has no request-ready signal. A request is accepted on its local rising
    edge. The service freezes its read/write effect once, then returns the
    registered completion after ``response_latency_ticks`` local steps. While
    the response is withheld, the CPU must keep the same request asserted.
    The request observed after applying a completion input is independently
    eligible as the next edge's request, even when its payload matches the
    request just completed.
    """

    artifact_kind = "rvx_memory_cpu"
    runtime_kind = "rvx_memory_cpu"
    service_schema = "generated_rvx_memory_service.v1"
    max_driver_samples_per_operation = 1
    max_memory_materialized_bytes_per_operation = 4
    max_pending_responses = 1
    max_local_ticks_per_step = 1
    max_transaction_events_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, artifact, *, base_dir, cache_dir, memory,
                 response_latency_ticks: int = 1, **kwargs):
        document = getattr(artifact, "runtime_document", None)
        if (not isinstance(document, dict) or document.get("kind") != self.runtime_kind
                or not isinstance(memory, PersistentMemory)):
            raise ValueError("RVX memory CPU requires its generated artifact and PersistentMemory")
        maximum = document.get("effective_max_wait_cycles")
        if (type(response_latency_ticks) is not int or response_latency_ticks < 1
                or type(maximum) is not int or response_latency_ticks > maximum):
            raise ValueError("RVX response latency exceeds the admitted local wait bound")
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        self.memory = memory
        self.service = MemoryService(memory, TransactionLedger())
        self.response_latency_ticks = response_latency_ticks
        self._pending: dict[str, object] | None = None
        self._sequence_memory = 0
        self.memory_write_count = 0
        self.accepted_addresses: list[int] = []
        self.last_samples: tuple[dict, ...] = ()

    @property
    def pending_responses(self) -> int:
        return int(self._pending is not None)

    def identity_document(self):
        return {
            **super().identity_document(),
            "rvx_memory_service_schema_version": self.service_schema,
            "source_component": self.artifact.plan.request.instance_id,
            "memory_policy": "ram-rom-only",
            "response_latency_ticks": self.response_latency_ticks,
        }

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._pending = None
        self._sequence_memory = 0
        self.memory_write_count = 0
        self.accepted_addresses = []
        self.last_samples = ()

    def reset_local(self) -> dict[str, int]:
        cancelled = self.pending_responses
        # The request's memory effect already happened at its acceptance edge.
        # Reset clears only the unconsumed response and preserves RAM contents.
        self._pending = None
        super().reset_local()
        return {"cancelled_responses": cancelled}

    def end_case(self) -> None:
        # A testcase boundary discards response bookkeeping; RAM remains owned
        # by PersistentMemory and follows the runner's reset policy.
        self._pending = None
        super().end_case()

    @staticmethod
    def _integer(values: Mapping, name: str, width: int) -> int:
        value = values.get("rvx_" + name)
        if type(value) is not int or not 0 <= value < 1 << width:
            raise ProtocolEnvironmentError("RVX bus observation width mismatch: " + name)
        return value

    @staticmethod
    def _same_request(values: Mapping, pending: dict[str, object]) -> bool:
        write = bool(pending["write"])
        if values["rvx_addr"] != pending["address"]:
            return False
        if write:
            return (values["rvx_write_request"] == 1
                    and values["rvx_read_request"] == 0
                    and values["rvx_write_data"] == pending["write_data"]
                    and values["rvx_write_strobe"] == pending["write_strobe"])
        return values["rvx_read_request"] == 1 and values["rvx_write_request"] == 0

    def _accept(self, values: Mapping) -> dict[str, object]:
        read = self._integer(values, "read_request", 1)
        write = self._integer(values, "write_request", 1)
        if read and write:
            raise ProtocolEnvironmentError("RVX read and write requests are mutually exclusive")
        if not read and not write:
            raise AssertionError("_accept called without a physical request")
        address = self._integer(values, "addr", 32)
        if address & 3:
            raise ProtocolEnvironmentError("RVX memory request is not word aligned")
        self._sequence_memory += 1
        key = TransactionKey(
            "local-execution",
            self._case_id or "local-testcase",
            self.artifact.plan.request.instance_id,
            self.reset_epoch,
            "memory",
            self._sequence_memory,
        )
        write_data = self._integer(values, "write_data", 32)
        write_strobe = self._integer(values, "write_strobe", 4)
        first_event = len(self.service.events)
        try:
            if write:
                self.service.write(key, address, write_data,
                                   width_bytes=4, byte_enable=write_strobe)
                self.memory_write_count += 1
                response_data = 0
            else:
                response_data = self.service.read(key, address, width_bytes=4).value
        except (ValueError, RuntimeError) as error:
            self._abort()
            raise ProtocolEnvironmentError(
                "RVX memory request is outside the declared RAM policy"
            ) from error
        for event in self.service.events[first_event:]:
            event["local_tick"] = self.local_ticks
        self.accepted_addresses.append(address)
        return {
            "key": key,
            "write": bool(write),
            "address": address,
            "write_data": write_data,
            "write_strobe": write_strobe,
            "response_data": response_data,
            "age": 0,
        }

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError("RVX memory CPU has no fuzzable response inputs")

        pending = self._pending
        response_due = bool(
            pending is not None
            and int(pending["age"]) + 1 >= self.response_latency_ticks
        )
        read_response = int(response_due and not bool(pending["write"]))
        write_response = int(response_due and bool(pending["write"]))
        read_data = int(pending["response_data"]) if read_response and pending else 0
        controls = (read_response, write_response, read_data)

        receipt = self.command("STEP_RVX_MEMORY", controls)
        if receipt.status != "result" or receipt.new_ticks != 1:
            self._abort()
            raise ProtocolEnvironmentError(
                "RVX local command did not advance exactly one tick: "
                + str(getattr(receipt, "error_detail", None))
            )
        payload = receipt.payload
        if not isinstance(payload, dict) or not isinstance(payload.get("samples"), list) \
                or len(payload["samples"]) != 1:
            self._abort()
            raise ProtocolEnvironmentError("RVX driver returned an invalid single-tick trace")
        pre = payload.get("pre_backend")
        sample_pre = payload["samples"][0].get("pre")
        sample_post = payload["samples"][0].get("post")
        observations = payload.get("observations")
        if (not isinstance(pre, dict) or not isinstance(sample_pre, dict)
                or not isinstance(sample_post, dict)
                or not isinstance(observations, dict)
                or not isinstance(observations.get("backend"), dict)
                or not isinstance(observations.get("physical"), dict)):
            self._abort()
            raise ProtocolEnvironmentError("RVX driver omitted its physical tick snapshots")
        observed_pre = sample_pre.get("backend")
        sampled_post = sample_post.get("backend")
        observed_post = observations["backend"]
        if (not isinstance(sampled_post, dict)
                or not isinstance(sample_post.get("physical"), dict)
                or observed_post != sampled_post):
            self._abort()
            raise ProtocolEnvironmentError("RVX post-edge snapshots disagree")
        expected_inputs = {
            "rvx_read_response": read_response,
            "rvx_write_response": write_response,
            "rvx_read_data": read_data,
        }
        if (not isinstance(observed_pre, dict)
                or any(pre.get(name) != value or observed_pre.get(name) != value
                       for name, value in expected_inputs.items())
                or observed_pre != pre):
            self._abort()
            raise ProtocolEnvironmentError("RVX response controls disagree with sampled physical pins")
        for role, (_, width) in _ROLES.items():
            self._integer(pre, role, width)

        read = pre["rvx_read_request"]
        write = pre["rvx_write_request"]
        if read and write:
            self._abort()
            raise ProtocolEnvironmentError("RVX asserted read and write together")
        if pending is not None and not response_due:
            if not self._same_request(pre, pending):
                self._abort()
                raise ProtocolEnvironmentError("RVX changed a held request before completion")
            pending["age"] = int(pending["age"]) + 1
            accepted = None
            completed = None
        else:
            completed = pending if response_due else None
            if response_due:
                self._pending = None
            accepted = self._accept(pre) if read or write else None
            self._pending = accepted

        self.memory.advance_step()
        self.last_samples = tuple(copy.deepcopy(payload["samples"]))
        post_backend = observed_post
        outputs = {}
        for role in _ROLES:
            name = "rvx_" + role
            raw = post_backend.get(name)
            if type(raw) is not int or not 0 <= raw < 1 << _ROLES[role][1]:
                self._abort()
                raise ProtocolEnvironmentError("RVX post-edge output width mismatch: " + role)
            outputs[name] = raw

        completed_key = completed["key"] if completed else None
        accepted_key = accepted["key"] if accepted else None
        return {
            **outputs,
            "data_req_valid": int(bool(read or write)),
            "data_req_accepted": int(accepted is not None),
            "data_req_write": int(bool(accepted["write"])) if accepted else 0,
            "data_req_addr": int(accepted["address"]) if accepted else 0,
            "data_req_wdata": int(accepted["write_data"]) if accepted else 0,
            "data_req_be": int(accepted["write_strobe"]) if accepted else 0,
            "data_req_source_sequence": accepted_key.source_sequence if accepted_key else 0,
            "data_rsp_consumed": int(completed is not None),
            "data_rsp_rdata": int(completed["response_data"]) if completed else 0,
            "data_rsp_source_epoch": completed_key.source_epoch if completed_key else 0,
            "data_rsp_source_sequence": completed_key.source_sequence if completed_key else 0,
            "driver_samples": copy.deepcopy(self.last_samples),
            "physical_observations": copy.deepcopy(observations["physical"]),
        }
