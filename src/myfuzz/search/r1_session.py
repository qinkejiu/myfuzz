"""Narrow live R1 assembly using existing causal GPIO and CPU input gates.

This is a mechanism fixture, not a generic CPU/IP factory or an IRQ proof.
All register effects come from RegisterProgramRuntime's actual CPU programs.
"""
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from time import monotonic_ns

from .gpio_actions import GpioActionSpace
from .gpio_fields import read_gpio_field_current
from .gpio_relations import install_gpio_relation_consumer


def _bounded_stop(boundary, *, replay_advance_count, deadline_ns, max_advances):
    if (replay_advance_count is not None and
            (type(replay_advance_count) is not int or not 1 <= replay_advance_count <= max_advances)):
        raise ValueError('bounded actual replay prefix required')
    if deadline_ns is not None and (type(deadline_ns) is not int or deadline_ns <= 0):
        raise ValueError('positive monotonic deadline required')
    def stop(index):
        if replay_advance_count is not None:
            return index + 1 == replay_advance_count
        return bool((deadline_ns is not None and monotonic_ns() >= deadline_ns) or boundary(index))
    return stop


def _check_deadline(deadline_ns, replay_advance_count):
    if replay_advance_count is None and deadline_ns is not None and monotonic_ns() >= deadline_ns:
        raise TimeoutError('R1 search budget expired before admission')


class _ProgramBoundary:
    """Scheduling hint only; live consumers still authenticate all effects.

    Prefetch can reach the next slot before the final store. Do not hand off
    until the journal also contains the requested effect and data has drained.
    Documentary rows here never grant a reward or a consumption certificate.
    """
    def __init__(self, runner, cpu, *, program_end, instruction_end, request):
        self.runner, self.cpu = runner, cpu
        self.program_end, self.instruction_end = program_end, instruction_end
        self.request, self.cursor = request, runner.event_count
        self.effect = False
        self.span = (cpu.memory.resolve_span(request['result_address'], 4, write=True)
                     if request['operation'] == 'register_read' else None)

    def __call__(self, advance_index):
        rows = self.runner.events_since(self.cursor)
        self.cursor += len(rows)
        for row in rows:
            if self.span is None:
                self.effect |= (row.get('kind') == 'gpio_apb_access'
                    and row.get('component') == 'gpio_b' and row.get('status') == 'observed'
                    and row.get('decoded_offset') == 4 and row.get('write') is True
                    and row.get('wdata') == self.request['value'])
            elif row.get('kind') == 'memory_write_commit':
                doc = row.get('commit_document', {})
                self.effect |= ((doc.get('memory_id'), doc.get('generation'),
                    doc.get('byte_offset')) == self.span
                    and doc.get('commit_status') == 'complete'
                    and doc.get('width_bytes') == 4 and doc.get('byte_enable') == 15)
        address = self.cpu.waiting_instruction_address
        return bool(self.effect and type(address) is int
            and self.program_end <= address < self.instruction_end
            and self.cpu.memory.instruction_slot_unmaterialized(address)
            and self.cpu._pending_data is None and not self.cpu._queued_mmio)


@dataclass
class R1Session:
    session: object
    runner: object
    registers: object
    decoder: object
    authority: object
    observer: object
    space: GpioActionSpace
    bootstrap: object
    audit_all_components: bool = False
    _closed: bool = field(default=False, init=False)

    def begin(self, *, max_warmup_rounds=256):
        if self._closed:
            raise ValueError('R1 session is closed')
        if type(max_warmup_rounds) is not int or not 1 <= max_warmup_rounds <= 1024:
            raise ValueError('bounded warmup rounds required')
        # Manifest construction validates the configured receipt before begin.
        for component in (tuple(self.runner.sessions) if self.audit_all_components else ('gpio_b',)):
            self.runner.sessions[component].prepare_local()
        self.session.begin()
        for _ in range(max_warmup_rounds):
            if self.runner.sessions['cpu'].waiting_instruction_address == self.bootstrap.instruction_start:
                return
            receipt = self.session.advance_initial(self.bootstrap.template.schedule_order)
            if receipt.status != 'running' or receipt.violations:
                raise RuntimeError('R1 bootstrap did not remain running')
        raise RuntimeError('R1 bootstrap did not reach the online CPU slot')

    def field_state(self):
        if self._closed:
            return dict(status='unknown', reason='R1 session is closed')
        return read_gpio_field_current(self.observer,
            expected_epoch=self.runner.sessions['gpio_b'].reset_epoch)

    def submit(self, decision, *, case_id, replay_advance_count=None, deadline_ns=None):
        if self._closed:
            raise ValueError('R1 session is closed')
        stop_options = dict(replay_advance_count=replay_advance_count, deadline_ns=deadline_ns)
        # Validate bounds before preparation or gate registration.
        _bounded_stop(lambda index: False, max_advances=self.registers.advance_rounds, **stop_options)
        _check_deadline(deadline_ns, replay_advance_count)
        action = self.space.catalog.get(decision.action_id)
        if action.operator != 'external_pin_event':
            request = self.space.request(decision, case_id=case_id)
            prepared = self.registers.prepare(request)
            boundary = _ProgramBoundary(self.runner, self.runner.sessions['cpu'],
                program_end=prepared.source.address + len(prepared.source.data),
                instruction_end=self.bootstrap.instruction_end, request=request)
            stop = _bounded_stop(boundary, max_advances=len(prepared.case.advances), **stop_options)
            _check_deadline(deadline_ns, replay_advance_count)
            return self.registers.submit(request, expected_manifest=prepared.document(),
                                         stop_after_advance=stop)
        from .gpio_actions import validate_pin_session
        validate_pin_session(self.session)
        request = self.space.external_request(decision, case_id=case_id)
        prepared = self.registers.prepare_external(request)
        cpu = self.runner.sessions['cpu']
        fragment = prepared.case.support_instructions[0]
        end = fragment.address + len(fragment.data)
        def at_next_slot(index):
            address = cpu.waiting_instruction_address
            return (type(address) is int and end <= address < self.bootstrap.instruction_end
                    and cpu.memory.instruction_slot_unmaterialized(address)
                    and cpu._pending_data is None and not cpu._queued_mmio)
        stop = _bounded_stop(at_next_slot, max_advances=len(prepared.case.advances), **stop_options)
        _check_deadline(deadline_ns, replay_advance_count)
        return self.registers.submit_external(request, expected_manifest=prepared.document(),
                                              stop_after_advance=stop)

    def close(self, primary_error=None):
        if self._closed:
            return
        from myfuzz.runtime.generic_campaign import _close_runtime_resources
        _close_runtime_resources(self, (), primary_error, 'R1')
        self._closed = True


def _r1_factory(cache_dir):
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_factory,
        make_ibex_pulp_dual_source_stream_bootstrap,
        make_ibex_pulp_dual_source_online_decoder)
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap, result_slot_readback=True)
    factory = make_ibex_pulp_dual_source_factory(Path(cache_dir), gpio_consumption=True,
        physical_observations=True, source_actions=True, memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256=decoder.runtime_contract.identity_sha256)
    return bootstrap, decoder, factory


def _install_r1_runtime(session, decoder, *, advance_rounds, enable_external, bootstrap=None):
    from myfuzz.scenario.ibex_pulp_dual_source import ROOT
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    runner = session.runner
    authority = GpioRegisterVersionAuthority(runner.sessions['gpio_b'])
    observer = install_gpio_relation_consumer(runner, authority, target_id='gpio_b',
        register='gpioen', bit_lo=8, width=1,
        runtime_contract_sha256=decoder.runtime_contract.identity_sha256, session=session)
    if bootstrap is not None:
        session.declare_instruction_slots('cpu', bootstrap.instruction_start, bootstrap.instruction_count)
    sidecar = ROOT / 'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json'
    registers = RegisterProgramRuntime(session, cpu_component='cpu',
        sidecars={'gpio_a': sidecar, 'gpio_b': sidecar}, advance_rounds=advance_rounds,
        max_program_bytes=64, max_records=256,
        external_sources=external_pin_sources_from_decoder(decoder) if enable_external else ())
    return registers, authority, observer


def r1_replay_factories(cache_dir, *, advance_rounds=96, enable_external=True,
                        audit_all_components=False):
    """Reuse the original R1 construction with observers bound to the fresh session."""
    bootstrap, decoder, construct = _r1_factory(cache_dir)
    def factory():
        runner = construct()
        try:
            for component in (tuple(runner.sessions) if audit_all_components else ('gpio_b',)):
                runner.sessions[component].configure_built_executable_receipt()
            return runner
        except BaseException as error:
            from myfuzz.runtime.generic_campaign import _close_runtime_resources
            _close_runtime_resources(SimpleNamespace(runner=runner, session=None), (), error, 'R1 replay construction')
            raise
    def runtime_factory(session):
        return _install_r1_runtime(session, decoder, advance_rounds=advance_rounds,
                                   enable_external=enable_external)[0]
    return factory, runtime_factory


def create_r1_session(*, cache_dir, advance_rounds=48, enable_external=True,
                      audit_all_components=False):
    """Prepare one CPU/configuration/pin/observer session without starting RTL."""
    if type(advance_rounds) is not int or not 1 <= advance_rounds <= 512:
        raise ValueError('bounded register advance rounds required')
    if type(enable_external) is not bool or type(audit_all_components) is not bool:
        raise ValueError('boolean R1 execution options required')
    from myfuzz.scenario.ibex_pulp_dual_source import RESULT_ADDRESS
    from myfuzz.scenario.session_runtime import ScenarioSession
    bootstrap, decoder, factory = _r1_factory(cache_dir)
    runner, session = factory(), None
    try:
        session = ScenarioSession(bootstrap.template, runner, checker=None)
        registers, authority, observer = _install_r1_runtime(session, decoder,
            advance_rounds=advance_rounds, enable_external=enable_external, bootstrap=bootstrap)
        for component in (tuple(runner.sessions) if audit_all_components else ('gpio_b',)):
            runner.sessions[component].configure_built_executable_receipt()
        return R1Session(session, runner, registers, decoder, authority, observer,
            GpioActionSpace(result_address=RESULT_ADDRESS + 4), bootstrap,
            audit_all_components=audit_all_components)
    except BaseException as error:
        from myfuzz.runtime.generic_campaign import _close_runtime_resources
        _close_runtime_resources(SimpleNamespace(session=session, runner=runner), (), error, 'R1 construction')
        raise
