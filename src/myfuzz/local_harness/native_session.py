"""Generic single-outstanding completion memory service over generated RTL."""
from __future__ import annotations
import copy
from collections.abc import Mapping
from .session import GeneratedLocalSession
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter


class GeneratedNativeMemorySession(GeneratedLocalSession):
    """RAM/ROM service with optional declared-window MMIO; errors never fake completion.

    No IRQ or instruction decoding is synthesized by the environment. An
    optional typed physical instruction marker remains an RTL observation.

    An optional :class:`~myfuzz.scenario.router.DataflowRouter` may be supplied
    so a CPU beat whose address falls inside a declared device window is served
    by that window's real target instead of local RAM. Routing is opt-in:
    without a router this session behaves exactly as before (RAM/ROM only), so
    every existing identity and budget stays unchanged.

    The router is addressed by the 32-bit word beat (``address & ~3``), matching
    the other memory CPU sessions, and only one target access is performed per
    local step: the beat is serviced inline and its response becomes the beat's
    read response, so an MMIO read is real device data rather than a
    synthesised value. Deferred (queued) MMIO delivery is deliberately not
    implemented here.
    """
    artifact_kind = 'native_memory_cpu'
    max_driver_samples_per_operation=1
    max_memory_materialized_bytes_per_operation=4
    max_pending_responses=1
    max_local_ticks_per_step=1
    max_transaction_events_per_step=1
    max_mmio_target_accesses_per_step=0
    runtime_kind='native_memory_cpu'
    service_schema='generated_native_memory_service.v1'
    read_request_be=15

    def __init__(self,artifact,*,base_dir,cache_dir,memory,
                 router: DataflowRouter | None = None,**kwargs):
        if artifact.runtime_document.get('kind')!=self.runtime_kind or not isinstance(memory,PersistentMemory):
            raise ValueError('native completion CPU requires authenticated artifact and persistent memory')
        if router is not None and not isinstance(router, DataflowRouter):
            raise ValueError('native completion CPU router must be a DataflowRouter')
        super().__init__(artifact,base_dir=base_dir,cache_dir=cache_dir,**kwargs)
        self.memory=memory
        self.service=MemoryService(memory,TransactionLedger())
        self.router=router
        self.mmio_write_count=0
        self.mmio_read_count=0
        if router is not None:
            # One routed target access per local step; the beat is serviced
            # inline, so the driver reservation must admit it.
            self.max_mmio_target_accesses_per_step=1
        self._pending=None
        self._sequence_memory=0
        self._quiescing=False
        self.memory_write_count=0
        self.native_instruction_fetch_count=0
        self.accepted_addresses=[]
        self.last_samples=()
        self._online_instruction_slots=False
        self._native_bus_observer = None
        self._physical_tick_samples_enabled = False
        if 'native_completion_observation' in self._artifact_document:
            from myfuzz.scenario.native_cpu_events import NativeBusObserver
            self._native_bus_observer = NativeBusObserver(self)
            self._physical_tick_samples_enabled = True

    def declare_instruction_slots(self, address, count=1):
        """Opt in before startup; only an authenticated physical marker may gate fetches."""
        if self.process is not None or self._case_id is not None:
            raise RuntimeError('native instruction slots require pre-start declaration')
        marker=self._artifact_document.get('instruction_identity_observation')
        if not marker:
            raise ValueError('native online instructions require physical instruction identity')
        self.memory.declare_instruction_slots(address,count)
        self._online_instruction_slots=True

    @property
    def waiting_instruction_address(self):
        """Actual POST offered, not accepted, fetch waiting for a declared word."""
        if not self._online_instruction_slots or not self.last_samples:
            return None
        post=self.last_samples[-1]['post']
        backend=post['backend']
        marker=self._artifact_document['instruction_identity_observation']
        if (backend['m_req_valid'] and not backend['m_req_write']
                and post['physical'][marker] == 1
                and self.memory.instruction_slot_unmaterialized(backend['m_req_addr'])):
            return backend['m_req_addr']
        return None

    def accept_instructions(self,address,data,*,source_event_id):
        if not self._online_instruction_slots:
            raise ValueError('native instruction slots were not declared')
        return self.service.accept_instructions(address,data,source_event_id=source_event_id)

    def _native_request_ready(self,available):
        # Withheld readiness leaves the real adapter in REQUEST. Its original
        # finite timeout and request-stability checks still run on every tick.
        return int(bool(available) and self.waiting_instruction_address is None)

    def _check_native_online_acceptance(self,pre,sample):
        if not self._online_instruction_slots:
            return
        marker=self._artifact_document['instruction_identity_observation']
        if sample['pre']['physical'][marker] == 1:
            if pre['m_req_write'] or (self.router is not None and self.router.owns(pre['m_req_addr'])):
                raise ProtocolEnvironmentError('native instruction fetch cannot write or reach MMIO')

    def identity_document(self):
        return {**super().identity_document(),
                'native_service_schema_version':self.service_schema,
                'source_component':self.artifact.plan.request.instance_id,
                'memory_policy':'ram-rom-only'}

    @property
    def pending_responses(self):
        observer = self._native_bus_observer
        # Backend consumption precedes the real CPU handshake by one tick.
        # Keep that same outstanding transfer visible to normal quiesce.
        return int(self._pending is not None
                   or (observer is not None and observer.pending is not None))

    def begin_case(self,testcase_id):
        if self._native_bus_observer is not None and self._native_bus_observer.failed:
            raise RuntimeError('native bus observation is terminal')
        super().begin_case(testcase_id)
        self._pending=None;self._sequence_memory=0;self._quiescing=False;self.last_samples=()

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('native process is not running')
        self._quiescing=True

    def _service_accepted_request(self,key,address,write,be,value):
        """Serve one accepted beat; override to route declared MMIO windows.

        The base service is pure RAM/ROM: a write updates the persistent bytes
        and a read returns the current value.  A session constructed with a
        router first offers the beat to every declared device window, so an
        access inside one is answered by that window's real target.  Windows are
        keyed by the word beat, so a byte address inside a window still routes;
        ``step_local`` refuses unaligned addresses in the first place.

        Routing is deliberately absent from ``identity_document``: the native
        service identity is a strict closed set (see
        ``scenario.contracts._verify_generated_session``), so a routed session
        records the same identity as a RAM-only one.
        """
        router=self.router
        if router is not None:
            beat_address=address&~3
            if router.owns(beat_address):
                response=router.transact(self.service.ledger,key,address=beat_address,
                    write=bool(write),wdata=value,be=be,beat_bytes=4)
                if type(response) is not tuple or len(response)!=2:
                    raise ProtocolEnvironmentError('native routed target response malformed')
                if write:
                    self.mmio_write_count+=1
                else:
                    self.mmio_read_count+=1
                return response[0]
        if write:
            self.service.write(key,address,value,width_bytes=4,byte_enable=be)
            self.memory_write_count+=1
            return 0
        snapshot = self.service.read(key,address,width_bytes=4)
        if self._native_bus_observer is not None:
            self._native_bus_observer.bind_read_snapshot(key, snapshot)
        return snapshot.value

    def reset_local(self):
        cancelled=self.pending_responses
        if self._native_bus_observer is not None:
            self._native_bus_observer.cancel_reset()
        self._pending=None
        super().reset_local()
        return {'cancelled_responses':cancelled}

    def _abort(self):
        observer = getattr(self, '_native_bus_observer', None)
        if observer is not None:
            observer.failed = True
        super()._abort()

    def end_case(self):
        observer = self._native_bus_observer
        incomplete = (observer is not None and observer.pending is not None
                      and self.process is not None)
        primary = None
        if incomplete:
            observer.failed = True
            primary = ProtocolEnvironmentError('native bus transfer incomplete at close')
        try:
            super().end_case()
        except BaseException as cleanup:
            if primary is None:
                raise
            try:
                primary.add_note('native bus close cleanup: ' + repr(cleanup))
            except BaseException:
                pass
        if primary is not None:
            raise primary

    def _observe_verified_memory_edge(self, receipt):
        """Optional passive measurement, after receipt checks and before service."""
        return None

    def _record_native_bus_receipt(self, receipt, pending_response):
        if self._native_bus_observer is not None:
            try:
                self._native_bus_observer.observe(receipt, pending_response)
            except BaseException as primary:
                self._native_bus_observer.failed = True
                try:
                    self._abort()
                except BaseException as cleanup:
                    try:
                        primary.add_note('native bus observation cleanup: ' + repr(cleanup))
                    except BaseException:
                        pass
                raise

    @property
    def drain_tick_samples(self):
        # Absence of an opt-in stream must retain Runner's legacy output route.
        if self._native_bus_observer is None:
            return None
        return self._native_bus_observer.drain

    def step_local(self,inputs:Mapping[str,int]):
        if not isinstance(inputs,Mapping) or inputs:
            raise ValueError('native memory CPU has no declared external inputs')
        pending=self._pending
        controls=(self._native_request_ready(pending is None and not self._quiescing),int(pending is not None),pending[0] if pending else 0,0)
        receipt=self.command('STEP_MEMORY',controls)
        if receipt.status!='result' or receipt.new_ticks!=1:
            self._abort()
            raise ProtocolEnvironmentError('native completion fault: '+str(receipt.error_detail))
        payload=receipt.payload
        pre=payload['pre_backend']
        names=('m_req_ready','m_rsp_valid','m_rsp_rdata','m_rsp_error')
        if (any(pre[name]!=value for name,value in zip(names,controls))
            or payload['samples'][0]['pre']['backend']!=pre):
            raise ProtocolEnvironmentError('native command handshake observation mismatch')
        self.last_samples=tuple(copy.deepcopy(payload['samples']))
        self._observe_verified_memory_edge(receipt)
        self._record_native_bus_receipt(receipt, pending)
        accepted=int(bool(pre['m_req_valid'] and pre['m_req_ready']))
        consumed=int(bool(pre['m_rsp_valid'] and pre['m_rsp_ready']))
        if consumed:
            if pending is None:raise ProtocolEnvironmentError('native response without request')
            self._pending=None
        if accepted:
            if pending is not None:raise ProtocolEnvironmentError('native concurrent request')
            self._check_native_online_acceptance(pre,payload['samples'][0])
            address=pre['m_req_addr'];write=pre['m_req_write'];be=pre['m_req_be'];value=pre['m_req_wdata']
            if address%4 or (not write and be!=self.read_request_be):
                self._abort();raise ProtocolEnvironmentError('native unaligned or incomplete read')
            self._sequence_memory+=1
            key=TransactionKey('local-execution',self._case_id,self.artifact.plan.request.instance_id,
                self.reset_epoch,'memory',self._sequence_memory)
            try:
                response=self._service_accepted_request(key,address,write,be,value)
            except (ValueError,RuntimeError) as error:
                self._abort();raise ProtocolEnvironmentError('native backend error without completion') from error
            self._pending=(response,self._sequence_memory)
            self.accepted_addresses.append(address)
            marker=self._artifact_document.get('instruction_identity_observation')
            if marker and payload['samples'][0]['pre']['physical'][marker]:
                if write:self._abort();raise ProtocolEnvironmentError('instruction marker accompanied a write')
                self.native_instruction_fetch_count+=1
        self.memory.advance_step()
        physical=payload['observations']['physical']
        outputs={}
        for row in self._artifact_document['physical_exports']:
            if row['direction']=='output':
                raw=physical[row['runtime_name']]
                value=int(raw,16) if row['width']>64 else raw
                if type(value) is not int or not 0<=value<1<<row['width']:
                    raise ProtocolEnvironmentError('native physical output width mismatch')
                name=row['physical_port'];outputs[name]=outputs.get(name,0)|(value<<row['bit_lo'])
        return {**outputs,'data_req_valid':pre['m_req_valid'],'data_req_accepted':accepted,
            'data_write':pre['m_req_write'],'data_addr':pre['m_req_addr'],
            'data_wdata':pre['m_req_wdata'],'data_be':pre['m_req_be'],
            'data_rsp_consumed':consumed,'data_rsp_rdata':pending[0] if consumed else 0,
            'data_rsp_source_epoch':self.reset_epoch if consumed else 0,
            'data_rsp_source_sequence':pending[1] if consumed else 0,
            'driver_samples':copy.deepcopy(self.last_samples),
            'physical_observations':copy.deepcopy(physical)}
