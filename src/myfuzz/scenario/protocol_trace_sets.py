"""Bounded multi-endpoint observation over one unchanged raw session journal."""
from .ip_protocol_events import IpProtocolEventNormalizer
from .ip_protocol_checker import IpProtocolChecker
from .ip_protocol_evidence import IpProtocolEvidenceConsumer
from .ip_base_coverage import IpBaseCoverageConsumer


class ProtocolTraceSetObserver:
    """Each endpoint has independent checker/proof state over the same raw ID."""
    def __init__(self, component, artifact):
        from myfuzz.local_harness.native_physical_observation import verify_cpu_obi_protocol_traces
        verify_cpu_obi_protocol_traces(artifact)
        document = artifact.runtime_document
        profile, request = artifact.plan.profile, artifact.plan.request
        traces = document['base_protocol_traces']['traces']
        self.entries = {}
        for trace in traces:
            endpoint = trace['endpoint_id']
            cfg = dict(component_id=profile.component_id,instance_id=request.instance_id,
                       protocol_trace=trace)
            if endpoint in self.entries:
                raise ValueError('protocol-trace-set-duplicate-endpoint')
            self.entries[endpoint] = dict(normalizer=IpProtocolEventNormalizer(**cfg),
                checker=IpProtocolChecker(**cfg),
                evidence=IpProtocolEvidenceConsumer({component:cfg},
                    runtime_contract_sha256=document['artifact_digest'],
                    max_pending=64,max_records=256,max_event_gap=4096),
                coverage=IpBaseCoverageConsumer(component_id=profile.component_id,
                    instance_id=request.instance_id,endpoint_protocols={endpoint:trace['protocol']},
                    max_pending=64))
        self.cursor = 0

    def report(self, journal):
        # A complete journal prefix includes scheduler/reset events as well as
        # raw/projections. Never renumber or fabricate a second raw stream.
        for index in range(self.cursor,len(journal)):
            event = journal[index]
            for entry in self.entries.values():
                entry['evidence'].consume(event)
                entry['coverage'].consume((event,),start_cursor=index)
        self.cursor = len(journal)
        return dict(schema_version='runner_protocol_trace_set_report.v1',
            proof_scope='protocol_boundary_only',cursor=self.cursor,
            endpoints={endpoint:dict(evidence=entry['evidence'].report(),
                coverage=entry['coverage'].snapshot()) for endpoint,entry in self.entries.items()})
