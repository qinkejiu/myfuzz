"""Closed raw8 pin inputs on the already bound shared F5 runtime."""
from dataclasses import dataclass

from myfuzz.runtime.contracts import GenericRuntimeRefused, require_identifier
from .storage import LoweredCase, _require_hex_record


@dataclass(frozen=True)
class PinFlowContext:
    plan_sha256: str
    path_id: str
    source_id: str
    flow_id: str = 'F5'

    def document(self):
        return {'schema_version':'generic_pin_flow_context.v1','plan_sha256':self.plan_sha256,
                'path_id':self.path_id,'source_id':self.source_id,'flow_id':self.flow_id}


class PinFlowKernel:
    kernel_id='pin.kernel.v1'

    def prepare(self,bound_plan,path_id):
        rows=[p for p in bound_plan.plan.document().get('paths',())
              if p.get('flow_id')=='F5' and p.get('path_id')==path_id]
        if len(rows)!=1:
            raise GenericRuntimeRefused('generic-plan-mismatch','/path_id')
        pins=[s for s in rows[0]['sources'] if s.get('kind')=='external_pin'
              and s.get('origin')=='fuzzable' and s.get('width')==1]
        if len(pins)!=1:
            raise GenericRuntimeRefused('generic-source-unverified','/path/sources')
        return PinFlowContext(bound_plan.plan_sha256,path_id,pins[0]['source_id'])

    def lower(self,context,case):
        if type(case) is not dict or set(case)!={'testcase_id','path_id','source_id','raw_records_hex'}:
            raise GenericRuntimeRefused('generic-case-shape','/case')
        require_identifier(case['testcase_id'],'/case/testcase_id')
        if case['path_id']!=context.path_id or case['source_id']!=context.source_id:
            raise GenericRuntimeRefused('generic-source-unverified','/case/source_id')
        rows=case['raw_records_hex']
        if type(rows) is not list or not rows:
            raise GenericRuntimeRefused('generic-case-shape','/case/raw_records_hex')
        records=tuple(_require_hex_record(r,'/case/raw_records_hex') for r in rows)
        if any(len(raw)!=8 for raw in records):
            raise GenericRuntimeRefused('generic-case-shape','/case/raw_records_hex')
        return LoweredCase(case['testcase_id'],context.path_id,context.source_id,'F5',8,records)

    def capture(self,context,receipt):
        # Actual submissions remain documentary until a live consumer exists.
        if receipt.get('schema_version')!='compiled_shared_F5_case.v1' or receipt.get('flow_id')!='F5':
            raise GenericRuntimeRefused('generic-evidence-missing','/receipt')
        return ()

    def feedback(self,context,claims):
        return ()
