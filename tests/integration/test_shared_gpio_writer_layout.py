"""Use the actual GPIO D3 candidate ABI, including its external pin slice."""
import pytest
from tests.integration.test_shared_f5_support_binding import all_six


def test_real_GPIOEN_records_preserve_the_pin_slice(all_six):
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout, CandidateLayoutError
    from myfuzz.integration.shared_f6_slots import declare_shared_writer
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from tests.integration.test_compiled_f6_contract import ROOT
    inputs=all_six.compiled_inputs()
    path,=[p for p in inputs['compiled']['paths'] if p['flow_id']=='F4' and p['status']=='executable']
    layout=compile_candidate_layout(path)
    assert layout.byte_length==5
    stream,=[s for s in layout.slices if s.kind=='cpu_mmio_stream']
    pin,=[s for s in layout.slices if s.kind=='external_pin']
    assert stream.width==32 and pin.width==1 and pin.bit_offset==8
    admission=admit_compiled_f6_runtime_path(artifacts=dict(all_six.artifacts),compiled_inputs=inputs,base_dir=ROOT)
    slots=admission['execution_contract']['program_contract']['shared_slots']
    for value,raw in ((0x100,'0001000000'),(0x101,'0101000000')):
        encoded=layout.encode({stream.source_id:value,pin.source_id:0})
        assert encoded.hex()==raw
        declaration=declare_shared_writer(inputs,slots,raw=encoded,slot_index=0)
        assert declaration['candidate']['value']==value
        with pytest.raises(CandidateLayoutError,match='record-length'):
            declare_shared_writer(inputs,slots,raw=encoded[:4],slot_index=0)
