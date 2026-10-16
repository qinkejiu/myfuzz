"""Raw receipt epoch schema is part of the generated artifact identity."""
import pytest

from tests.local_harness.test_generic_apb3_register_real import artifact as apb_artifact, request as apb_request
from tests.local_harness.test_generic_tlul_register_real import artifact as tl_artifact, request as tl_request
from tests.local_harness.test_generic_wishbone_register_real import artifact as wb_artifact, request as wb_request


@pytest.mark.parametrize('artifact,request_factory,component', [
    (apb_artifact, apb_request, 'timer'),
    (tl_artifact, tl_request, 'rv_timer'),
    (wb_artifact, wb_request, 'zipcpu_timer'),
])
def test_new_generic_artifact_declares_raw_observation_schema(artifact, request_factory, component):
    generated = artifact(request_factory(component))
    assert generated.runtime_document.get('raw_observation_schema_version') == 'ip_raw_observation.v1'
    assert 'artifact_digest' in generated.runtime_document
