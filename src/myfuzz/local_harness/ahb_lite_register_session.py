"""Full-word persistent AHB-Lite register session on the shared beat transport."""
from .apb3_register_session import GeneratedApb3RegisterSession


class GeneratedAhbLiteRegisterSession(GeneratedApb3RegisterSession):
    artifact_kind = 'ahb_lite_register_observe'
    access_operation = 'ACCESS_AHB_REG'
    step_operation = 'STEP_AHB_REG'
    source_operation = 'SOURCE_AHB_REG'
    bind_operation = 'BIND_AHB_REG'
    transport_error_label = 'generic AHB-Lite'
    error_response_label = 'AHB-Lite target/transport'

    def identity_document(self):
        document = super().identity_document()
        document.pop('apb3_register_service_schema_version')
        document['ahb_lite_register_service_schema_version'] = 'generated_ahb_lite_register_observe.v1'
        return document
