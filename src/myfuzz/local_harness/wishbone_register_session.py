"""Persistent generic Wishbone register and physical-output observation session."""
from __future__ import annotations

from .tlul_register_session import GeneratedTlulRegisterSession


class GeneratedWishboneRegisterSession(GeneratedTlulRegisterSession):
    artifact_kind = 'wishbone_register_observe'
    step_operation = 'STEP_WB_REG'
    access_operation = 'ACCESS_WB_REG'

    def __init__(self, artifact, **kwargs):
        super().__init__(artifact, **kwargs)
        self._partial_write = artifact.plan.profile.capabilities['partial_write']

    def identity_document(self):
        doc = super().identity_document()
        doc.pop('tlul_register_service_schema_version')
        doc['wishbone_register_service_schema_version'] = 'generated_wishbone_register_observe.v1'
        return doc

    def _access(self, write, offset, value=0, be=15):
        if write and not self._partial_write and be != 15:
            raise ValueError('Wishbone target requires full-word writes')
        return super()._access(write, offset, value, be)
