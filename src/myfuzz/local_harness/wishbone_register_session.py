"""Persistent generic Wishbone register and physical-output observation session."""
from __future__ import annotations

from copy import deepcopy
import json

from .tlul_register_session import GeneratedTlulRegisterSession

_ROUTED_CONTEXT_SCHEMA = 'wishbone_storage_routed_context.v1'
_DELIVERY_KEYS = frozenset({
    'source_transaction', 'device_id', 'window_base', 'window_size', 'address',
    'offset', 'write', 'value', 'be'})
_CONTEXT_SOURCE_KEYS = (
    'source_transaction', 'device_id', 'window_base', 'window_size',
    'address', 'offset', 'write', 'value')


class GeneratedWishboneRegisterSession(GeneratedTlulRegisterSession):
    artifact_kind = 'wishbone_register_observe'
    step_operation = 'STEP_WB_REG'
    access_operation = 'ACCESS_WB_REG'

    def __init__(self, artifact, **kwargs):
        super().__init__(artifact, **kwargs)
        self._partial_write = artifact.plan.profile.capabilities['partial_write']
        # Routed CPU-MMIO correlation state: one access at a time, and only
        # after a version authority of this exact session enabled the path.
        self._storage_active_context = None
        self._storage_last_access = None

    def identity_document(self):
        doc = super().identity_document()
        doc.pop('tlul_register_service_schema_version')
        doc['wishbone_register_service_schema_version'] = 'generated_wishbone_register_observe.v1'
        return doc

    def _access(self, write, offset, value=0, be=15):
        if write and not self._partial_write and be != 15:
            raise ValueError('Wishbone target requires full-word writes')
        return super()._access(write, offset, value, be)

    @property
    def routed_register_access_enabled(self):
        """True only for a started storage row with a registered exact issuer."""
        from myfuzz.scenario.wishbone_storage_register_version import (
            wishbone_storage_authority)
        self._check_artifact_stable()
        document = self._artifact_document
        if (document.get('kind') != self.artifact_kind
                or type(document.get('storage_observation')) is not dict
                or type(self._execution) is not str or not self._execution
                or type(self._case_id) is not str or not self._case_id):
            return False
        return wishbone_storage_authority(self) is not None

    def routed_register_access(self, source_transaction, *, address, offset,
                               write, value, be, delivery_context):
        """Drive one Router-delivered CPU access through the real command path.

        The routed context is correlation only: it is never source, reset or
        version authority.  Its measured ``tick`` and ``read_value`` are added
        by the authority only after the native receipt exists.
        """
        from dataclasses import asdict
        from myfuzz.scenario.ledger import TransactionKey
        from myfuzz.scenario.wishbone_storage_register_version import (
            revoke_wishbone_storage_authority, validate_pending_routed_context)
        if (not self.routed_register_access_enabled
                or type(source_transaction) is not TransactionKey
                or type(write) is not bool
                or any(type(item) is not int
                       for item in (address, offset, value, be))
                or not 0 <= address <= 0xffffffff
                or not 0 <= offset < self._window or offset % 4
                or not 0 <= value <= 0xffffffff
                or (not write and value != 0) or be != 15
                or self._storage_active_context is not None
                or self.process is None or self.process.poll() is not None):
            raise ValueError('wishbone-storage-routed-access-context-invalid')
        expected = dict(source_transaction=asdict(source_transaction),
                        address=address, offset=offset, write=write,
                        value=value, be=be)
        if (type(delivery_context) is not dict
                or set(delivery_context) != _DELIVERY_KEYS
                or type(delivery_context['device_id']) is not str
                or not delivery_context['device_id']
                or type(delivery_context['window_base']) is not int
                or not 0 <= delivery_context['window_base'] <= 0xffffffff
                or type(delivery_context['window_size']) is not int
                or delivery_context['window_size'] != self._window
                or address != delivery_context['window_base'] + offset
                or delivery_context['window_base'] + self._window > 1 << 32
                or json.dumps({key: delivery_context[key] for key in expected},
                              sort_keys=True, allow_nan=False)
                != json.dumps(expected, sort_keys=True, allow_nan=False)):
            raise ValueError('wishbone-storage-routed-delivery-mismatch')
        fields = (int(write), offset, value if write else 0, be)
        context = {key: deepcopy(delivery_context[key])
                   for key in _CONTEXT_SOURCE_KEYS}
        context.update(byte_enable=be, word_index=offset >> 2, read_value=0,
                       execution=self._execution,
                       reset_epoch=self.reset_epoch,
                       command_sequence=self._sequence + 1,
                       schema_version=_ROUTED_CONTEXT_SCHEMA,
                       source_authenticated=False)
        self._storage_active_context = context
        try:
            validate_pending_routed_context(
                self._storage_active_context, fields=fields,
                sequence=self._sequence + 1, execution=self._execution,
                epoch=self.reset_epoch, window=self._window)
            reply = self.command(self.access_operation, fields)
            result = self._take(reply)
            if result['error']:
                raise RuntimeError('actual storage Wishbone error')
            access_id = f'wishbone-storage:{self._execution}:{reply.sequence}'
            self._storage_last_access = (source_transaction, access_id)
            return dict(rdata=result['rdata'], target_access_id=access_id,
                        target_context_schema_version=_ROUTED_CONTEXT_SCHEMA,
                        source_authenticated=False)
        except BaseException:
            # A refusal after a real command cannot preserve an issuer scope.
            revoke_wishbone_storage_authority(self)
            raise
        finally:
            self._storage_active_context = None

    def routed_delivery_failed(self, source_transaction, access_id):
        from myfuzz.scenario.wishbone_storage_register_version import (
            revoke_wishbone_storage_authority)
        revoke_wishbone_storage_authority(self)
        if self._storage_last_access != (source_transaction, access_id):
            raise ValueError(
                'wishbone-storage-routed-terminal-context-mismatch')
        self._storage_last_access = None

    def command(self, operation, fields):
        """Bind the exact built receipt and the measured samples per command."""
        from myfuzz.scenario.wishbone_storage_register_version import (
            wishbone_storage_authority)
        authority = wishbone_storage_authority(self)
        if authority is None:
            return super().command(operation, fields)
        try:
            authority._actual_begin(self, operation, fields)
            receipt = super().command(operation, fields)
            authority._actual_command(self, operation, fields, receipt)
        except BaseException:
            authority._revoke()
            raise
        return receipt

    def end_case(self):
        primary = []
        try:
            return super().end_case()
        except BaseException as error:
            primary.append(error)
            raise
        finally:
            failure = self._close_storage_authority()
            if failure is not None:
                if primary:
                    primary[0].add_note(
                        'storage authority revoke failure: ' + repr(failure))
                else:
                    raise failure

    def reset_local(self):
        primary = []
        try:
            return super().reset_local()
        except BaseException as error:
            primary.append(error)
            raise
        finally:
            failure = self._close_storage_authority()
            if failure is not None:
                if primary:
                    primary[0].add_note(
                        'storage authority revoke failure: ' + repr(failure))
                else:
                    raise failure

    def _close_storage_authority(self):
        from myfuzz.scenario.wishbone_storage_register_version import (
            revoke_wishbone_storage_authority)
        try:
            revoke_wishbone_storage_authority(self)
        except BaseException as error:
            return error
        return None
