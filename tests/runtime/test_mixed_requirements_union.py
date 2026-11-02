"""Shared endpoints must satisfy every selected flow's requirements."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.flows.mixed import MixedStorageKernel
from tests.runtime.test_storage_kernel import raw_path


def test_shared_endpoint_requirements_preserve_read_and_write_in_any_order():
    kernel = MixedStorageKernel()
    rows = [raw_path('F2'), raw_path('F4')]
    requirements = kernel.requirements(rows)
    assert requirements == kernel.requirements(list(reversed(rows)))
    assert all(row.operations == ('read', 'write') for row in requirements)
    for path in rows:
        for required in kernel._kernels[path['flow_id']].requirements(path):
            combined = next(row for row in requirements
                            if (row.role, row.endpoint_id) == (required.role, required.endpoint_id))
            assert set(required.evidence_obligations) <= set(combined.evidence_obligations)


def test_shared_endpoint_incompatible_tokens_are_refused():
    kernel = MixedStorageKernel()
    original = kernel._kernels['F4'].requirements(raw_path('F4'))
    kernel._kernels['F4'] = SimpleNamespace(requirements=lambda _: tuple(
        replace(row, data_width=64) for row in original))
    with pytest.raises(GenericRuntimeRefused) as error:
        kernel.requirements([raw_path('F2'), raw_path('F4')])
    assert error.value.code == 'generic-template-mismatch'


def test_requirements_dispatches_to_registered_kernel():
    kernel = MixedStorageKernel(include_memory=True)
    requirement = kernel._kernels['F2'].requirements(raw_path('F2'))[0]
    kernel._kernels['F1'] = SimpleNamespace(requirements=lambda _: (requirement,))
    assert kernel.requirements({'flow_id': 'F1'}) == (requirement,)


def test_registered_kernel_without_requirements_is_explicitly_refused():
    with pytest.raises(GenericRuntimeRefused) as error:
        MixedStorageKernel(include_memory=True).requirements({'flow_id': 'F1'})
    assert error.value.code == 'generic-semantic-unsupported'
