"""Capture same-call F2 assertion inputs for the general capability report.

Consistency checks here do not issue native authority or promote a capability
tier. The runtime owns the live evidence; the report validates and describes it.
"""
from copy import deepcopy
import json
from myfuzz.scenario.capability_report import build_capability_report


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _capture(runtime):
    return dict(assertions=deepcopy(runtime.assertion_results()),
        assertion_evidence=dict(execution_binding=deepcopy(runtime.execution_binding.document()),
            path_id=runtime.path['path_id'],run_id=runtime.run_id,
            cases=deepcopy(runtime.assertion_case_evidence())))


def capture_f2_report_material(*,compiled,runtime,harness_set,fresh_verification):
    """Project checked outcomes using independently captured live case evidence."""
    if (type(fresh_verification) is not dict
            or not {'matches','first_difference','verification_scope'}<=set(fresh_verification)
            or fresh_verification['matches'] is not True
            or fresh_verification['first_difference'] is not None
            or fresh_verification['verification_scope']!='full'):
        raise ValueError('compiled-F2-report-full-fresh-required')
    material=_capture(runtime)
    report=build_capability_report(compiled,harness_set=harness_set,
        fresh_verification=deepcopy(fresh_verification),
        assertion_results=deepcopy(material['assertions']),
        assertion_evidence=deepcopy(material['assertion_evidence']))
    if _canonical(_capture(runtime))!=_canonical(material):
        raise ValueError('compiled-F2-report-input-drift')
    material['capability_report']=report
    return deepcopy(material)
