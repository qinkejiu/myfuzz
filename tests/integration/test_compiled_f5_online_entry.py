"""Production F5 preparation is checked before the real factory may start."""
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.integration import ibex_pulp_online as online
from myfuzz.runtime.preparation import create_preparation
from myfuzz.scenario.session_runtime import ScenarioSession

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'configs/scenarios/compiled-f5-ibex-pulp-gpio'
CAPABILITY = ROOT / 'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json'


def test_f5_preparation_crosswalk_is_consumed_before_begin_and_rechecked(tmp_path):
    context = create_preparation(base_dir=ROOT, compose_path=CONFIG / 'compose.json',
        capability_paths=(CAPABILITY,), supplement_path=CONFIG / 'execution_supplement.json',
        generated_dir=tmp_path / 'generated', flow_ids=('F5',))
    def no_start(*, bootstrap, decoder, factory, **options):
        runner = factory()
        gate = factory.new_source_action_gate() if options['source_actions'] else None
        session = ScenarioSession(bootstrap.template, runner, prerequisite_gate=gate)
        session.declare_instruction_slots('cpu', bootstrap.instruction_start, bootstrap.instruction_count)
        session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                        decoder.runtime_paths, source_ownership=decoder.ownership)
        return online.IbexPulpOnlineRuntime(session, decoder, None, factory)
    try:
        with patch.object(online, 'make_pulp_dual_source_online_runtime', no_start), \
             patch('subprocess.Popen', side_effect=AssertionError('must not start native')):
            runtime = online.make_ibex_pulp_online_runtime(cache_dir=tmp_path / 'cache',
                run_id='f5-software', f5_only=True, preparation_context=context)
            assert runtime.compiled_f5_crosswalk['runtime_enforcement'] == 'topology_only'
            assert runtime.compiled_f5_crosswalk['source']['physical_bit_offset'] == 8
            assert runtime.factory().bindings == runtime.session.runner.bindings
            # A software-only spy checks what the actual submit boundary receives;
            # it does not claim any RTL execution or IRQ observation.
            with patch.object(runtime.session, 'submit_case', return_value='software-receipt') as submit:
                assert runtime.submit_f5(bytes.fromhex('0000000100000000')) == 'software-receipt'
                case = submit.call_args.args[0]
                assert (case.source.value, case.source.bit_offset, case.source.width) == (1, 8, 1)
                assert len(case.support_instructions) == 1
                assert runtime.decoder.instruction_cursor == runtime.decoder.instruction_start + 16
            inputs = context.compiled_inputs()
            path = next(row for row in inputs['compiled']['paths'] if row['flow_id'] == 'F5')
            path['runtime_path_identity'] = 'tampered'
            with pytest.raises(ValueError):
                runtime.factory()
            with patch.object(runtime.session, 'submit_case') as submit:
                with pytest.raises(ValueError):
                    runtime.submit_f5(bytes.fromhex('0000000100000000'))
                submit.assert_not_called()
    finally:
        context.close()
