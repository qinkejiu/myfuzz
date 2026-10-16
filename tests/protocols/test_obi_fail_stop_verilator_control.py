"""Software controls for the explicit same-testbench Verilator gate."""
from unittest.mock import patch
import subprocess
import pytest
from tests.protocols import test_obi_processor_memory_adapter_rtl as adapter_tests


def invoke(compile_rc=0, native_rc=134, native_text='OBI backend error cannot be represented'):
    case=adapter_tests.ObiProcessorMemoryAdapterRtlTests()
    replies=[subprocess.CompletedProcess([],compile_rc,'compile stdout','compile stderr'),
             subprocess.CompletedProcess([],native_rc,native_text,'native stderr')]
    with patch('shutil.which',return_value='/tools/verilator'),patch('subprocess.run',side_effect=replies) as run:
        case.test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel_verilator()
    return run


def test_same_tb_verilator_build_and_nonzero_fatal_are_required(capsys):
    calls=invoke().call_args_list
    compile_args=calls[0].args[0]
    assert compile_args[0]=='/tools/verilator'
    assert all(flag in compile_args for flag in ('--binary','--timing','--assert','--top-module','--Mdir'))
    assert compile_args[compile_args.index('-j')+1]=='1'
    assert compile_args[-2].endswith('obi_processor_memory_adapter.sv')
    assert compile_args[-1].endswith('no_error.sv')
    assert calls[1].args[0][0].endswith('/obj/no_error')
    assert 'OBI_FAIL_STOP_RESULT' in capsys.readouterr().out


@pytest.mark.parametrize('compile_rc,native_rc,text',[(1,134,'OBI backend error cannot be represented'),
    (0,0,'OBI backend error cannot be represented'),(0,134,'backend error was silently accepted')])
def test_build_failure_zero_exit_and_wrong_fatal_are_not_passes(compile_rc,native_rc,text):
    with pytest.raises(AssertionError):invoke(compile_rc,native_rc,text)


def test_both_tools_compile_identical_original_stimulus():
    import hashlib
    testbenches=[]
    def run(command,**kwargs):
        if command[-1].endswith('.sv'):
            from pathlib import Path
            testbenches.append(Path(command[-1]).read_bytes())
            return subprocess.CompletedProcess(command,0,'','')
        return subprocess.CompletedProcess(command,134,'OBI backend error cannot be represented','')
    case=adapter_tests.ObiProcessorMemoryAdapterRtlTests()
    with patch('shutil.which',side_effect=lambda name:'/tools/'+name),patch('subprocess.run',side_effect=run):
        case.test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel()
        case.test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel_verilator()
    assert len(testbenches)==2 and testbenches[0]==testbenches[1]
    assert hashlib.sha256(testbenches[0]).hexdigest()=='83b46a7a6fb8dacc15dfe19a8b04926215877ce867003944670648d11153dc39'


def test_absent_verilator_is_explicit_skip_and_runs_no_process():
    import unittest
    with patch('shutil.which',return_value=None),patch('subprocess.run') as run:
        with pytest.raises(unittest.SkipTest,match='Verilator is not installed'):
            adapter_tests.ObiProcessorMemoryAdapterRtlTests().test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel_verilator()
    run.assert_not_called()
