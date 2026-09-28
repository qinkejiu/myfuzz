"""Importable software harness used to exercise the evidence replay CLI."""

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


class Session:
    max_final_state_growth_bytes_per_operation = 4096
    max_evidence_record_bytes = 4096

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


def make_runner():
    ownership = compile_ownership(
        (InputField("gpio", "pin", 1),),
        (InputOwner("gpio", "pin", 0, 1, "source", "external"),))
    return ScenarioRunner(sessions={"gpio": Session()},
                          ownership=ownership, bindings=())
