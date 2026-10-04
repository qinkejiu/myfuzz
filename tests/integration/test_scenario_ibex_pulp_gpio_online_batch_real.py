"""Online B GPIO inputs drive one live Ibex ISR/GPIO A testcase."""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario import (BatchSourceEvent, ScenarioBatchRecorder,
                            ScenarioBatchCodec, replay_scenario_batch)
from myfuzz.scenario import checker
from tests.integration.test_scenario_ibex_pulp_gpio_reverse_generated_real import (
    make_reverse_factory, reverse_genome)


def online_template():
    base = reverse_genome(0x49)
    return replace(base, testcase_id="ibex-pulp-gpio-online-stateful-batch",
                   max_steps=900, actions=(), reset_actions=(), quiesce_steps=0)


def _cpu_step_observations(events, component):
    """Use raw local samples where present, matching scheduler observation order."""
    step_events = [event for event in events
                   if event.get("component") == component
                   and event.get("kind") is None and "outputs" in event]
    sampled = {event.get("component") for event in events
               if event.get("kind") == "local_tick_sample"}
    observations = [event["outputs"] for event in events
                    if event.get("kind") == "local_tick_sample"
                    and event.get("component") == component]
    if component not in sampled:
        observations.extend(event["outputs"] for event in step_events)
    return observations


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for pinned RTL")
class OnlineIbexPulpGpioBatchTests(unittest.TestCase):
    def test_live_inputs_cross_real_rtl_and_replay_as_one_stateful_testcase(self):
        with tempfile.TemporaryDirectory(prefix="myfuzz-ibex-pulp-online-") as directory:
            cache = Path(os.environ.get("MYFUZZ_IBEX_GPIO_CACHE",
                                        Path(directory) / "cache"))
            factory, runners = make_reverse_factory(cache)
            runner = factory()
            cpu = runner.sessions["cpu"]
            memory_generation = cpu.memory.generation
            recorder = ScenarioBatchRecorder(online_template(), runner)
            recorder.begin()

            schedule = recorder.template.schedule_order
            request_accepts = 0
            response_consumes = 0
            previous_request_accept = False
            previous_response_consume = False
            first_request_tick = None
            next_rise_tick = None
            rise_values = (0x49, 0x81, 0xff)
            rise_index = 0
            admissions = []
            final_output_tick = None
            result_values = []
            gpio_a_write_values = []
            gpio_a_output_values = []

            def admit(action_id, value):
                event = BatchSourceEvent(action_id, "gpio_b", "gpio_in", value,
                                         bit_offset=8, width=8)
                recorder.submit_source_event(event)
                admissions.append((action_id, value, runner.local_ticks["cpu"],
                                   runner.event_count))

            def next_round_rise(action_id):
                nonlocal rise_index, next_rise_tick
                if rise_index >= len(rise_values):
                    raise AssertionError("unexpected fourth external GPIO rise")
                value = rise_values[rise_index]
                rise_index += 1
                admit(action_id, value)
                next_rise_tick = None

            for step_index in range(recorder.template.max_steps):
                component = schedule[step_index % len(schedule)]
                before = runner.event_count
                recorder.advance((component,))
                window = runner.events_since(before)
                result_values.extend(event["value"] for event in window
                                     if event.get("kind") == "memory_write"
                                     and event.get("component") == "cpu"
                                     and event.get("address") == 0x20000)
                gpio_a_write_values.extend(event["write_value"] for event in window
                                           if event.get("kind") == "mmio_delivery"
                                           and event.get("device_id") == "gpio_a"
                                           and event.get("offset") == 0x0c
                                           and event.get("write"))
                gpio_a_output_values.extend(event["outputs"]["gpio_out"]
                                            for event in window
                                            if event.get("component") == "gpio_a"
                                            and event.get("outputs", {}).get("gpio_out")
                                            in rise_values)
                if component == "cpu":
                    for outputs in _cpu_step_observations(window, "cpu"):
                        req = outputs.get("data_req_accepted") == 1
                        rsp = outputs.get("data_rsp_consumed") == 1
                        if req and not previous_request_accept:
                            request_accepts += 1
                            if request_accepts == 4:
                                first_request_tick = runner.local_ticks["cpu"]
                        if rsp and not previous_response_consume:
                            response_consumes += 1
                            if response_consumes in (5, 10) and rise_index in (1, 2):
                                admit(f"gpio-b-fall-after-round-{rise_index}", 0)
                                next_rise_tick = runner.local_ticks["cpu"] + 64
                        previous_request_accept = req
                        previous_response_consume = rsp

                    cpu_tick = runner.local_ticks["cpu"]
                    if rise_index == 0 and first_request_tick is not None:
                        if cpu_tick >= first_request_tick + 8:
                            next_round_rise("gpio-b-rise-49")
                    elif next_rise_tick is not None and cpu_tick >= next_rise_tick:
                        value = rise_values[rise_index]
                        next_round_rise(f"gpio-b-rise-{value:02x}")

                # Stop only after the third stored value reached real GPIO A
                # and the CPU has had a short local settle window.
                if (len(result_values) == len(gpio_a_write_values) == 3
                        and all(value in gpio_a_output_values for value in rise_values)):
                    if final_output_tick is None:
                        final_output_tick = runner.local_ticks["cpu"]
                if (final_output_tick is not None
                        and runner.local_ticks["cpu"] >= final_output_tick + 16):
                    break

            trace = recorder.finish()
            self.assertEqual("complete", trace.status)
            self.assertEqual([0x49, 0, 0x81, 0, 0xff],
                             [value for _, value, _, _ in admissions])
            self.assertEqual(5, sum(isinstance(command, BatchSourceEvent)
                                    for command in recorder.plan.commands))
            self.assertEqual(recorder.plan,
                             ScenarioBatchCodec.decode(
                                 ScenarioBatchCodec.encode(recorder.plan)))

            events = trace.events
            self.assertFalse(any(event.get("kind") == "reset_barrier" for event in events))
            self.assertEqual(3, sum(event.get("kind") == "initial_image"
                                    for event in events))
            self.assertEqual(memory_generation, cpu.memory.generation)
            self.assertEqual([0x49, 0x81, 0xff], [event["value"] for event in events
                             if event.get("kind") == "memory_write"
                             and event.get("component") == "cpu"
                             and event.get("address") == 0x20000])
            self.assertEqual([0x4900, 0x8100, 0xff00], [event["read_value"]
                             for event in events if event.get("kind") == "mmio_delivery"
                             and event.get("device_id") == "gpio_b"
                             and event.get("offset") == 8 and not event.get("write")])
            self.assertEqual([0x49, 0x81, 0xff], [event["write_value"]
                             for event in events if event.get("kind") == "mmio_delivery"
                             and event.get("device_id") == "gpio_a"
                             and event.get("offset") == 0x0c and event.get("write")])

            gpio_a_outputs = [event["outputs"]["gpio_out"] for event in events
                              if event.get("component") == "gpio_a"
                              and "gpio_out" in event.get("outputs", {})]
            for value in (0x49, 0x81, 0xff):
                self.assertIn(value, gpio_a_outputs)

            irq_sources = [event for event in events if event.get("kind") == "source_start"
                           and tuple(event.get("source", ())) == ("gpio_b", "irq")
                           and tuple(event.get("target", ())) == ("cpu", "irq")]
            irq_pulses = [event for event in events if event.get("kind") == "pulse_start"
                          and tuple(event.get("source", ())) == ("gpio_b", "irq")
                          and tuple(event.get("target", ())) == ("cpu", "irq")]
            self.assertEqual(3, len(irq_sources))
            self.assertEqual(3, len(irq_pulses))
            cpu_irq_high = [event for event in events if event.get("component") == "cpu"
                            and event.get("inputs", {}).get("irq") == 1]
            self.assertGreaterEqual(len(cpu_irq_high), 3)
            cpu_isr_vectors = [event for event in events
                               if event.get("component") == "cpu"
                               and event.get("outputs", {}).get("instr_req_accepted") == 1
                               and event.get("outputs", {}).get("instr_addr") == 0x1012c]
            self.assertEqual(3, len(cpu_isr_vectors))
            self.assertGreaterEqual(request_accepts, 4)
            self.assertGreaterEqual(response_consumes, 10)

            result = cpu.memory.read(0x20000, 4,
                                     transaction_id="online-final-result")
            self.assertEqual(0xff, result.value)
            first_round = checker.check_pulp_gpio_reverse_irq_chain(
                events, external_byte=0x49)
            self.assertTrue(first_round["complete"], first_round)

            replay = replay_scenario_batch(recorder.plan, factory, trace)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertEqual(2, len(runners))
            self.assertIsNot(runners[0], runners[1])
            self.assertEqual(trace.events, replay.actual_trace.events)
            self.assertEqual(trace.local_ticks, replay.actual_trace.local_ticks)


if __name__ == "__main__":
    unittest.main()
