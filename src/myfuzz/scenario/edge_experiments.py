"""Isolated real RTL factories for the declared A-to-B dataflow controls."""

from __future__ import annotations

from .examples import make_ibex_two_gpio_runner
from .ownership import InputField, InputOwner, compile_ownership
from .runner import Binding, ScenarioRunner


def make_cut_a_to_b_runner() -> ScenarioRunner:
    """Remove only the A output to B input edge from the real three DUT scene."""
    baseline = make_ibex_two_gpio_runner()
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
         InputField("gpio_b", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
         InputOwner("gpio_b", "gpio_in", 0, 32, "fixed", "constant_zero")))
    return ScenarioRunner(
        sessions=baseline.sessions,
        ownership=ownership,
        bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))


def make_fixed_b_input_runner() -> ScenarioRunner:
    """Drive B from an explicit fixed test source while A still runs real RTL."""
    baseline = make_ibex_two_gpio_runner()
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
         InputField("gpio_b", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
         InputOwner("gpio_b", "gpio_in", 0, 8, "source", "isolated_fixed_b"),
         InputOwner("gpio_b", "gpio_in", 8, 24, "fixed", "constant_zero")))
    return ScenarioRunner(
        sessions=baseline.sessions,
        ownership=ownership,
        bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
