"""Shared normalisation for frozen driver-text snapshots.

``driver_renderer`` renders every kind through one C++ template, and after the
2026-10 snapshot freeze it gained env-gated DUT-eval timing instrumentation:

* four extra includes (``<chrono>``, ``<cstdlib>``, ``<fstream>``, ``<unistd.h>``);
* the ``dut_timing_dir``/``dut_eval_ns``/``dut_eval_count`` state block plus
  ``eval_dut()`` and ``write_dut_timing()``, inserted between
  ``using JsonObject = ...`` and ``static std::uint64_t local_ticks``;
* every ``dut.eval()`` call rewritten to ``eval_dut(dut)``;
* the closing ``write_dut_timing();``/``dut_timing_startup = false;`` calls.

The instrumentation is behaviour neutral when ``MYFUZZ_DUT_TIMING_DIR`` is
unset: :func:`..._eval_dut`'s fast path performs exactly one ``dut.eval()``, and
the timing JSON is only written to a directory the environment names.  Snapshots
that pin *rendered firmware text* therefore normalise both sides with
:func:`strip_dut_eval_timing` and compare the result byte for byte, so the
archived digests stay the reference of record.  Nothing beyond that one
instrumentation layer is dropped here; each caller still selects its own region
(:func:`main_region`) or its own extra tokens (:func:`drop_lines_with`) for
unrelated, equally declared drift.
"""
from __future__ import annotations

#: Includes the timing instrumentation adds ahead of the firmware body.
DUT_TIMING_INCLUDES = ('#include <chrono>\n', '#include <cstdlib>\n',
                       '#include <fstream>\n', '#include <unistd.h>\n')
#: Tokens that only the timing instrumentation emits.
DUT_TIMING_TOKENS = ('dut_timing', 'dut_eval_count', 'dut_eval_ns',
                     'write_dut_timing', 'MYFUZZ_DUT_TIMING_DIR')
_BLOCK_START = 'static const char *dut_timing_dir'
_BLOCK_END = 'static std::uint64_t local_ticks'


def strip_dut_eval_timing(text):
    """Return ``text`` with the DUT-eval timing instrumentation removed.

    Everything else is retained verbatim, so two texts that differ only by that
    instrumentation normalise to identical bytes.
    """
    for include in DUT_TIMING_INCLUDES:
        text = text.replace(include, '')
    start = text.find(_BLOCK_START)
    if start != -1:
        end = text.find(_BLOCK_END, start)
        if end != -1:
            text = text[:start] + text[end:]
    text = text.replace('@TIMED_DECLARATIONS@', '')
    text = text.replace('eval_dut(dut)', 'dut.eval()')
    return '\n'.join(line for line in text.split('\n')
                     if 'write_dut_timing();' not in line
                     and 'dut_timing_startup = false;' not in line)


def main_region(text):
    """Driver text from ``int main(`` on: the firmware body a snapshot pins."""
    return text[text.index('int main('):]


def drop_lines_with(text, tokens=DUT_TIMING_TOKENS):
    """Drop the lines carrying any of ``tokens`` (each caller names its own)."""
    return '\n'.join(line for line in text.splitlines()
                     if not any(token in line for token in tokens))
