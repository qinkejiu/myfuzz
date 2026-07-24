"""Argument adapter for applications that supply composition/runtime callables."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys
from typing import TextIO

from .pipeline import CompositionProducer, RuntimePreparer, run_candidate_pipeline


def run_pipeline_cli(
    argv: Sequence[str],
    *,
    composition_producer: CompositionProducer,
    runtime_preparer: RuntimePreparer,
    stdout: TextIO | None = None,
) -> int:
    """Parse stable CLI arguments while keeping producer selection injectable."""
    parser = argparse.ArgumentParser(prog="myfuzz-integration")
    parser.add_argument("--input-config", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--top-k", required=True, type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--memory-state-path", type=Path)
    arguments = parser.parse_args(tuple(argv))
    result = run_candidate_pipeline(
        arguments.input_config,
        output_dir=arguments.output_dir,
        top_k=arguments.top_k,
        dry_run=arguments.dry_run,
        composition_producer=composition_producer,
        runtime_preparer=runtime_preparer,
        memory_state_path=arguments.memory_state_path,
    )
    destination = stdout if stdout is not None else sys.stdout
    destination.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


__all__ = ["run_pipeline_cli"]
