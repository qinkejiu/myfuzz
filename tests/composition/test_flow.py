#!/usr/bin/env python3
"""Composition integration tests for the existing design-flow entry point."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.scripts import run_design_flow


ROOT = Path(__file__).resolve().parents[2]


def load_generate_composition_module():
    script = ROOT / "scripts" / "generate_composition.py"
    spec = importlib.util.spec_from_file_location("generate_composition_task4", script)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CompositionFlowTests(unittest.TestCase):
    def test_script_help_selects_composition_without_pythonpath(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        result = subprocess.run(
            [sys.executable, "src/myfuzz/scripts/run_design_flow.py", "--help"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("composition", result.stdout)

    def test_composition_is_a_selectable_flow_stage(self) -> None:
        self.assertEqual(run_design_flow.selected_stages("composition"), ["composition"])
        all_stages = run_design_flow.selected_stages("all")
        self.assertIn("composition", all_stages)
        self.assertLess(all_stages.index("frontend"), all_stages.index("composition"))
        self.assertLess(all_stages.index("composition"), all_stages.index("instrument"))

    def test_stage_composition_materializes_facts_and_invokes_generator(self) -> None:
        root = Path("/repo").resolve()
        paths = {
            "out_dir": root / "runs" / "example",
            "composition": root / "runs" / "example" / "composition",
            "composition_frontend": root / "runs" / "example" / "composition_hdl_facts.json",
        }
        cfg = {
            "composition": {
                "config": "configs/composition/declarations.json",
                "top_k": 2,
            }
        }
        frontend_library = root / "build" / "libmyfuzz_frontend.so"
        expected = {"schema_version": "composition_generation_summary.v1"}

        with (
            patch.object(run_design_flow, "write_composition_facts") as write_facts,
            patch.object(run_design_flow, "generate_compositions", return_value=expected) as generate,
        ):
            actual = run_design_flow.stage_composition(
                root,
                cfg,
                paths,
                frontend_library,
            )

        declarations = root / "configs" / "composition" / "declarations.json"
        write_facts.assert_called_once_with(
            declarations,
            paths["composition_frontend"],
            frontend_library=frontend_library,
        )
        generate.assert_called_once_with(
            declarations,
            paths["composition_frontend"],
            2,
            paths["composition"],
            frontend_library=frontend_library,
        )
        self.assertIs(actual, expected)

    def test_stage_composition_reuses_explicit_facts_and_output_paths(self) -> None:
        root = Path("/repo").resolve()
        paths = {
            "out_dir": root / "runs" / "example",
            "composition": root / "runs" / "example" / "composition",
            "composition_frontend": root / "runs" / "example" / "composition_hdl_facts.json",
        }
        cfg = {
            "composition": {
                "declarations": "inputs/declarations.json",
                "frontend_facts": "inputs/hdl_facts.json",
                "out_dir": "published/candidates",
                "top_k": 3,
            }
        }
        frontend_library = root / "build" / "libmyfuzz_frontend.so"

        with (
            patch.object(run_design_flow, "write_composition_facts") as write_facts,
            patch.object(run_design_flow, "generate_compositions", return_value={}) as generate,
        ):
            run_design_flow.stage_composition(root, cfg, paths, frontend_library)

        write_facts.assert_not_called()
        generate.assert_called_once_with(
            root / "inputs" / "declarations.json",
            root / "inputs" / "hdl_facts.json",
            3,
            root / "published" / "candidates",
            frontend_library=frontend_library,
        )

    def test_stage_composition_dispatches_protocol_manifest(self) -> None:
        root = Path("/repo").resolve()
        paths = {
            "composition": root / "runs" / "example" / "composition",
            "composition_frontend": root / "runs" / "example" / "composition_hdl_facts.json",
        }
        cfg = {
            "composition": {
                "kind": "protocol_composition",
                "manifest": "configs/designs/ibex_protocol_composition/manifest.json",
                "out_dir": "published/protocol-composition",
            }
        }
        expected = {"schema_version": "protocol_composition.v1", "complete": True}

        with patch.object(
            run_design_flow,
            "write_protocol_composition",
            create=True,
            return_value=expected,
        ) as write_protocol:
            actual = run_design_flow.stage_composition(
                root,
                cfg,
                paths,
                root / "build" / "libmyfuzz_frontend.so",
            )

        write_protocol.assert_called_once_with(
            root / "configs/designs/ibex_protocol_composition/manifest.json",
            root / "published/protocol-composition",
            root=root,
        )
        self.assertIs(actual, expected)

    def test_protocol_composition_rejects_missing_or_mixed_configuration(self) -> None:
        root = Path("/repo").resolve()
        paths = {"composition": root / "out" / "composition"}
        frontend_library = root / "build" / "libmyfuzz_frontend.so"

        with self.assertRaisesRegex(ValueError, r"^composition.protocol_manifest:required$"):
            run_design_flow.stage_composition(
                root,
                {"composition": {"kind": "protocol_composition"}},
                paths,
                frontend_library,
            )

        with self.assertRaisesRegex(ValueError, r"^composition:configuration-mixed$"):
            run_design_flow.stage_composition(
                root,
                {
                    "composition": {
                        "kind": "protocol_composition",
                        "manifest": "manifest.json",
                        "config": "declarations.json",
                    }
                },
                paths,
                frontend_library,
            )

        with self.assertRaisesRegex(ValueError, r"^composition:configuration-mixed$"):
            run_design_flow.stage_composition(
                root,
                {
                    "composition": {
                        "kind": "candidate_search",
                        "config": "declarations.json",
                        "protocol_manifest": "manifest.json",
                    }
                },
                paths,
                frontend_library,
            )

    def test_generate_composition_help_lists_protocol_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/generate_composition.py", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--protocol-manifest", result.stdout)
        self.assertIn("--root", result.stdout)

    def test_generate_composition_protocol_mode_forwards_paths_and_prints_summary(self) -> None:
        module = load_generate_composition_module()
        root = Path("/repo").resolve()
        manifest = root / "manifest.json"
        output = root / "generated"
        summary = {
            "schema_version": "protocol_composition.v1",
            "manifest_hash": "sha256:" + "a" * 64,
            "ir_path": (output / "composition_ir.json").as_posix(),
            "wrapper_path": (output / "ibex_protocol_composition_top.sv").as_posix(),
            "source_list_path": (output / "sources.f").as_posix(),
            "complete": True,
        }
        args = argparse.Namespace(
            protocol_manifest=manifest,
            out_dir=output,
            root=root,
            config=None,
            frontend=None,
            top_k=None,
            frontend_library=None,
        )

        stdout = io.StringIO()
        with (
            patch.object(module, "parse_args", return_value=args),
            patch.object(
                module,
                "write_protocol_composition",
                create=True,
                return_value=summary,
            ) as write_protocol,
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(module.main(), 0)

        write_protocol.assert_called_once_with(manifest, output, root=root)
        self.assertEqual(json.loads(stdout.getvalue()), summary)

    def test_generate_composition_protocol_mode_rejects_incomplete_summary(self) -> None:
        module = load_generate_composition_module()
        root = Path("/repo").resolve()
        args = argparse.Namespace(
            protocol_manifest=root / "manifest.json",
            out_dir=root / "generated",
            root=root,
            config=None,
            frontend=None,
            top_k=None,
            frontend_library=None,
        )
        stderr = io.StringIO()

        with (
            patch.object(module, "parse_args", return_value=args),
            patch.object(
                module,
                "write_protocol_composition",
                create=True,
                return_value={"schema_version": "protocol_composition.v1", "complete": True},
            ),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 1)

        self.assertIn("summary", stderr.getvalue())

    def test_main_dispatches_explicit_composition_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cfg = {
                "out_dir": "out",
                "project_root": ".",
                "flist": "sources.f",
                "top": "catalog",
                "composition": {
                    "config": "declarations.json",
                    "top_k": 4,
                },
            }
            args = argparse.Namespace(
                config="flow.json",
                stage="composition",
                frontend_library=None,
                server_verilator_bin=None,
                jobs="1",
                fuzz_seconds=5,
                force=False,
            )
            frontend_library = root / "libmyfuzz_frontend.so"

            with (
                patch.object(run_design_flow, "repo_root", return_value=root),
                patch.object(run_design_flow, "parse_args", return_value=args),
                patch.object(run_design_flow, "load_config", return_value=cfg),
                patch.object(
                    run_design_flow,
                    "default_frontend_library",
                    return_value=frontend_library,
                ),
                patch.object(run_design_flow, "stage_composition", return_value={}) as stage,
            ):
                self.assertEqual(run_design_flow.main(), 0)

            stage.assert_called_once()
            stage_root, stage_cfg, stage_paths, stage_library = stage.call_args.args
            self.assertEqual(stage_root, root)
            self.assertIs(stage_cfg, cfg)
            self.assertEqual(stage_library, frontend_library)
            self.assertEqual(stage_paths["composition"], root / "out" / "composition")
            self.assertEqual(
                stage_paths["composition_frontend"],
                root / "out" / "composition_hdl_facts.json",
            )

    def test_explicit_composition_stage_requires_configuration(self) -> None:
        with self.assertRaisesRegex(ValueError, r"^composition:configuration-required$"):
            run_design_flow.stage_composition(
                Path("/repo"),
                {},
                {
                    "composition": Path("/repo/out/composition"),
                    "composition_frontend": Path("/repo/out/composition_hdl_facts.json"),
                },
                Path("/repo/libmyfuzz_frontend.so"),
            )


if __name__ == "__main__":
    unittest.main()
