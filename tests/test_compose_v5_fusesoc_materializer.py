from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.builder.contracts import content_digest, validate_contract
from myfuzz.scripts.materialize_compose_v5_fusesoc_target import (
    MaterializationError,
    _load_recipe,
)


def _recipe() -> dict[str, object]:
    return {
        "schema": "myfuzz.compose-v5-fusesoc-recipe/v1",
        "name": "unit_target",
        "mappings": ["vendor:library:generic:1"],
        "components": [
            {
                "id": "cpu0",
                "role": "cpu",
                "core": "vendor:library:cpu:1",
                "target": "lint",
                "tool": "icarus",
                "top_module": "cpu_top",
                "metadata_wrapper": False,
                "fusesoc_parameters": {},
                "module_parameters": {},
            },
            {
                "id": "ip0",
                "role": "ip",
                "core": "vendor:library:ip0:1",
                "target": "lint",
                "tool": "icarus",
                "top_module": "ip0_top",
                "metadata_wrapper": False,
                "fusesoc_parameters": {},
                "module_parameters": {},
            },
            {
                "id": "ip1",
                "role": "ip",
                "core": "vendor:library:ip1:1",
                "target": "lint",
                "tool": "icarus",
                "top_module": "ip1_top",
                "metadata_wrapper": False,
                "fusesoc_parameters": {},
                "module_parameters": {},
            },
            {
                "id": "ram0",
                "role": "ram",
                "core": "vendor:library:ram:1",
                "target": "default",
                "tool": "icarus",
                "top_module": "ram_top",
                "metadata_wrapper": True,
                "fusesoc_parameters": {},
                "module_parameters": {"Depth": 256},
            },
        ],
        "digest": "",
    }


class FuseSocMaterializerRecipeTest(unittest.TestCase):
    def _write(self, value: object, root: Path) -> Path:
        path = root / "recipe.json"
        path.write_text(json.dumps(value), encoding="ascii")
        return path

    def test_empty_digest_is_computed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            recipe = _recipe()
            loaded = _load_recipe(self._write(recipe, Path(directory)))
        payload = dict(recipe)
        payload.pop("digest")
        self.assertEqual(loaded["digest"], content_digest(payload))
        validate_contract(loaded, "compose_v5_fusesoc_recipe_v1")

    def test_declared_digest_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            recipe = _recipe()
            recipe["digest"] = "0" * 64
            with self.assertRaisesRegex(MaterializationError, "digest mismatch"):
                _load_recipe(self._write(recipe, Path(directory)))

    def test_components_must_be_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            recipe = _recipe()
            recipe["components"][0], recipe["components"][1] = (
                recipe["components"][1], recipe["components"][0]
            )
            with self.assertRaisesRegex(MaterializationError, "sorted by id"):
                _load_recipe(self._write(recipe, Path(directory)))

    def test_requires_one_cpu_one_ram_and_two_ips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            recipe = _recipe()
            recipe["components"] = copy.deepcopy(recipe["components"][:-1])
            with self.assertRaisesRegex(MaterializationError, "exactly one CPU"):
                _load_recipe(self._write(recipe, Path(directory)))

    def test_module_parameters_reject_non_integer_and_non_string_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            recipe = _recipe()
            recipe["components"][3]["module_parameters"] = {"Depth": True}  # type: ignore[index]
            with self.assertRaisesRegex(MaterializationError, "integer or string"):
                _load_recipe(self._write(recipe, Path(directory)))
        with tempfile.TemporaryDirectory() as directory:
            recipe = _recipe()
            recipe["components"][3]["module_parameters"] = {"Depth": 1.5}  # type: ignore[index]
            with self.assertRaisesRegex(MaterializationError, "integer or string"):
                _load_recipe(self._write(recipe, Path(directory)))


if __name__ == "__main__":
    unittest.main()
