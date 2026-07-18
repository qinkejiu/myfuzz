import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import InputValidationError, build_register_model, import_cmsis_svd  # noqa: E402


def source_model():
    field = {"name": "ENABLE", "lsb": 0, "width": 1, "access": "rw", "reset": 0,
             "side_effect": "none", "volatile": False, "irq": None, "enum": ()}
    register = {"name": "CTRL", "offset": 0, "width": 32, "access": "rw", "reset": 0,
                "side_effect": "none", "volatile": False, "irq": None, "fields": (field,)}
    return {"schema": "myfuzz.register-source/v1", "name": "DEMO",
            "blocks": ({"name": "DEMO", "base": 0x4000, "registers": (register,)},)}


class RegisterModelTest(unittest.TestCase):
    def test_json_and_svd_semantics_produce_same_blocks(self):
        direct = build_register_model(source_model(), provenance={"source": "json"})
        svd = """<device><peripherals><peripheral><name>DEMO</name><baseAddress>0x4000</baseAddress>
        <registers><register><name>CTRL</name><addressOffset>0</addressOffset><size>32</size>
        <access>read-write</access><resetValue>0</resetValue><fields><field><name>ENABLE</name>
        <bitOffset>0</bitOffset><bitWidth>1</bitWidth><access>read-write</access></field></fields>
        </register></registers></peripheral></peripherals></device>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.svd"; path.write_text(svd, encoding="utf-8")
            imported = import_cmsis_svd(path)
        self.assertEqual(direct.blocks, imported.blocks)
        self.assertNotEqual(direct.digest, imported.digest)

    def test_unknown_fields_overlap_and_bad_access_fail(self):
        value = source_model(); value["surprise"] = True
        with self.assertRaisesRegex(InputValidationError, "unknown field"):
            build_register_model(value, provenance={"source": "test"})
        value = source_model(); value["blocks"][0]["registers"][0]["access"] = "magic"
        with self.assertRaisesRegex(InputValidationError, "unsupported access"):
            build_register_model(value, provenance={"source": "test"})


if __name__ == "__main__":
    unittest.main()
