"""The TileLink 1.0 protocol plugin mirrors a real declaration, not a spec dump.

``src/myfuzz/protocols/plugins/tilelink.json`` exists because the repository
already carried a real TileLink 1.0 declaration -- the BOOM semantic interface
description -- and had no plugin to bind it to.  These tests tie the plugin's
declared fields back to that file, and pin the things it deliberately does *not*
claim: no A/B/C/D/E channel mapping and no legal adapter.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from myfuzz.composition.processor_adapters import (
    ProcessorAdapterError,
    resolve_processor_adapter,
)
from myfuzz.composition.processor_boundary import ProcessorMemoryBinding
from myfuzz.protocols import load_builtin_protocol, load_protocol_catalog


ROOT = Path(__file__).resolve().parents[2]
BOOM_DECLARATION = ROOT / "configs" / "cpus" / "boom" / "interface_description.json"
PLUGIN_DIR = ROOT / "src" / "myfuzz" / "protocols" / "plugins"
_A_B_C_D_E_CHANNEL_FIELDS = frozenset((
    "a_valid", "a_ready", "a_opcode", "a_param", "a_size", "a_source", "a_address",
    "a_mask", "a_data", "a_user", "a_corrupt",
    "b_valid", "b_ready", "b_opcode", "b_param", "b_size", "b_source", "b_address",
    "b_mask", "b_data", "b_user", "b_corrupt",
    "c_valid", "c_ready", "c_opcode", "c_param", "c_size", "c_source", "c_address",
    "c_data", "c_user", "c_corrupt",
    "d_valid", "d_ready", "d_opcode", "d_param", "d_size", "d_source", "d_sink",
    "d_data", "d_user", "d_error", "d_corrupt",
    "e_valid", "e_ready", "e_sink",
))


def _declared_tilelink_endpoints() -> list[dict]:
    document = json.loads(BOOM_DECLARATION.read_text(encoding="utf-8"))
    return [endpoint for endpoint in document["endpoints"]
            if tuple(endpoint.get("protocol", ())) == ("tilelink", "1")]


def _declared_roles() -> set[str]:
    return {field["role"] for endpoint in _declared_tilelink_endpoints()
            for field in endpoint["fields"]}


class TileLinkPluginTests(unittest.TestCase):
    def test_plugin_is_registered_under_the_declared_protocol_and_version(self):
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("tilelink", "1")
        self.assertEqual("tilelink", plugin.protocol_id)
        self.assertEqual("1", plugin.version)
        self.assertIn(("tilelink", "1"),
                      {(item.protocol_id, item.version) for item in catalog.plugins})
        self.assertEqual(plugin, load_builtin_protocol("tilelink", "1"))

    def test_fields_are_exactly_the_roles_the_real_declaration_names(self):
        plugin = load_builtin_protocol("tilelink", "1")
        declared = _declared_roles()
        self.assertEqual({"address", "read_data", "request", "response", "write_data"},
                         declared)
        self.assertEqual(declared, {field.field_id for field in plugin.fields})
        # Host means the TileLink initiator, exactly as in the other plugins: the
        # master drives address/request/write_data and receives read_data/response.
        directions = {field.field_id: field.direction for field in plugin.fields}
        self.assertEqual({"address": "host_to_device", "request": "host_to_device",
                          "write_data": "host_to_device",
                          "read_data": "device_to_host",
                          "response": "device_to_host"}, directions)
        required = {field.field_id: field.required for field in plugin.fields}
        # ``cpu.instruction_memory`` declares no write_data, so the plugin cannot
        # make it mandatory for the protocol as a whole.
        self.assertEqual({"write_data": False}, {k: v for k, v in required.items() if not v})
        self.assertEqual({"address", "read_data", "request", "response"},
                         {k for k, v in required.items() if v})

    def test_no_a_b_c_d_e_channel_is_invented(self):
        plugin = load_builtin_protocol("tilelink", "1")
        self.assertFalse({field.field_id for field in plugin.fields}
                         & _A_B_C_D_E_CHANNEL_FIELDS)
        self.assertEqual(1, len(plugin.channel_relations))
        self.assertEqual("request_response_handshake",
                         plugin.channel_relations[0].kind)
        self.assertEqual(("request", "response"), plugin.channel_relations[0].field_ids)
        self.assertEqual(1, len(plugin.temporal_rules))
        self.assertEqual("response_after_request", plugin.temporal_rules[0].kind)

    def test_no_adapter_is_claimed_because_none_exists_in_this_repository(self):
        plugin = load_builtin_protocol("tilelink", "1")
        self.assertEqual((), plugin.legal_adapters)
        # The repository really has no TileLink processor-memory adapter, so the
        # empty list is a fact about the tree, not an omission.
        self.assertFalse(sorted((ROOT / "src/myfuzz/protocols/rtl").glob("*tilelink*")))
        with self.assertRaisesRegex(ProcessorAdapterError,
                                    "unsupported-processor-adapter:tilelink@1"):
            resolve_processor_adapter(ProcessorMemoryBinding(
                "memory", "memory_master", ("tilelink", "1"), (), ()))

    def test_capability_limits_do_not_claim_undeclared_features(self):
        limits = dict(load_builtin_protocol("tilelink", "1").capability_limits)
        self.assertEqual(1, limits["max_outstanding"])
        self.assertIs(limits["byte_enable"], False)
        self.assertIs(limits["partial_write"], False)
        self.assertEqual("configs/cpus/boom/interface_description.json",
                         limits["x-role-declaration"])
        self.assertEqual("abstract-roles-only", limits["x-role-vocabulary"])
        self.assertEqual("not-declared", limits["x-channel-mapping"])
        # Coherence, ids and bursts are TileLink features the declaration never
        # names; the plugin must not answer them either way.
        self.assertFalse({"coherence", "ids", "bursts", "source_id_reordering"} & set(limits))


if __name__ == "__main__":
    unittest.main()
