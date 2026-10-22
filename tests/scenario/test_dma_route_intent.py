"""Static declarations preserve intent without accepting runtime identities."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest

from myfuzz.scenario.dma_route_intent import (
    DmaMasterRouteIntent,
    dma_master_route_intents_document,
    parse_dma_master_route_intents,
)


def peripheral_row(**changes):
    row = {
        'route_id': 'copy.destination',
        'initiator_instance': 'mover',
        'initiator_endpoint_id': 'declared.profile.master',
        'target': {'kind': 'peripheral', 'component_instance': 'output',
                   'device_id': 'output.window',
                   'endpoint_id': 'declared.profile.slave'},
        'base': 0x40001000, 'size': 4096, 'operation': 'write',
        'permissions': ['write'], 'byte_enable': 15,
        'readable_offsets': [], 'writable_offsets': [12],
        'accepted_write_values': {'kind': 'range', 'start': 0,
                                  'stop': 256, 'step': 1},
    }
    row.update(changes)
    return row


def memory_row(**changes):
    row = peripheral_row(
        route_id='copy.source', operation='read', permissions=['read'],
        target={'kind': 'persistent_memory', 'component_instance': 'storage',
                'resource_id': 'ram'}, writable_offsets=[],
        accepted_write_values={'kind': 'values', 'values': []})
    row.update(changes)
    return row


def wrapper(*rows):
    return {'schema_version': 'dma_master_route_intent.v1', 'routes': list(rows)}


def parse_row(row):
    return parse_dma_master_route_intents(wrapper(row))[0]


class DmaMasterRouteIntentTests(unittest.TestCase):
    def test_round_trip_closed_wrapper_and_target_variants(self):
        rows = [peripheral_row(), memory_row()]
        routes = parse_dma_master_route_intents(wrapper(*reversed(rows)))
        self.assertIsInstance(routes, tuple)
        self.assertTrue(all(isinstance(route, DmaMasterRouteIntent) for route in routes))
        self.assertEqual([route.route_id for route in routes],
                         ['copy.destination', 'copy.source'])
        self.assertEqual(dma_master_route_intents_document(routes), wrapper(*rows))
        self.assertEqual(dma_master_route_intents_document(reversed(routes)),
                         wrapper(*rows))
        self.assertEqual(routes[0].target['device_id'], 'output.window')
        self.assertEqual(routes[1].target['resource_id'], 'ram')

    def test_digest_is_exact_canonical_row_without_live_identity_fields(self):
        row = peripheral_row(route_id='路线.目标')
        route = parse_row(row)
        expected = hashlib.sha256(json.dumps(row, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False, allow_nan=False)
            .encode('utf-8')).hexdigest()
        self.assertEqual(route.identity_sha256, expected)
        self.assertEqual(route.document(), row)
        self.assertNotIn('identity_sha256', route.document())
        self.assertNotEqual(replace(route, route_id='renamed').identity_sha256, expected)

    def test_parsed_intents_are_deeply_immutable_and_do_not_alias_input(self):
        row = peripheral_row(accepted_write_values={'kind': 'values', 'values': [3, 1, 3]})
        original = deepcopy(row)
        route = parse_row(row)
        self.assertEqual(route.permissions, ('write',))
        self.assertEqual(route.readable_offsets, ())
        self.assertEqual(route.writable_offsets, (12,))
        self.assertEqual(route.accepted_write_values, (3, 1, 3))
        with self.assertRaises(FrozenInstanceError):
            route.base = 0
        with self.assertRaises(TypeError):
            route.target['device_id'] = 'changed'
        row['target']['device_id'] = 'changed'
        row['accepted_write_values']['values'].append(4)
        document = route.document()
        document['target']['device_id'] = 'changed-again'
        document['permissions'].append('read')
        self.assertEqual(route.document(), original)

    def test_values_order_multiplicity_and_range_representation_are_injective(self):
        policies = [
            {'kind': 'values', 'values': [0, 2, 4]},
            {'kind': 'values', 'values': [4, 2, 0]},
            {'kind': 'values', 'values': [0, 2, 4, 4]},
            {'kind': 'range', 'start': 0, 'stop': 5, 'step': 2},
            {'kind': 'range', 'start': 0, 'stop': 6, 'step': 2},
            {'kind': 'range', 'start': 4, 'stop': -1, 'step': -2},
        ]
        routes = [parse_row(peripheral_row(accepted_write_values=p)) for p in policies]
        self.assertEqual(len({route.identity_sha256 for route in routes}), len(policies))
        for route, policy in zip(routes, policies):
            self.assertEqual(route.document()['accepted_write_values'], policy)

    def test_full_u32_range_is_valid_without_expansion(self):
        for policy in ({'kind': 'range', 'start': 0, 'stop': 1 << 32, 'step': 1},
                       {'kind': 'range', 'start': (1 << 32) - 1, 'stop': -1, 'step': -1}):
            with self.subTest(policy=policy):
                route = parse_row(peripheral_row(accepted_write_values=policy))
                self.assertIsInstance(route.accepted_write_values, range)
                self.assertEqual(route.document()['accepted_write_values'], policy)

    def test_read_only_peripheral_has_empty_values(self):
        row = peripheral_row(operation='read', permissions=['read'],
            readable_offsets=[0, 8], writable_offsets=[],
            accepted_write_values={'kind': 'values', 'values': []})
        self.assertEqual(parse_row(row).document(), row)

    def test_read_write_peripheral_and_memory_permissions(self):
        for row in (peripheral_row(operation='read', permissions=['read', 'write'],
                                   readable_offsets=[0]),
                    memory_row(operation='write', permissions=['read', 'write'])):
            with self.subTest(row=row):
                self.assertEqual(parse_row(row).document(), row)

    def test_maximum_u64_aperture_endpoint_is_valid(self):
        row = memory_row(base=(1 << 64) - 4, size=4)
        self.assertEqual(parse_row(row).document(), row)

    def test_wrapper_must_be_closed_versioned_and_nonempty(self):
        for document in (None, [], {}, {'routes': [memory_row()]},
                         {**wrapper(memory_row()), 'schema_version': 'unknown'},
                         {**wrapper(memory_row()), 'extra': 1},
                         wrapper(), {**wrapper(memory_row()), 'routes': ()}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                parse_dma_master_route_intents(document)

    def test_duplicate_ids_refuse_in_parser_and_document_helper(self):
        route = parse_row(memory_row())
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            parse_dma_master_route_intents(wrapper(memory_row(), memory_row()))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            dma_master_route_intents_document((route, route))
        with self.assertRaises(ValueError):
            dma_master_route_intents_document(())
        with self.assertRaises(ValueError):
            dma_master_route_intents_document((route.document(),))

    def test_every_row_field_is_required(self):
        for key in peripheral_row():
            row = peripheral_row()
            del row[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                parse_row(row)

    def test_runtime_and_unknown_fields_are_rejected_at_every_closed_level(self):
        runtime_fields = ('endpoint_identity_sha256', 'target_identity_sha256',
                          'identity_sha256', 'rule_index', 'prerequisite_index',
                          'source_node_id', 'target_node_id', 'session_id', 'unknown')
        for key in runtime_fields:
            for location in ('wrapper', 'row', 'target', 'accepted_write_values'):
                document = wrapper(peripheral_row())
                target = {'wrapper': document, 'row': document['routes'][0],
                          'target': document['routes'][0]['target'],
                          'accepted_write_values': document['routes'][0]['accepted_write_values']}[location]
                target[key] = 'f' * 64
                with self.subTest(key=key, location=location), self.assertRaises(ValueError):
                    parse_dma_master_route_intents(document)

    def test_target_union_rejects_mixed_missing_unknown_and_blank_fields(self):
        targets = [None, [], {}, {'kind': 'ram'},
                   {**memory_row()['target'], 'device_id': 'window'},
                   {**peripheral_row()['target'], 'resource_id': 'ram'}]
        for valid in (memory_row()['target'], peripheral_row()['target']):
            for key in valid:
                missing = dict(valid)
                del missing[key]
                targets.append(missing)
                for invalid in ('', ' ', ' padded ', None, True, 7):
                    targets.append({**valid, key: invalid})
        for target in targets:
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_row(peripheral_row(target=target))

    def test_identity_names_must_be_nonblank_unpadded_strings(self):
        for key in ('route_id', 'initiator_instance', 'initiator_endpoint_id'):
            for value in ('', ' ', ' padded', 'padded ', None, True, 7):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    parse_row(peripheral_row(**{key: value}))

    def test_aperture_requires_aligned_bounded_exact_integers(self):
        for key, values in (('base', [-4, 1, True, 0.0, '0', 1 << 64]),
                            ('size', [0, 1, -4, 6, True, 4.0, '4', 1 << 64])):
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    parse_row(peripheral_row(**{key: value}))
        with self.assertRaises(ValueError):
            parse_row(memory_row(base=(1 << 64) - 4, size=8))

    def test_permissions_require_canonical_unique_operations_and_membership(self):
        for permissions in ([], ['write', 'write'], ['execute'], 'write',
                            [True], ['read'], ['write', 'read']):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                parse_row(peripheral_row(permissions=permissions))
        for operation in ('transfer', '', None, True):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                parse_row(peripheral_row(operation=operation))
        for enable in (0, 1, 7, 16, True, 15.0, '15'):
            with self.subTest(enable=enable), self.assertRaises(ValueError):
                parse_row(peripheral_row(byte_enable=enable))

    def test_offsets_require_unique_aligned_relative_words(self):
        for offsets in (None, (), '12', [True], [0.0], [-4], [1], [4096], [4093], [12, 12]):
            for key in ('readable_offsets', 'writable_offsets'):
                row = peripheral_row(permissions=['read', 'write'], readable_offsets=[0])
                row[key] = offsets
                with self.subTest(key=key, offsets=offsets), self.assertRaises(ValueError):
                    parse_row(row)

    def test_peripheral_permissions_and_write_policy_must_match_offsets(self):
        rows = [peripheral_row(readable_offsets=[0]),
                peripheral_row(writable_offsets=[]),
                peripheral_row(accepted_write_values={'kind': 'values', 'values': []}),
                peripheral_row(accepted_write_values={'kind': 'range', 'start': 3, 'stop': 3, 'step': 1}),
                peripheral_row(operation='read', permissions=['read', 'write']),
                peripheral_row(operation='read', permissions=['read'], readable_offsets=[0],
                               writable_offsets=[])]
        for row in rows:
            with self.subTest(row=row), self.assertRaises(ValueError):
                parse_row(row)

    def test_memory_rejects_peripheral_only_fields(self):
        for changes in ({'readable_offsets': [0]}, {'writable_offsets': [0]},
                        {'accepted_write_values': {'kind': 'values', 'values': [0]}},
                        {'accepted_write_values': {'kind': 'range', 'start': 0, 'stop': 0, 'step': 1}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_row(memory_row(**changes))

    def test_accepted_value_union_rejects_non_u32_values_and_malformed_shapes(self):
        policies = [None, [], {}, {'kind': 'tuple', 'values': [0]},
                    {'kind': 'values', 'values': ()},
                    {'kind': 'values', 'values': '0'},
                    {'kind': 'range', 'start': 0, 'stop': 1},
                    {'kind': 'range', 'start': 0, 'stop': 1, 'step': 0}]
        for invalid in (-1, 1 << 32, True, 0.0, '0', None):
            policies.append({'kind': 'values', 'values': [invalid]})
        for key in ('start', 'stop', 'step'):
            for invalid in (True, 0.0, '0', None):
                policies.append({**{'kind': 'range', 'start': 0, 'stop': 4, 'step': 1}, key: invalid})
        policies.extend(({'kind': 'range', 'start': -1, 'stop': 4, 'step': 1},
                         {'kind': 'range', 'start': 0, 'stop': (1 << 32) + 1, 'step': 1},
                         {'kind': 'range', 'start': 3, 'stop': -2, 'step': -1}))
        for policy in policies:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                parse_row(peripheral_row(accepted_write_values=policy))

    def test_custom_pointer_names_exact_invalid_field(self):
        document = wrapper(peripheral_row(writable_offsets=[4096]))
        with self.assertRaisesRegex(ValueError, '/composition/dma_master_routes/routes/0/writable_offsets'):
            parse_dma_master_route_intents(document,
                                          pointer='/composition/dma_master_routes')

    def test_direct_construction_copies_mutable_collections_and_checks_invariants(self):
        route = parse_row(peripheral_row())
        values = list(route.permissions)
        target = dict(route.target)
        copied = replace(route, target=target, permissions=values,
                         accepted_write_values=[2, 1])
        values.append('read')
        target['device_id'] = 'changed'
        self.assertEqual(copied.permissions, ('write',))
        self.assertEqual(copied.target['device_id'], 'output.window')
        self.assertEqual(copied.accepted_write_values, (2, 1))
        with self.assertRaises(ValueError):
            replace(route, base=True)


if __name__ == '__main__':
    unittest.main()
