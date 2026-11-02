"""Bounded read-chunk cache: same values, bounded memory, counted reloads.

The journal keeps at most ``chunk_cache_size`` spilled chunks resident.  The
public ``Sequence`` behaviour (order, slices, negative indexes, IndexError,
detached snapshots) must be identical for every capacity, and the on-disk
chunk format must stay a bare ``pickle`` of the chunk list.
"""

import pickle
import unittest

from myfuzz.scenario.event_journal import EventJournal

ENV = 'MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE'


class EventJournalCacheTests(unittest.TestCase):
    def setUp(self):
        self._journals = []

    def tearDown(self):
        for journal in self._journals:
            journal.close()

    def journal(self, **kwargs):
        journal = EventJournal(**kwargs)
        self._journals.append(journal)
        return journal

    def fill(self, journal, count):
        events = [{'event_id': index + 1, 'value': [index]} for index in range(count)]
        for event in events:
            journal.append(event)
        return events

    def test_default_capacity_is_four_and_env_override_wins(self):
        import os
        self.assertNotIn(ENV, os.environ)
        self.assertEqual(4, self.journal(chunk_size=2).chunk_cache_size)
        os.environ[ENV] = '1'
        try:
            self.assertEqual(1, self.journal(chunk_size=2).chunk_cache_size)
            self.assertEqual(2, self.journal(chunk_size=2, chunk_cache_size=2).chunk_cache_size)
        finally:
            del os.environ[ENV]

    def test_invalid_capacity_is_rejected(self):
        import os
        for value in ('0', '-1', 'two', '1.5'):
            os.environ[ENV] = value
            try:
                with self.assertRaisesRegex(ValueError, 'positive integer'):
                    EventJournal(chunk_size=2)
            finally:
                del os.environ[ENV]
        with self.assertRaisesRegex(ValueError, 'chunk_cache_size must be positive'):
            EventJournal(chunk_size=2, chunk_cache_size=0)
        with self.assertRaisesRegex(ValueError, 'chunk_size must be positive'):
            EventJournal(chunk_size=0)

    def test_resident_chunks_are_bounded_by_capacity(self):
        journal = self.journal(chunk_size=2, chunk_cache_size=2)
        self.fill(journal, 8)                       # 4 spilled chunks
        for index in range(0, 8, 2):                # chunks 0,1,2,3 in order
            journal[index]
        self.assertEqual(4, journal.chunk_loads)
        self.assertEqual(2, len(journal._cache))
        self.assertEqual([2, 3], list(journal._cache))
        # The two resident (most recent) chunks load nothing; the evicted one does.
        journal[4]
        journal[6]
        self.assertEqual(4, journal.chunk_loads)
        journal[0]
        self.assertEqual(5, journal.chunk_loads)
        self.assertEqual([3, 0], list(journal._cache))

    def test_alternating_reads_reload_only_with_single_chunk_capacity(self):
        legacy = self.journal(chunk_size=2, chunk_cache_size=1)
        cached = self.journal(chunk_size=2, chunk_cache_size=4)
        for journal in (legacy, cached):
            self.fill(journal, 8)
        for _ in range(5):
            for journal in (legacy, cached):
                journal[0]
                journal[6]
        # One slot cannot hold both chunks, so every alternation reloads both.
        self.assertEqual(10, legacy.chunk_loads)
        # Both chunks fit, so the whole alternation costs two loads total.
        self.assertEqual(2, cached.chunk_loads)

    def test_order_slices_negative_index_and_errors_are_unchanged(self):
        journal = self.journal(chunk_size=2, chunk_cache_size=1)
        events = self.fill(journal, 7)
        self.assertEqual(events, list(journal))
        self.assertEqual(events, [journal[index] for index in range(7)])
        self.assertEqual(events[2:6], journal[2:6])
        self.assertIsInstance(journal[2:6], list)
        self.assertEqual(events[-1], journal[-1])
        self.assertEqual(events[-3:], journal[-3:])
        self.assertEqual((), tuple(journal[7:]))
        with self.assertRaises(IndexError):
            journal[7]
        with self.assertRaises(IndexError):
            journal[-8]
        with self.assertRaisesRegex(TypeError, 'integer or slice'):
            journal['0']
        with self.assertRaisesRegex(TypeError, 'integer or slice'):
            journal[True]

    def test_spilled_chunk_file_format_is_a_bare_pickle(self):
        journal = self.journal(chunk_size=2, chunk_cache_size=1)
        events = self.fill(journal, 7)
        journal._file.flush()
        journal._file.seek(journal._offsets[0])
        self.assertEqual(events[0:2], pickle.load(journal._file))
        journal._file.seek(journal._offsets[-1])
        self.assertEqual(events[4:6], pickle.load(journal._file))
        self.assertEqual(3, len(journal._offsets))
        self.assertEqual(0, journal._offsets[0])
        self.assertEqual(sorted(journal._offsets), journal._offsets)
        self.assertEqual(journal._offsets[1],
                         len(pickle.dumps(events[0:2], protocol=pickle.HIGHEST_PROTOCOL)))

    def test_snapshot_stays_detached_and_equal_across_capacities(self):
        for capacity in (1, 2, 4):
            journal = self.journal(chunk_size=2, chunk_cache_size=capacity)
            events = self.fill(journal, 7)
            snapshot = journal.snapshot()
            self.assertEqual(7, len(snapshot))
            detached = snapshot[0]
            detached['value'].append(99)
            self.assertEqual(events[0], snapshot[0])
            journal.append({'event_id': 8, 'value': [7]})
            self.assertEqual(7, len(snapshot))
            self.assertEqual(tuple(events), snapshot)
            self.assertEqual(tuple(list(events)), journal.snapshot()[:7])
            self.assertTrue(snapshot == tuple(events))
            self.assertFalse(snapshot == tuple(events[:6]))


if __name__ == '__main__':
    unittest.main()
