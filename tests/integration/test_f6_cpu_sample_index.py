from myfuzz.integration import compiled_f6_saved_semantics


def test_cpu_sample_index_preserves_scan_order_duplicates_and_numeric_tick_equality():
    rows = [
        {'component': 'cpu', 'kind': 'local_tick_sample', 'local_tick': 1, 'phase': 'pre'},
        {'component': 'cpu', 'kind': 'local_tick_sample', 'local_tick': True, 'phase': 'post'},
        {'component': 'cpu', 'kind': 'local_tick_sample', 'local_tick': 1.0, 'phase': 'pre'},
        {'component': 'cpu', 'kind': 'local_tick_sample', 'local_tick': [], 'phase': 'pre'},
        {'component': 'dma', 'kind': 'local_tick_sample', 'local_tick': 1, 'phase': 'pre'},
        {'component': 'cpu', 'kind': 'other', 'local_tick': 1},
        {'component': 'cpu', 'kind': 'local_tick_sample', 'local_tick': 2, 'phase': 'post'},
    ]
    index = compiled_f6_saved_semantics._cpu_sample_index(rows, 'cpu')
    for tick in (0, 1, 2, 3):
        expected = [r for r in rows if r.get('component') == 'cpu'
                    and r.get('kind') == 'local_tick_sample' and r.get('local_tick') == tick]
        assert index.get(tick, []) == expected
