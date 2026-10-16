def _normalize(events, execution_ids):
    """Normalize declared execution fields and typed journal ledger references."""
    import re
    if set(execution_ids) != {'cpu', 'dma', 'uart', 'runner'}:
        raise ValueError('execution IDs must identify CPU, DMA, UART and Runner')
    issued = {n: v for n, v in execution_ids.items() if v is not None}
    if (len(set(issued.values())) != len(issued)
            or any(type(v) is not str or re.fullmatch(r'[0-9a-f]{32}', v) is None
                for v in issued.values())):
        raise ValueError('execution IDs must be distinct native UUID hex strings')
    mapping = {v: 'execution:' + n for n, v in issued.items()}
    def visit(value, field=None, *, event_record=False, ledger_reference=False):
        if isinstance(value, dict):
            state_edge = (event_record and value.get('kind') == 'state_dependency'
                and {'event_id', 'producer_event_id', 'edge_kind', 'memory_id',
                     'generation', 'byte_offset', 'version', 'source', 'target'} <= value.keys())
            return {key: visit(item, key,
                ledger_reference=state_edge and key in ('source', 'target'))
                for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [visit(item, field) for item in value]
        if type(value) is str:
            if field in ('execution', 'execution_id'):
                return mapping.get(value, value)
            if ledger_reference or field in ('writer_event_id', 'writer_event_ids',
                    'pending_before_finalize', 'pending_after_finalize',
                    'uncertain_transactions'):
                # Producer stores TransactionKey repr in ledger writer and
                # uncertainty fields. List recursion retains the field context. Match
                # only its leading execution token; retain the entire suffix.
                match = re.fullmatch(r"TransactionKey\(execution_id='([0-9a-f]{32})', (.*)\)", value)
                if match and match[1] in mapping:
                    return "TransactionKey(execution_id='" + mapping[match[1]] + "', " + match[2] + ')'
        return value
    # Only records in the supplied journal root are state-dependency edges.
    # Identically named nested payloads and untyped source strings stay intact.
    if isinstance(events, (tuple, list)):
        return [visit(event, event_record=True) for event in events]
    return visit(events)
