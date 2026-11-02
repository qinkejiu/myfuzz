"""Execution policy is separate from the input sequence being replayed."""
from time import monotonic

EXECUTION_MODES = ('develop', 'search', 'acceptance')


def requires_replay(execution_mode, mode, legacy_default=True, *, interesting=False):
    if execution_mode not in (None, *EXECUTION_MODES):
        raise ValueError('invalid execution mode')
    if mode not in ('original', 'fresh'):
        raise ValueError('invalid original/fresh mode')
    if mode == 'fresh':
        return True
    if execution_mode is None:
        return legacy_default
    return execution_mode == 'acceptance' or (execution_mode == 'search' and interesting)


def boundary_summary(summary, status):
    result = dict(summary)
    result['verification'] = dict(summary.get('verification', {}))
    result['verification']['session_boundary'] = {
        'status': status, 'matches': True if status == 'verified' else False if status == 'failed' else None}
    if status == 'failed':
        result['status'] = 'failed'
    return result


def candidate_summary(summary):
    from myfuzz.local_harness.execution_validation import execution_validation_active
    return boundary_summary(summary, 'pending') if execution_validation_active() else summary


def invalidate_boundary(output, error, boundary_status='failed', *, static_validation_policy=None):
    """Preserve failed evidence while making its public summary unusable."""
    import json
    from pathlib import Path
    output = Path(output)
    if not output.is_dir():
        return
    path = output / 'search-summary.json'
    try:
        summary = json.loads(path.read_text()) if path.is_file() else {}
    except (OSError, ValueError):
        summary = {}
    summary = boundary_summary(summary, boundary_status)
    summary['status'] = 'failed'
    summary['error'] = str(error)
    summary['error_type'] = type(error).__name__
    if static_validation_policy is not None:
        summary['static_validation_policy'] = static_validation_policy
    path.write_text(json.dumps(summary, indent=2) + '\n')


def run_boundary(output, run, *, execution_mode=None, mode='original'):
    """Validate once for local search; revalidate for acceptance and fresh."""
    import json
    from pathlib import Path
    from myfuzz.local_harness.execution_validation import execution_validation_scope, execution_validation_active
    output = Path(output)
    if execution_validation_active():
        raise ValueError('public execution boundary cannot be nested')
    if output.exists() or output.is_symlink():
        raise ValueError('existing output must never be overwritten')
    revalidate = mode == 'fresh' or execution_mode not in ('search', 'develop')
    policy = 'entry-and-exit' if revalidate else 'entry-only'
    started = monotonic()
    boundary_state = None
    try:
        with execution_validation_scope(revalidate=revalidate) as boundary_state:
            result = run()
            body_finished = monotonic()
        verified_at = monotonic()
        result = boundary_summary(result, 'verified')
        result['static_validation_policy'] = policy
        result['workflow_wall_seconds'] = verified_at - started
        result['boundary_revalidation_seconds'] = verified_at - body_finished
        (output / 'search-summary.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    except BaseException as error:
        try:
            status = boundary_state.get('status', 'failed') if boundary_state is not None else 'failed'
            invalidate_boundary(output, error, status, static_validation_policy=policy)
        except (OSError, ValueError) as invalidation_error:
            error.add_note('could not invalidate summary: ' + str(invalidation_error))
        raise
