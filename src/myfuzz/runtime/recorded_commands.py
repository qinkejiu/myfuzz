"""Join observational wire recordings to actual component execution identities."""
import re


def _hex(value, width):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % width, value) is not None


def recorded_command_documents(rows, *, executions, scope, audited=False):
    """Export phases through one join; audited callers also pin binary identity.

    Incomplete recordings remain incomplete. This exports observations, not an
    execution credential, and never infers which process ran from row order.
    """
    if type(executions) is not dict or not executions:
        raise ValueError('recorded trace executions missing')
    index = {}
    for row in rows:
        if type(row) is not dict or type(row.get('identity')) is not dict:
            continue
        component, nonce = row.get('component'), row['identity'].get('execution_nonce')
        if type(component) is str and type(nonce) is str:
            index.setdefault((component, nonce), []).append(row)
    documents, used, components = {}, set(), None
    for phase, identities in executions.items():
        if type(identities) is not dict or not identities or (
                components is not None and set(identities) != components):
            raise ValueError('recorded trace audit components mismatch')
        components = set(identities)
        sessions = {}
        for component, expected in identities.items():
            if type(expected) is not dict or (audited and expected.get('component') != component):
                raise ValueError('recorded trace identity malformed')
            nonce = expected.get('execution_nonce')
            if not _hex(nonce, 32) or nonce in used:
                raise ValueError('recorded trace nonce invalid or reused')
            used.add(nonce)
            matches = index.get((component, nonce), ())
            if len(matches) != 1:
                raise ValueError('recorded trace session missing or ambiguous:' + str(component))
            row = matches[0]
            identity = row['identity']
            if type(row.get('complete')) is not bool or type(row.get('records')) is not list:
                raise ValueError('recorded trace recording malformed')
            if audited:
                if any(not _hex(expected.get(key), 64) or identity.get(key) != expected[key]
                       for key in ('build_digest', 'binary_sha256')):
                    raise ValueError('recorded trace build identity mismatch')
                if (identity.get('pid') is not None or expected.get('pid') is not None) and (
                        type(identity.get('pid')) is not int or identity['pid'] <= 0
                        or type(expected.get('pid')) is not int
                        or identity['pid'] != expected['pid']):
                    raise ValueError('recorded trace process identity mismatch')
                if (identity.get('artifact_digest') is not None
                        or expected.get('artifact_digest') is not None) and (
                        not _hex(identity.get('artifact_digest'), 64)
                        or identity.get('artifact_digest') != expected.get('artifact_digest')):
                    raise ValueError('recorded trace artifact identity mismatch')
            sessions[component] = {key: row[key] for key in ('complete', 'identity', 'records')}
        documents[phase] = {'schema_version': 'local_command_trace.v1',
            'scope': f'{scope} {phase} actual session commands; observational capture',
            'sessions': sessions}
    return documents
