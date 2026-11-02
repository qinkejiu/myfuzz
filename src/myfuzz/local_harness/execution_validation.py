"""Explicit execution boundaries for expensive static authentication.

Dynamic producer, process, protocol and executable checks remain at their callers.
A memo is local to one context and is never an admission based on timestamps.

Two kinds of reuse are deliberately distinguished here:

``execution_validation_scope``
    Collects the static authentication a body performs, then re-runs every one
    of them before the scope closes.  A validator registered with an
    ``identity`` observation is instead *re-observed*: when the identity of its
    inputs is unchanged the accepted result still belongs to those exact inputs
    and is kept.  An identity that cannot be observed, or that changed, falls
    back to running the validator again and comparing the result, so the exit
    re-authentication is never skipped, only not repeated.

:func:`identity_memo`
    One accepted computation per *observed content identity* for the life of
    the process (some preparations are repeated by several callers that cannot
    share a scope, for example the driver rendered by the entry and by the
    builder).  The caller observes the identity on every call, so a hit means
    "these exact bytes already produced this result", never "this function ran
    before".  ``namespace`` keeps different computations apart; an identity of
    ``None`` means "could not observe the inputs" and always recomputes.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path


class ExecutionValidationError(ValueError):
    """Static authentication changed or failed at an execution boundary."""


_SCOPE = ContextVar('myfuzz_execution_validation', default=None)
_STRICT = ContextVar('myfuzz_execution_validation_strict', default=False)


def identity_reuse_enabled() -> bool:
    """Whether an unchanged input may keep an already accepted result.

    Throughput knob only.  Reuse is not one of the checks: disabling it makes
    every static validator run again at the exit boundary, which is strictly
    more work than the default.  ``MYFUZZ_IDENTITY_REUSE=0`` exists so the same
    bytes can be measured with and without the reuse.
    """
    raw = os.environ.get('MYFUZZ_IDENTITY_REUSE')
    if raw is None or raw == '1':
        return True
    if raw == '0':
        return False
    raise ValueError('invalid-myfuzz-identity-reuse')


def strict_validation_active():
    return _STRICT.get()


def execution_validation_active():
    """Whether results are currently provisional inside an execution scope."""
    return _SCOPE.get() is not None


# --------------------------------------------------------------------------- #
# Content identity: what a validator actually read, never when it ran
# --------------------------------------------------------------------------- #

#: One SHA-256 per file, re-read only when the stat stamp changed.  Files are
#: immutable in a run unless somebody edits them, so the stamp is a cheap
#: re-observation of *bytes that were already hashed*; a validator that must see
#: a same-size, restored-mtime edit re-reads without this cache (see
#: ``execution_validation.file_digest_now``).
_DIGESTS: dict[str, tuple[tuple[int, int, int, int, int], str]] = {}
_DIGEST_LIMIT = 8192


def _stamp(info) -> tuple[int, int, int, int, int]:
    """Stat stamp that a write cannot restore.

    ``ctime`` is the inode change time: every write, truncate, rename or
    ``utime`` updates it and no unprivileged caller can set it back, so a
    same-size edit with a restored ``mtime`` still re-reads and re-digests.
    """
    return (info.st_ctime_ns, info.st_mtime_ns, info.st_size, info.st_ino, info.st_dev)


def file_digest(path) -> str | None:
    """SHA-256 of one file, re-read only when its stat stamp changed."""
    path = Path(path)
    try:
        info = path.stat()
    except OSError:
        return None
    key = str(path)
    cached = _DIGESTS.get(key)
    if cached is not None and cached[0] == _stamp(info):
        return cached[1]
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    if len(_DIGESTS) >= _DIGEST_LIMIT:
        _DIGESTS.pop(next(iter(_DIGESTS)))
    _DIGESTS[key] = (_stamp(info), digest)
    return digest


def file_digest_now(path) -> str | None:
    """SHA-256 of one file, always re-read (for gates that must see any edit)."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _plain(value):
    """The canonical JSON shape of one identity part (bytes digests only)."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'sha256': hashlib.sha256(bytes(value)).hexdigest()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {'repr': repr(value)}


def identity_of(*parts) -> str:
    """One content identity from canonical parts; equal parts, equal identity."""
    payload = json.dumps([_plain(part) for part in parts], sort_keys=True,
                         separators=(',', ':'), ensure_ascii=True, default=repr)
    return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# One accepted computation per observed identity
# --------------------------------------------------------------------------- #

_IDENTITY_RESULTS: dict[tuple, object] = {}
_IDENTITY_RESULTS_LIMIT = 64


@contextmanager
def _subordinated(memo):
    """Reuse enclosing results while one identity-checked result is computed.

    The validator computed here is covered by the caller's identity
    observation, so its own nested static results are not separate exit
    checkpoints: they are seeded from the enclosing scope (a hit stays a hit)
    and any new one is discarded with this scope.
    """
    token = _SCOPE.set({} if memo is None else dict(memo))
    strict = _STRICT.set(True)
    try:
        yield
    finally:
        _STRICT.reset(strict)
        _SCOPE.reset(token)


def identity_memo(namespace, identity, compute, discover=None):
    """Return ``compute()`` once per observed content identity, per process.

    ``identity`` is observed by the caller on every call.  ``discover`` is for a
    computation whose input rows are only known after it ran (the caller records
    what it read): it is observed before the computation (reusing rows learned
    earlier) and once more after it, so the *first* call already leaves a key
    the second call can hit, while a row that changed during the computation
    yields no key and the work is repeated.
    """
    if not identity_reuse_enabled():
        return compute()
    if identity is None and discover is not None:
        identity = observed(discover)
    if identity is not None and (namespace, identity) in _IDENTITY_RESULTS:
        return deepcopy(_IDENTITY_RESULTS[(namespace, identity)])
    with _subordinated(_SCOPE.get()):
        result = compute()
    keys = []
    if identity is not None:
        keys.append((namespace, identity))
    if discover is not None:
        found = observed(discover)
        if found is not None and found != identity:
            keys.append((namespace, found))
    for key in keys:
        if len(_IDENTITY_RESULTS) >= _IDENTITY_RESULTS_LIMIT:
            _IDENTITY_RESULTS.pop(next(iter(_IDENTITY_RESULTS)))
        _IDENTITY_RESULTS[key] = deepcopy(result)
    return deepcopy(result)


def observed(identity):
    """Observe an identity, or ``None`` when it cannot be observed right now."""
    if identity is None:
        return None
    try:
        return identity()
    except Exception:
        return None


#: ``key namespace -> resolve(key)`` observations for validators whose own
#: module cannot pass one (for example ``source_lock.py``, whose accepted result
#: and key vocabulary are owned elsewhere).  ``resolve`` returns a content
#: identity or ``None``; nothing here can widen what a validator accepts.
_KEY_IDENTITIES: list[tuple[str, object]] = []


def register_key_identity(namespace, resolve):
    """Register how to observe the inputs of keys in ``namespace``."""
    if not isinstance(namespace, str) or not callable(resolve):
        raise ValueError('key-identity-registration-invalid')
    _KEY_IDENTITIES[:] = [row for row in _KEY_IDENTITIES if row[0] != namespace]
    _KEY_IDENTITIES.append((namespace, resolve))


def key_identity(key):
    """The registered input observation for ``key``, or ``None``."""
    if not isinstance(key, tuple) or not key or not isinstance(key[0], str):
        return None
    for namespace, resolve in _KEY_IDENTITIES:
        if key[0] == namespace:
            return observed(lambda: resolve(key))
    return None


def static_validation(key, validate, identity=None, observe_after=False):
    """Return the accepted result for ``key``, registering its inputs once.

    ``observe_after`` is for a validator whose identity can only be observed by
    re-reading the input rows *it* recorded: the observation then happens after
    the computation, and a row that changed while it ran leaves no identity (so
    the exit boundary computes the validator again instead of reusing it).
    """
    memo = _SCOPE.get()
    if memo is None:
        return validate()
    if key not in memo:
        identify = identity if identity is not None else (lambda: key_identity(key))
        expected_identity = None
        if not observe_after and identity_reuse_enabled():
            expected_identity = observed(identify)
        token = _STRICT.set(True)
        try:
            result = validate()
        finally:
            _STRICT.reset(token)
        if observe_after and identity_reuse_enabled():
            expected_identity = observed(identify)
        memo[key] = (deepcopy(result), validate, identify, expected_identity)
    return deepcopy(memo[key][0])


def static_validation_matches(key, validate, current):
    """Compare against the private snapshot without copying it on each check."""
    memo = _SCOPE.get()
    if memo is None:
        return validate() == current
    if key not in memo:
        static_validation(key, validate)
    return memo[key][0] == current


@contextmanager
def execution_validation_scope(*, revalidate=True):
    """Authenticate lazily, reuse observed-identical results, then reauthenticate.

    A validator registered with an identity is re-run only when re-observing
    that identity fails to reproduce it; see the module docstring.  Trusted
    local searches may disable exit revalidation entirely.  A body exception
    remains primary even when final authentication also fails.  The yielded
    state reports static authentication independently of body failures.
    """
    memo = {}
    state = {'status': 'pending', 'matches': None}
    token = _SCOPE.set(memo)
    primary = None
    try:
        yield state
    except BaseException as error:
        primary = error
        raise
    finally:
        # Final validators cannot reuse this or an enclosing scope's memo.
        disabled = _SCOPE.set(None)
        strict = _STRICT.set(True)
        failures = []
        try:
            for expected, validate, identify, identity in (memo.values() if revalidate else ()):
                try:
                    if identify is not None and identity is not None:
                        try:
                            if identify() == identity:
                                continue
                        except BaseException as error:
                            # An unobservable input is not an unchanged one.
                            failures.append(error)
                            continue
                    if validate() != expected:
                        raise ExecutionValidationError('static identity changed')
                except BaseException as error:
                    failures.append(error)
        finally:
            _STRICT.reset(strict)
            _SCOPE.reset(disabled)
            _SCOPE.reset(token)
        state.update(status='failed' if failures else 'verified', matches=not failures)
        if failures:
            error = ExecutionValidationError('execution validation failed: ' +
                                             '; '.join(repr(item) for item in failures))
            if primary is not None:
                primary.add_note(str(error))
            else:
                raise error from failures[0]
