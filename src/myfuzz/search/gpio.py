"""Read-only GPIOEN documentary views from the live production authority.

``version`` counts observed writes in the current epoch, including same-value
overwrites. It is derived metadata, not an authority-issued field version.
No view or writer reference proves a writer-to-consumer relation. Exceptions
propagate: the caller must represent unavailable queries as unknown, never
recover current execution permission from these documents.
"""
from dataclasses import dataclass
from hashlib import sha256

from .model import canonical, identifier, natural


def _ref(prefix, document):
    return prefix + sha256(canonical(document)).hexdigest()


def _word(value):
    if type(value) is not int or not 0 <= value < 1 << 32:
        raise ValueError('GPIOEN uint32 required')


def _digest(value):
    if (type(value) is not str or len(value) != 64
            or any(char not in '0123456789abcdef' for char in value)):
        raise ValueError('GPIOEN digest required')


@dataclass(frozen=True)
class GpioCurrent:
    """Immutable documentary state; version is a derived epoch write count."""
    value: int
    epoch: int
    version: int
    last_writer_ref: str | None
    evidence_ref: str
    contract: str

    def __post_init__(self):
        _word(self.value)
        natural(self.epoch)
        natural(self.version)
        if (self.version == 0) != (self.last_writer_ref is None):
            raise ValueError('GPIOEN baseline/writer mismatch')
        if self.last_writer_ref is not None:
            identifier(self.last_writer_ref)
        identifier(self.evidence_ref)
        identifier(self.contract)

    @property
    def identity(self):
        # The writer reference includes process scope and artifact provenance;
        # independent sessions with identical values/counts do not alias.
        return self.epoch, self.version, self.value, self.last_writer_ref, self.contract


def validate_gpio_documentary(witness, writes, *, expected_epoch,
                              expected_command_sequence):
    """Validate documents and derive metadata; this function grants no trust.

    Unit tests may supply documents here. Only ``read_gpio_current`` queries an
    actual live authority; saved or fabricated documents cannot enter it.
    """
    natural(expected_epoch)
    natural(expected_command_sequence)
    if type(witness) is not dict or type(writes) is not list:
        raise ValueError('GPIOEN documentary objects required')
    required = {'register', 'reset_epoch', 'value', 'local_tick',
                'command_sequence', 'process_scope', 'source_sha256',
                'artifact_digest', 'observation_contract'}
    if not required <= witness.keys():
        raise ValueError('GPIOEN witness fields missing')
    for name in ('reset_epoch', 'local_tick', 'command_sequence'):
        natural(witness[name])
    if (witness['register'] != 'GPIOEN' or witness['reset_epoch'] != expected_epoch
            or witness['command_sequence'] != expected_command_sequence):
        raise ValueError('GPIOEN witness scope mismatch')
    _word(witness['value'])
    scope = witness['process_scope']
    if type(scope) is not dict or set(scope) != {'pid', 'execution'}:
        raise ValueError('GPIOEN process scope required')
    natural(scope['pid'])
    if scope['pid'] == 0:
        raise ValueError('GPIOEN live pid required')
    identifier(scope['execution'])
    _digest(witness['source_sha256'])
    _digest(witness['artifact_digest'])
    contract = witness['observation_contract']
    if type(contract) is not dict or not contract:
        raise ValueError('GPIOEN observation contract required')
    selected = []
    previous = None
    for row in writes:
        if type(row) is not dict or not {'epoch', 'tick', 'command_sequence',
                                       'before', 'after', 'context'} <= row.keys():
            raise ValueError('GPIOEN write fields missing')
        for name in ('epoch', 'tick', 'command_sequence'):
            natural(row[name])
        _word(row['before'])
        _word(row['after'])
        if row['context'] is not None and type(row['context']) is not dict:
            raise ValueError('GPIOEN write context malformed')
        if row['epoch'] > expected_epoch:
            raise ValueError('GPIOEN future write epoch')
        if previous is not None:
            if (row['epoch'] < previous['epoch'] or row['epoch'] == previous['epoch']
                    and (row['tick'] <= previous['tick']
                         or row['command_sequence'] < previous['command_sequence']
                         or row['before'] != previous['after'])):
                raise ValueError('GPIOEN write history discontinuous')
        previous = row
        if row['epoch'] == expected_epoch:
            if (row['tick'] > witness['local_tick']
                    or row['command_sequence'] > witness['command_sequence']):
                raise ValueError('GPIOEN write is newer than witness')
            selected.append(row)
    if selected and selected[-1]['after'] != witness['value']:
        raise ValueError('GPIOEN last write/current mismatch')
    contract_ref = _ref('gpio-contract:', dict(source_sha256=witness['source_sha256'],
        artifact_digest=witness['artifact_digest'], observation_contract=contract,
        process_scope=scope))
    writer_ref = (None if not selected else _ref('gpio-writer:', dict(
        write=selected[-1], version=len(selected), contract=contract_ref)))
    return GpioCurrent(witness['value'], expected_epoch, len(selected), writer_ref,
                       _ref('gpio-current:', dict(witness=witness, writes=writes)), contract_ref)


def validate_gpio_live_scope(receipt, launches, before, after, *, expected_epoch,
                             process_pid, process_returncode):
    """Pure fail-closed scope checks; documents alone never authorize a read.

    The production write history lacks process identities. Exactly one launch
    since receipt configuration is therefore required before attributing any
    history to the current process, even when its epoch/value matches.
    """
    natural(expected_epoch)
    natural(process_pid)
    if (process_pid == 0 or process_returncode is not None
            or type(receipt) is not dict or type(launches) is not tuple
            or len(launches) != 1 or type(launches[0]) is not dict
            or type(before) is not dict or type(after) is not dict
            or before != after or before.get('reset_epoch') != expected_epoch):
        raise ValueError('GPIOEN single live launch and stable query required')
    row = launches[0]
    scope = before.get('process_scope')
    if (type(scope) is not dict or type(row.get('pid')) is not int
            or row['pid'] != process_pid or scope.get('pid') != process_pid
            or row.get('execution_nonce') != scope.get('execution')
            or row.get('reaped') is not False or row.get('returncode') is not None
            or row.get('aborted') is not False or row.get('failure_stage') is not None):
        raise ValueError('GPIOEN launch/process scope mismatch')
    identifier(scope.get('execution'))
    for name in ('artifact_digest', 'binary_sha256', 'build_digest'):
        _digest(receipt.get(name))
        if row.get(name) != receipt[name]:
            raise ValueError('GPIOEN launch receipt mismatch')
    if (row.get('ready_artifact_digest') != receipt['artifact_digest']
            or before.get('artifact_digest') != receipt['artifact_digest']
            or row.get('observed_executable_sha256') != receipt['binary_sha256']):
        raise ValueError('GPIOEN launch executable/ready mismatch')


def read_gpio_current(authority, target):
    """Query only public issue/consume/writes; never command, step, or write.

    The production issuer validates its current command sequence. A second
    query after reading writes rejects advancement during the snapshot, without
    consulting target-private sequence fields or authority registries.
    """
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    if (type(authority) is not GpioRegisterVersionAuthority
            or type(target) is not GeneratedPulpGpioSession
            or authority.target is not target):
        raise ValueError('GPIOEN actual bound authority and target required')
    # The caller must configure this receipt before prepare/start. Never opt in
    # here: doing so after an earlier unobserved process could hide old writes.
    receipt = target.validate_built_executable_receipt()
    launches = target.built_executable_launch_observations()
    epoch = target.reset_epoch
    before = authority.consume(authority.issue(register='GPIOEN', reset_epoch=epoch))
    writes = authority.writes()
    after = authority.consume(authority.issue(register='GPIOEN', reset_epoch=epoch))
    if (target.reset_epoch != epoch
            or target.validate_built_executable_receipt() != receipt
            or target.built_executable_launch_observations() != launches):
        raise ValueError('GPIOEN state advanced during read')
    process = target.process
    if process is None:
        raise ValueError('GPIOEN live process mismatch')
    validate_gpio_live_scope(receipt, launches, before, after, expected_epoch=epoch,
        process_pid=process.pid, process_returncode=process.poll())
    return validate_gpio_documentary(before, writes, expected_epoch=epoch,
        expected_command_sequence=after['command_sequence'])
