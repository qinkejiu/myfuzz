"""Source-bound INTEN reset rules; detached documents never enroll evidence.

FIX 1 -- readback-independence allow-list (rule scope; fail-closed unchanged).
The frozen rule refused *any* non-read command inside a post-reset interval, and the
shipped bootstrap necessarily writes gpio_a's PADDIR (offset 0), GPIOEN (offset 4)
and PADOUT (offset 12) there, so the interval that observed the real reset default
could never be certified.  The permission added here is narrow, explicit and
re-derived from the pinned RTL bytes on every use:

  * ``r_gpio_inten`` has exactly two writers in the pinned source -- :217 the
    asynchronous active-low reset and :234 its own APB write path -- and every other
    occurrence is a read (:138 in ``s_is_int_all``, :260 into ``s_gpio_inten``,
    :595/:605 in PRDATA).  A write decoded to ``r_gpio_dir`` / ``r_gpio_out`` /
    ``r_gpio_en`` therefore cannot alter INTEN's stored or readable value.
  * The allow-list is INTEN-referenced, never profile-wide, and lives in the rule
    and configuration (identity-pinned with profile/sidecar/RTL SHA, rule revision
    and rule hash).  ``_reviewed_readback_independence`` re-checks the anchors
    against the live bytes; a saved document can never supply the permission.
  * Writes to INTEN itself and to every 128-byte alias remain invalidating
    unconditionally (any value, any byte enable, any field).
  * ``r_gpio_en`` does gate the IRQ output at :138, so the permission is scoped to
    the **observed readback** only and is never a claim about interrupt behaviour.

FIX 2 -- per-interval refusal projection (diagnostic only, no check relaxed).
``report()`` used insertion-ordered ``setdefault`` per target, so the pre-reset
interval (no barrier) published ``missing_actual_reset_barrier_binding`` and the real
barriered-interval reason was discarded.  Every considered interval's reason is now
published under ``state.interval_refusals`` as
``{target_instance, target_epoch, reason}`` while ``state.gaps`` keeps its accepted
``{target_instance, reason}`` shape, whose headline reason is the first reason from an
interval that actually bound a reset barrier.  The closed session-document validator
was extended strictly for both shapes: the state key set, the new row key
``target_epoch`` (unsigned integer or null), the per-target partition, the gap
taxonomy and the ``readback_allowance`` certificate projection are all exact.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from weakref import WeakKeyDictionary

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability, _revalidate_ip_test_capability
from myfuzz.local_harness import pulp_gpio_probe_contract as _probe_contract
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_register_map
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from .register_program_runtime import RegisterProgramRuntime
from . import native_reset_evidence as _native_reset_module
from .native_reset_evidence import NativeResetEvidence
from .memory_commit_authority import MemoryCommitAuthority
from .memory_authority_distribution import MemoryAuthorityDistribution
from . import register_program_verifier as _program_verifier_module
from .register_program_verifier import RegisterProgramVerifier as _RegisterProgramVerifier
from .ordinary_apb_access_evidence import OrdinaryApbAccessEvidence as _OrdinaryApbAccessEvidence

_SOURCE='third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv'
_SOURCE_SHA='1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef'
_PROBE_SOURCE='src/myfuzz/local_harness/pulp_gpio_probe_contract.py'
_PROBE_SHA='52c5a3eb0aa3cd14d4e4f2543e4e483d0d23ae02c0812b93622931730f4063dd'
_REVISION='git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83'
_EVIDENCE_REF='rtl:'+_SOURCE+'@f82caeb7f7d89427f05e9af5ed31e0675efe0d83:217,325-328,590-598,138;sha256='+_SOURCE_SHA
_CRITICAL_SOURCE_NAMES=('native_reset_evidence.py','register_program_runtime.py','memory_commit_authority.py',
    'memory_authority_distribution.py','register_program_verifier.py','ordinary_apb_access_evidence.py')
# Scope of the configured rule (what this verifier may support when every link
# is real) and the scope of a report that observed no complete readback chain.
_READBACK_SCOPE='observed_source_bound_reset_default_readback'
_REFUSAL_SCOPE='source_bound_reset_default_refusal_only'
_CERTIFICATE_SCHEMA='ordinary_register_reset_default_certificate.v1'
# Every refusal reason this verifier can publish; the closed document validator
# accepts exactly these.
_GAP_REASONS=frozenset(('incomplete_reset_evidence','missing_native_reset_default_readback',
    'missing_actual_reset_barrier_binding','incomplete_command_coverage',
    'affecting_write_in_reset_interval','unknown_command_in_reset_interval',
    'unknown_offset_in_reset_interval','incomplete_command_in_reset_interval',
    'missing_ordinary_access_evidence','missing_actual_selected_read',
    'actual_selected_read_link_mismatch','ambiguous_selected_read',
    'missing_issued_ram_commit','foreign_issued_ram_commit','ambiguous_issued_ram_commit',
    'observed_readback_is_not_source_reset_default','interval_seal_domain_mismatch'))
# Closed projection of one Runner-bound Task2 interval and of one Task1 command.
_RESET_SEAL_KEYS=frozenset(('schema_version','target_instance','target_epoch','logical_process',
    'reset_barrier_event_id','cpu_component','cpu_source_epoch','cpu_logical_process',
    'runner_command_epoch','memory_generation','memory_ids'))
_COMMAND_KEYS=frozenset(('schema_version','command_ordinal','logical_process','target_epoch',
    'command_sequence','operation','fields','parsed_receipt_projection','status','reason',
    'coverage_cursor'))
_CERTIFICATE_KEYS=frozenset(('schema_version','evidence_id','target_instance','register','field',
    'operation','offset','width','reset_value','observed_reset_value','alias_period',
    'address_decode_mask','rule_sha256','configuration_sha256','native_reset_configuration_sha256',
    'profile_fingerprint','sidecar_fingerprint','source_path','source_sha256','source_revision',
    'probe_contract_source','probe_contract_sha256','register_map_sha256','evidence_ref',
    'reset_seal','coverage_cursor','read_access_ref','ram_commit_ref','proof_scope','readback_allowance',
    'grants_storage','grants_version_dependency','grants_prerequisites','grants_functional'))
_COVERAGE_CURSOR_KEYS=frozenset(('first_command_ordinal','last_command_ordinal','command_count',
    'first_command_sequence','last_command_sequence','last_coverage_cursor','commands_sha256'))
_READ_ACCESS_KEYS=frozenset(('access_id','ordinal','target_receipt_event_id','acceptance_event_id',
    'delivery_event_id','source_transaction','request_evidence','cpu_response','command_ordinal',
    'command_sequence','target_receipt_rdata','observed_readback'))
_RAM_COMMIT_KEYS=frozenset(('commit_id','service_commit_sequence','event_id','fullkey','memory_id',
    'generation','byte_offset','width_bytes','byte_enable','enabled_byte_cells','payload_sha256'))
_GRANT_NAMES=('grants_storage','grants_version_dependency','grants_prerequisites','grants_functional')
# The permission this re-open adds is scoped to the observed readback, never to
# interrupt behaviour: r_gpio_en gates the IRQ output at :138.
_ALLOWANCE_SCOPE='observed_readback_only'
_READBACK_ALLOWANCE_KEYS=frozenset(('class','observed_register','observed_offset','permitted_registers',
    'permitted_offsets','permitted_command_ordinals','permitted_command_count','inten_writer_source_lines',
    'irq_output_gate_source_line','scope','irq_semantics_granted'))
# FIX 1 evidence, pinned by exact line and exact stripped text against the frozen
# RTL bytes (SHA enforced separately by _SOURCE_SHA).  Nothing here is inferred
# from a register name.
_INTEN_WRITE_SITES=((217,"r_gpio_inten[i]   <= 1'b0;"),
    (234,"r_gpio_inten[i]   <= s_gpio_inten[i]  ;"))
_INTEN_ENABLE_SITES=((248,"s_write_inten = 64'h0;"),
    (327,"s_write_inten[31:0] = 32'hFFFFFFFF;"),
    (332,"s_write_inten[63:32] = 32'hFFFFFFFF;"))
_INTEN_NEXT_STATE_SITES=((260,"s_gpio_inten[i]   = r_gpio_inten[i];"),
    (269,"s_gpio_inten[i]   = 1'b0;"),
    (328,"s_gpio_inten[31:0]  = PWDATA;"),
    (333,"s_gpio_inten[63:32]  = PWDATA;"))
_INTEN_IRQ_GATE_SITE=(138,"assign s_is_int_all  = r_gpio_inten & r_gpio_en & (s_is_int_rise | s_is_int_fall | s_is_int_rifa);")
_INTEN_READBACK_SITES=((260,"s_gpio_inten[i]   = r_gpio_inten[i];"),
    (595,"PRDATA[i] = r_gpio_inten[i];"),
    (605,"PRDATA[i-32] = r_gpio_inten[i];"))
# DIR / OUT / GPIOEN: the only registers whose written state is disjoint from
# r_gpio_inten.  PADOUTSET/PADOUTCLR are also r_gpio_out-only by the same
# argument but are deliberately NOT allowed: the shipped bootstrap never writes
# them, so allowing them would widen the relaxation without evidence.
_READBACK_INDEPENDENT_WRITES=(
    dict(register='PADDIR',offset=0,decode_macro='REG_PADDIR_00_31',decode_label='`REG_PADDIR_00_31:',
        decode_source_line=277,write_enable='s_write_dir',next_state='s_gpio_dir',state='r_gpio_dir',
        guard_site=(229,"if(s_write_dir[i])"),
        state_site=(230,"r_gpio_dir[i]     <= s_gpio_dir[i]    ;"),
        enable_sites=(
            (245,"s_write_dir   = 64'h0;"),
            (279,"s_write_dir[31:0]  = 32'hFFFFFFFF;"),
            (284,"s_write_dir[63:32] = 32'hFFFFFFFF;")),
        next_state_sites=(
            (258,"s_gpio_dir[i]     = r_gpio_dir[i];"),
            (267,"s_gpio_dir[i]     = 1'b0;"),
            (280,"s_gpio_dir[31:0]   = PWDATA;"),
            (285,"s_gpio_dir[63:32]  = PWDATA;")),
        state_sites=(
            (215,"r_gpio_dir[i]     <= 1'b0;"),
            (230,"r_gpio_dir[i]     <= s_gpio_dir[i]    ;"))),
    dict(register='GPIOEN',offset=4,decode_macro='REG_GPIOEN_00_31',decode_label='`REG_GPIOEN_00_31:',
        decode_source_line=415,write_enable='s_write_gpen',next_state='s_gpio_en',state='r_gpio_en',
        guard_site=(235,"if(s_write_gpen[i])"),
        state_site=(236,"r_gpio_en[i]      <= s_gpio_en[i]     ;"),
        enable_sites=(
            (249,"s_write_gpen  = 64'h0;"),
            (417,"s_write_gpen[31:0] = 32'hFFFFFFFF;"),
            (422,"s_write_gpen[63:32] = 32'hFFFFFFFF;")),
        next_state_sites=(
            (261,"s_gpio_en[i]      = r_gpio_en[i];"),
            (270,"s_gpio_en[i]      = 1'b0;"),
            (418,"s_gpio_en[31:0]    = PWDATA;"),
            (423,"s_gpio_en[63:32]    = PWDATA;")),
        state_sites=(
            (218,"r_gpio_en[i]      <= 1'b0;"),
            (236,"r_gpio_en[i]      <= s_gpio_en[i]     ;"))),
    dict(register='PADOUT',offset=12,decode_macro='REG_PADOUT_00_31',decode_label='`REG_PADOUT_00_31:',
        decode_source_line=287,write_enable='s_write_out',next_state='s_gpio_out',state='r_gpio_out',
        guard_site=(231,"if(s_write_out[i])"),
        state_site=(232,"r_gpio_out[i]     <= s_gpio_out[i]    ;"),
        enable_sites=(
            (246,"s_write_out   = 64'h0;"),
            (289,"s_write_out[31:0]  = 32'hFFFFFFFF;"),
            (294,"s_write_out[63:32] = 32'hFFFFFFFF;"),
            (299,"s_write_out[31:0]  = 32'hFFFFFFFF;"),
            (306,"s_write_out[63:32] = 32'hFFFFFFFF;"),
            (313,"s_write_out[31:0]  = 32'hFFFFFFFF;"),
            (320,"s_write_out[63:32] = 32'hFFFFFFFF;")),
        next_state_sites=(
            (259,"s_gpio_out[i]     = r_gpio_out[i];"),
            (268,"s_gpio_out[i]     = 1'b0;"),
            (290,"s_gpio_out[31:0]   = PWDATA;"),
            (295,"s_gpio_out[63:32]  = PWDATA;"),
            (302,"s_gpio_out[i]  = r_gpio_out[i] | PWDATA[i];"),
            (309,"s_gpio_out[i]  = r_gpio_out[i] | PWDATA[i-32];"),
            (316,"s_gpio_out[i]  = r_gpio_out[i] & ~PWDATA[i];"),
            (323,"s_gpio_out[i]  = r_gpio_out[i] & ~PWDATA[i-32];")),
        state_sites=(
            (216,"r_gpio_out[i]     <= 1'b0;"),
            (232,"r_gpio_out[i]     <= s_gpio_out[i]    ;"))))
_INDEPENDENCE_EVIDENCE_REF=('rtl:'+_SOURCE+'@f82caeb7f7d89427f05e9af5ed31e0675efe0d83:'
    '138,217,229-236,277-295,415-423;sha256='+_SOURCE_SHA)

def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)

def _path_member_code(value):
    if isinstance(value,property):
        return tuple(item for function in (value.fget,value.fset,value.fdel)
                     for item in (function,getattr(function,'__code__',None)))
    function=value.__func__ if isinstance(value,(staticmethod,classmethod)) else value
    return (function,getattr(function,'__code__',None))


def _make_path_guard(path_type):
    # Snapshot both the factory and the actual platform path MRO. Stdlib internal
    # object contents (_flavour, module helper implementations) remain trusted.
    concrete=type(path_type('.'))
    classes=tuple(dict.fromkeys((*path_type.__mro__,*concrete.__mro__)))
    metadata=_path_member_code;metadata_code=metadata.__code__
    records=tuple((cls,cls.__mro__,tuple((name,value,metadata(value))
                  for name,value in vars(cls).items())) for cls in classes)
    namespace=path_type.__new__.__globals__
    class_exports=tuple((name,value) for name,value in namespace.items() if value in classes)
    def check():
        if (_path_member_code is not metadata or metadata.__code__ is not metadata_code
                or any(namespace.get(name) is not value for name,value in class_exports)):
            raise ValueError('reset-default-path-dispatch-drift')
        for cls,mro,entries in records:
            current=vars(cls)
            if (cls.__mro__ is not mro or set(current)!={name for name,_,_ in entries}
                    or any(current[name] is not value or any(actual is not expected for actual,expected in zip(metadata(value),code))
                           for name,value,code in entries)):
                raise ValueError('reset-default-path-dispatch-drift')
    return check


def _current_source_files():
    own=Path(__file__).resolve();base=own.parents[3]
    paths=(own,base/_SOURCE,base/_PROBE_SOURCE,*(own.with_name(n) for n in _CRITICAL_SOURCE_NAMES))
    return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def _assigned_signal(line):
    """The assignment target of one RTL line, or None when it assigns nothing."""
    body=line.split('//')[0]
    for operator in ('<=','='):
        if operator in body:return body.split(operator,1)[0].strip()
    return None


def _assignment_sites(lines,signal):
    """Every (line number, stripped text) that assigns the given signal."""
    return tuple((number,lines[number-1].strip()) for number in range(1,len(lines)+1)
                 if (_assigned_signal(lines[number-1]) or '').split('[')[0]==signal)


def _decode_offset(lines,macro):
    """Byte offset of one reviewed address-decode macro, read from its `define."""
    prefix='`define '+macro+' '
    for number,value in enumerate(lines,1):
        if value.startswith(prefix):
            body=value[len(prefix):].split('//')[0].strip()
            if (len(body)!=8 or not body.startswith("5'b")
                    or any(digit not in '01' for digit in body[3:])):
                raise ValueError('reset-rule-address-decode-word-drift')
            return number,int(body[3:],2)*4
    raise ValueError('reset-rule-address-decode-macro-drift')


def _reviewed_readback_independence(text):
    """Re-derive the INTEN-vs-DIR/OUT/GPIOEN independence claim from source bytes.

    Every step is a byte-level query against the pinned RTL: the exact writer lines of
    ``r_gpio_inten``, the exact assignment sites of the INTEN write-enable and
    next-state, the IRQ output gate, the declared readback lines, and for each
    allow-listed register the decode case block, its write-enable and next-state
    assignment sites, and every assignment site of the stored state it can reach.
    Any drift refuses; a saved document can never supply this list.
    """
    lines=text.split('\n')
    def exact(site):
        number,expected=site
        if not 0<number<=len(lines) or lines[number-1].strip()!=expected:
            raise ValueError('reset-rule-inten-independence-anchor-drift')
    for site in (*_INTEN_WRITE_SITES,*_INTEN_ENABLE_SITES,*_INTEN_NEXT_STATE_SITES,
                 _INTEN_IRQ_GATE_SITE,*_INTEN_READBACK_SITES):
        exact(site)
    if _assignment_sites(lines,'r_gpio_inten')!=_INTEN_WRITE_SITES:
        raise ValueError('reset-rule-inten-writer-set-drift')
    if _assignment_sites(lines,'s_write_inten')!=_INTEN_ENABLE_SITES:
        raise ValueError('reset-rule-inten-write-enable-set-drift')
    if _assignment_sites(lines,'s_gpio_inten')!=_INTEN_NEXT_STATE_SITES:
        raise ValueError('reset-rule-inten-next-state-set-drift')
    reviewed=[]
    for entry in _READBACK_INDEPENDENT_WRITES:
        define_line,offset=_decode_offset(lines,entry['decode_macro'])
        if offset!=entry['offset']:raise ValueError('reset-rule-readback-independent-offset-drift')
        for site in (entry['guard_site'],entry['state_site']):exact(site)
        exact((entry['decode_source_line'],entry['decode_label']))
        if _assignment_sites(lines,entry['write_enable'])!=entry['enable_sites']:
            raise ValueError('reset-rule-readback-independent-enable-set-drift')
        if _assignment_sites(lines,entry['next_state'])!=entry['next_state_sites']:
            raise ValueError('reset-rule-readback-independent-next-state-set-drift')
        if _assignment_sites(lines,entry['state'])!=entry['state_sites']:
            raise ValueError('reset-rule-readback-independent-state-set-drift')
        if entry['state']=='r_gpio_inten' or entry['write_enable']=='s_write_inten':
            raise ValueError('reset-rule-readback-independent-shared-state')
        reviewed.append(dict(register=entry['register'],offset=offset,decode_macro=entry['decode_macro'],
            decode_define_source_line=define_line,decode_source_line=entry['decode_source_line'],
            write_enable=entry['write_enable'],next_state=entry['next_state'],state=entry['state'],
            guard_source_line=entry['guard_site'][0],state_source_line=entry['state_site'][0],
            enable_source_lines=[site[0] for site in entry['enable_sites']],
            next_state_source_lines=[site[0] for site in entry['next_state_sites']],
            state_source_lines=[site[0] for site in entry['state_sites']]))
    return tuple(reviewed)


def derive_inten_reset_rule(profile,capability,*,base_dir,target_instance=None):
    """A closed reviewed RTL rule, not inference from generic rw metadata."""
    if (type(profile) is not ComponentProfile or profile.component_id!='pulp_gpio'
            or profile.kind!='peripheral' or profile.address.window_size!=4096
            or profile.address.alignment!=4096):
        raise ValueError('reset-rule-exact-reviewed-target-required')
    _revalidate_ip_test_capability(capability,profile=profile)
    if target_instance is not None and (type(target_instance) is not str or not target_instance):
        raise ValueError('reset-rule-target-instance-required')
    probe=pulp_gpio_register_map()
    probe_path=Path(__file__).resolve().parents[3]/_PROBE_SOURCE
    if (hashlib.sha256(probe_path.read_bytes()).hexdigest()!=_PROBE_SHA
            or probe.get('decode')!='PADDR[6:2]' or probe.get('alias_period_bytes')!=128
            or probe.get('registers',{}).get('24')!={'name':'INTEN','semantics':'overwrite'}):
        raise ValueError('reset-rule-current-probe-decode-drift')
    source=profile.source
    if (source.source_root!='third_party/soc-pulp-apb-gpio' or source.revision!=_REVISION
            or source.top_module!='apb_gpio' or source.files!=('rtl/apb_gpio.sv',)
            or dict(source.elaboration.parameters)!=dict(APB_ADDR_WIDTH='12',NBIT_PADCFG='4',PAD_NUM='32')):
        raise ValueError('reset-rule-reviewed-source-required')
    path=Path(base_dir)/_SOURCE
    source_bytes=path.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest()!=_SOURCE_SHA:raise ValueError('reset-rule-source-drift')
    try:source_text=source_bytes.decode('utf-8')
    except UnicodeDecodeError:raise ValueError('reset-rule-source-drift')
    reviewed=_reviewed_readback_independence(source_text)
    registers=probe['registers']
    reviewed_offsets=[]
    for row in reviewed:
        declared=registers.get(str(row['offset']))
        if type(declared) is not dict or declared.get('name')!=row['register']:
            raise ValueError('reset-rule-reviewed-register-map-mismatch')
        reviewed_offsets.append(row['offset'])
    known_unrelated=[offset for offset in sorted(int(key) for key in registers) if offset!=24]
    if reviewed_offsets!=sorted(reviewed_offsets) or len(set(reviewed_offsets))!=len(reviewed_offsets):
        raise ValueError('reset-rule-reviewed-register-map-mismatch')
    register=next((r for r in profile.address.registers if r.offset==24),None)
    if (register is None or register.name!='INTEN' or register.width!=32 or register.access!='rw' or register.side_effect!='none'
            or register.reset_value not in (None,0) or register.writable_bits not in (None,0xffffffff)):
        raise ValueError('reset-rule-plain-inten-word-required')
    field=next((r for r in capability.register_semantics if r.register==register.name and r.field=='value'),None)
    if (field is None or (field.lsb,field.width,field.access,field.read_mask,field.write_mask,field.reset_value,field.side_effect)
            !=(0,32,'rw',0xffffffff,0xffffffff,0,'none') or field.evidence_ref!=_EVIDENCE_REF):
        raise ValueError('reset-rule-source-bound-inten-field-required')
    if sorted(r.offset for r in profile.address.registers)!=list(range(0,56,4)):
        raise ValueError('reset-rule-complete-reviewed-register-map-required')
    return dict(schema_version='source_bound_inten_reset_rule.v2',register=register.name,field=field.field,
        offset=24,width=32,reset_value=0,profile_reset_value=register.reset_value,target_instance=target_instance,
        probe_contract_source=_PROBE_SOURCE,probe_contract_sha256=_PROBE_SHA,
        register_map_sha256=hashlib.sha256(_json(probe).encode()).hexdigest(),
        address_decode_mask=124,alias_period=128,known_unrelated_offsets=known_unrelated,
        profile_offsets_outside_reviewed_map=[r.offset for r in profile.address.registers
            if r.offset!=24 and r.offset not in known_unrelated],
        readback_independent_writes=deepcopy(list(reviewed)),
        readback_independent_offsets=[row['offset'] for row in reviewed],
        readback_allowance_class='source_reviewed_disjoint_state_write',readback_scope_only=True,
        irq_semantics_granted=False,irq_output_gate_source_line=_INTEN_IRQ_GATE_SITE[0],
        inten_writer_source_lines=[site[0] for site in _INTEN_WRITE_SITES],
        independence_evidence_ref=_INDEPENDENCE_EVIDENCE_REF,
        source_path=_SOURCE,source_sha256=_SOURCE_SHA,source_revision=_REVISION,
        profile_fingerprint=profile.profile_fingerprint,sidecar_fingerprint=capability.sidecar_fingerprint,
        evidence_ref=field.evidence_ref,reset_source_lines=[209,217],write_source_lines=[233,234,325,328],
        grants_functional=False)

def _validate_inten_rule(rule):
    if type(rule) is not dict:raise ValueError('reset-rule-closed-current-rule-required')
    base=Path(__file__).resolve().parents[3]
    profile=load_component_profile(base/'configs/peripherals/pulp_gpio/component_profile.json')
    capability=load_ip_test_capability(base/'configs/peripherals/pulp_gpio/test_capability.json',profile=profile)
    expected=derive_inten_reset_rule(profile,capability,base_dir=base,target_instance=rule.get('target_instance'))
    if _json(rule)!=_json(expected):raise ValueError('reset-rule-current-target-comparison-mismatch')


def classify_inten_command(command,*,rule):
    _validate_inten_rule(rule)
    if type(command) is not dict or command.get('status')!='parsed_complete':return 'incomplete'
    operation=command.get('operation');fields=command.get('fields')
    if operation=='STEP_GPIO':
        return ('stable_field_no_internal_writer' if type(fields) in (list,tuple) and len(fields)==1
                and type(fields[0]) is int and 0<=fields[0]<=0xffffffff else 'unknown_command')
    if operation!='ACCESS_GPIO':return 'unknown_command'
    if (type(fields) not in (list,tuple) or len(fields)!=5
            or any(type(n) is not int or n<0 for n in fields)
            or fields[0]>0xffffffff or fields[1] not in (0,1) or fields[2]>=4096 or fields[2]%4
            or fields[3]>0xffffffff or fields[4]>15):return 'unknown_command'
    offset=fields[2]&rule['address_decode_mask']
    if fields[1]==0:return 'read'
    if offset==rule['offset']:return 'affecting_write'
    if offset in rule['readback_independent_offsets']:return 'readback_independent_write'
    return 'unrelated_write' if offset in rule['known_unrelated_offsets'] else 'unknown_offset'


def _create_verifier_type():
    pins=WeakKeyDictionary();sealed=set()
    class SealedType(type):
        def __setattr__(cls,name,value):
            if cls in sealed and type.__getattribute__(cls,name) is not value:
                raise ValueError('reset-default-sealed-class-metadata')
            return type.__setattr__(cls,name,value)
        def __delattr__(cls,name):
            if cls in sealed:raise ValueError('reset-default-sealed-class-metadata')
            return type.__delattr__(cls,name)
    class RegisterResetDefaultVerifier(metaclass=SealedType):
        """Startup recipient and fail-closed semantic evidence reader."""
        def __init__(self,runtime,*,max_records=256):
            guard()
            if (type(runtime) is not RegisterProgramRuntime or type(max_records) is not int
                    or not 1<=max_records<=65536 or runtime.session._begun):
                raise ValueError('reset-default-beforebegin-runtime-required')
            require_runtime(runtime)
            canonical=Path(__file__).resolve().parents[3]
            if any(Path(runtime.runner.sessions[alias].base_dir).resolve()!=canonical for alias in runtime.sidecars):
                raise ValueError('reset-default-canonical-target-source-root-required')
            runtime_entries['validate'][0](runtime);runner=runtime.runner;evidence=runner._native_reset_evidence
            if type(evidence) is not NativeResetEvidence:raise ValueError('reset-default-task2-required')
            require_evidence(evidence)
            evidence_entries['validate'][0](evidence)
            authority=runner._memory_commit_authority
            if (type(authority) is not MemoryCommitAuthority or evidence._authority is not authority
                    or runner._register_reset_default_verifier is not None or runner._register_program_verifier is not None):
                raise ValueError('reset-default-same-unused-authority-before-register-verifier-required')
            require_authority(authority)
            ordinary=runner._ordinary_apb_access_evidence
            if ordinary is not None:
                if type(ordinary) is not _OrdinaryApbAccessEvidence:
                    raise ValueError('reset-default-actual-ordinary-access-evidence-required')
                require_ordinary(ordinary)
            registry=authority._consumers;before=frozenset(registry)
            allowed={'default'}
            dependency=runner._memory_dependency_consumer
            if dependency is not None:
                if dependency._commit_authority is not authority or dependency._authority_consumer!='dependency_evidence':
                    raise ValueError('reset-default-actual-startup-consumer-required')
                allowed.add('dependency_evidence')
            if before!=allowed:raise ValueError('reset-default-unknown-startup-consumer')
            authority_entries['validate_consumer_registration'][0](authority,'register_reset_default_verifier')
            self.runtime=runtime;self._evidence=evidence;self._authority=authority;self._limit=max_records
            self._ordinary=ordinary
            self._rules={}
            for alias,path in runtime.sidecars.items():
                target=runner.sessions[alias];profile=target.artifact.plan.profile
                capability=load_ip_test_capability(path,profile=profile)
                self._rules[alias]=derive_inten_reset_rule(profile,capability,base_dir=target.base_dir,target_instance=alias)
            self._sources=_current_source_files()
            self._runtime_pin=runtime._static_json;self._evidence_pin=_json(evidence_entries['configuration'][0](evidence))
            self._configuration=dict(schema_version='register_reset_default_configuration.v1',max_records=max_records,
                runtime_configuration_sha256=hashlib.sha256(runtime._static_json.encode()).hexdigest(),
                native_reset_configuration_sha256=hashlib.sha256(self._evidence_pin.encode()).hexdigest(),
                rules=deepcopy(self._rules),source_files=dict(self._sources),
                proof_scope=_READBACK_SCOPE,grants_functional=False,
                grants_storage=False,grants_version_dependency=False,grants_prerequisites=False)
            self._config_pin=_json(self._configuration);self._bad=False;self._commits={};self._history={}
            self._methods=methods
            authority_entries['register_consumer'][0](authority,'register_reset_default_verifier')
            if authority._consumers is not registry or authority._consumers!=set(before)|{'register_reset_default_verifier'}:
                raise ValueError('reset-default-atomic-consumer-registration-mismatch')
            self._consumer_set=authority._consumers;self._consumer_floor=frozenset(authority._consumers)
            pins[self]={'binding':(runtime,evidence,authority,self._consumer_set,self._consumer_floor,self._config_pin,methods,max_records,ordinary),
                        'bad':False}
            runner._register_reset_default_verifier=self

        def __getattribute__(self,name):
            if name in methods:
                guard()
                if name in object.__getattribute__(self,'__dict__'):
                    if self in pins:pins[self]['bad']=True
                    object.__setattr__(self,'_bad',True)
                    raise ValueError('reset-default-instance-method-dispatch-drift')
                return methods[name][0].__get__(self,cls)
            return object.__getattribute__(self,name)

        def configuration(self):methods['_validate'][0](self);return json.loads(self._config_pin)

        def _validate(self):
            try:
                record=pins.get(self)
                actual=(self.runtime,self._evidence,self._authority,self._consumer_set,self._consumer_floor,
                        self._config_pin,self._methods,self._limit,self._ordinary)
                if (record is None or any(actual[i] is not record['binding'][i] for i in (0,1,2,3,4,6,8))
                        or actual[5]!=record['binding'][5] or actual[7]!=record['binding'][7]):
                    raise ValueError('reset-default-private-startup-binding-drift')
                if (self._consumer_floor is not record['binding'][4] or self._methods is not methods
                        or type(self._bad) is not bool or self._bad is not record['bad']):
                    raise ValueError('reset-default-private-startup-projection-drift')
                guard()
                require_runtime(self.runtime);require_evidence(self._evidence);require_authority(self._authority)
                if self._ordinary is not None:require_ordinary(self._ordinary)
                if (type(self) is not _TYPE or any(n in vars(self) or getattr(_TYPE,n) is not f or f.__code__ is not c
                        for n,(f,c) in methods.items())
                        or any(hashlib.sha256(Path(p).read_bytes()).hexdigest()!=h for p,h in self._sources.items())
                        or self.runtime.runner._register_reset_default_verifier is not self
                        or self.runtime.runner._memory_commit_authority is not self._authority
                        or self.runtime.runner._native_reset_evidence is not self._evidence
                        or self.runtime.runner._ordinary_apb_access_evidence is not self._ordinary
                        or self._evidence._authority is not self._authority
                        or self._authority._consumers is not self._consumer_set
                        or not self._consumer_floor.issubset(self._consumer_set)
                        or self._consumer_set-self._consumer_floor not in (set(),{'register_program_verifier'})
                        or (self._consumer_set-self._consumer_floor and not self._actual_later_register_verifier())
                        or 'register_reset_default_verifier' not in self._consumer_set
                        or self._authority.degraded
                        or type(self._limit) is not int or self._limit!=self._configuration['max_records']
                        or _json(self._rules)!=_json(self._configuration['rules'])
                        or _json(self._sources)!=_json(self._configuration['source_files'])
                        or self.runtime._static_json is not self._runtime_pin
                        or _json(self._configuration)!=self._config_pin):
                    self._bad=True;raise ValueError('reset-default-binding-or-source-drift')
                runtime_entries['validate_static_configuration'][0](self.runtime)
                evidence_entries['validate'][0](self._evidence,allow_incomplete=True)
                if _json(evidence_entries['configuration'][0](self._evidence))!=self._evidence_pin:
                    self._bad=True;raise ValueError('reset-default-evidence-configuration-drift')
            except BaseException:
                if self in pins:pins[self]['bad']=True
                self._bad=True
                raise
        def _actual_later_register_verifier(self):
            actual=self.runtime.runner._register_program_verifier
            if (type(actual) is not program_type or actual.runtime is not self.runtime
                    or actual._authority is not self._authority or actual._consumers is not self._consumer_set):return False
            try:program_validate(actual)
            except (AttributeError,KeyError,ValueError):return False
            return True

        def _preflight_command(self,*,new_operation=False):
            if type(new_operation) is not bool:raise ValueError('reset-default-operation-boolean-required')
            methods['_validate'][0](self)
            if self._bad or self.runtime._uncertain or self._evidence._status=='incomplete':
                raise ValueError('reset-default-permanently-incomplete')
            if new_operation and len(self._commits)>=self._limit:raise ValueError('reset-default-capacity')

        def _consume_actual_commit(self,logged,token):
            try:
                methods['_preflight_command'][0](self)
                issued=resolver(self._authority,token,consumer='register_reset_default_verifier')
                if (type(logged) is not dict or type(logged.get('event_id')) is not int
                        or self.runtime.runner._event_ref_by_id(logged['event_id']) is not logged
                        or issued is None or issued.get('component')!=self.runtime.cpu_component
                        or _json(issued['commit_document'])!=_json(logged.get('commit_document'))
                        or _json(issued['fullkey'])!=_json(logged.get('transaction'))):
                    raise ValueError('reset-default-actual-issued-journal-commit-required')
                if len(self._commits)>=self._limit:raise ValueError('reset-default-capacity')
                self._commits[issued['commit_id']]=_json(dict(certificate=issued,logged=deepcopy(logged)))
            except BaseException:
                if self in pins:pins[self]['bad']=True
                self._bad=True;raise

        def _ordinary_access_rows(self):
            """Live detached completed-access rows, or None when none were installed."""
            collector=self.runtime.runner._ordinary_apb_access_evidence
            if collector is None or collector is not self._ordinary:return None
            require_ordinary(collector)
            if 'completed_accesses' in vars(collector):raise ValueError('reset-default-ordinary-collector-drift')
            return ordinary_entries['completed_accesses'][0](collector)

        def _certificate_for_interval(self,seal,*,commands,accesses,commits):
            """Chain-only issuance for one already Runner-bound reset interval.

            Returns (certificate, None) or (None, refusal reason). Eligibility is
            not decided here: only NativeResetEvidence.completed_intervals() can
            supply a seal, and it filters on the sealed native_eligible lifecycle
            fact. A detached call therefore proves rule conformance only.
            """
            rule=self._rules.get(seal.get('target_instance')) if type(seal) is dict else None
            if (type(seal) is not dict or set(seal)!=set(_RESET_SEAL_KEYS)
                    or seal.get('schema_version')!='native_reset_interval.v1' or rule is None
                    or type(seal.get('target_instance')) is not str or not seal['target_instance']
                    or type(seal.get('cpu_component')) is not str or not seal['cpu_component']
                    or type(seal.get('memory_ids')) is not list or not seal['memory_ids']
                    or any(type(value) is not str or not value for value in seal['memory_ids'])
                    or len(set(seal['memory_ids']))!=len(seal['memory_ids'])
                    or any(type(seal.get(name)) is not int or seal[name]<0 for name in
                           ('target_epoch','logical_process','cpu_source_epoch','cpu_logical_process',
                            'runner_command_epoch','memory_generation'))
                    or seal['logical_process']<1):
                return None,'interval_seal_domain_mismatch'
            _validate_inten_rule(rule)
            # Runner binding: without the global reset barrier this is not a reset default.
            barrier=seal.get('reset_barrier_event_id')
            if type(barrier) is not int or barrier<1:return None,'missing_actual_reset_barrier_binding'
            if accesses is None:return None,'missing_ordinary_access_evidence'
            if type(commands) not in (list,tuple) or not commands or len(commands)>65536:
                return None,'incomplete_command_coverage'
            ordinals=[];sequences=[];classified=[]
            for command in commands:
                if (type(command) is not dict or set(command)!=set(_COMMAND_KEYS)
                        or command.get('schema_version')!='native_reset_command.v1'
                        or command.get('status')!='parsed_complete' or command.get('reason') is not None
                        or type(command.get('command_ordinal')) is not int or command['command_ordinal']<1
                        or type(command.get('command_sequence')) is not int or command['command_sequence']<1
                        or command.get('coverage_cursor')!=command['command_ordinal']
                        or command.get('logical_process')!=seal['logical_process']
                        or command.get('target_epoch')!=seal['target_epoch']
                        or type(command.get('parsed_receipt_projection')) is not dict):
                    return None,'incomplete_command_coverage'
                ordinals.append(command['command_ordinal']);sequences.append(command['command_sequence'])
                kind=classify_inten_command(command,rule=rule)
                if kind=='affecting_write':return None,'affecting_write_in_reset_interval'
                if kind=='unknown_offset':return None,'unknown_offset_in_reset_interval'
                if kind=='unknown_command':return None,'unknown_command_in_reset_interval'
                if kind not in ('read','stable_field_no_internal_writer','readback_independent_write'):
                    return None,'incomplete_command_in_reset_interval'
                classified.append((command,kind))
            if (ordinals!=list(range(ordinals[0],ordinals[0]+len(ordinals)))
                    or any(right<=left for left,right in zip(sequences,sequences[1:]))):
                return None,'incomplete_command_coverage'
            # Exactly one exact successful selected READ, in the sealed domains.
            reads=[command for command,kind in classified if kind=='read' and
                (command['fields'][1]==0 and (command['fields'][2]&rule['address_decode_mask'])==rule['offset']
                 and command['fields'][4]==15)]
            if not reads:return None,'missing_actual_selected_read'
            def in_domains(row):
                association=row['association'];transaction=association['source_transaction']
                return (association['target_instance']==seal['target_instance']
                    and association['target_reset_epoch']==seal['target_epoch']
                    and association['memory_generation']==seal['memory_generation']
                    and transaction['source_component']==seal['cpu_component']
                    and transaction['source_epoch']==seal['cpu_source_epoch'])
            candidates=[]
            for command in reads:
                projection=command['parsed_receipt_projection'];payload=projection.get('payload')
                if (projection.get('status')!='result' or type(payload) is not dict or payload.get('error')
                        or type(payload.get('rdata')) is not int or not 0<=payload['rdata']<1<<32):
                    return None,'incomplete_command_in_reset_interval'
                for row in accesses:
                    if (type(row) is not dict or row.get('schema_version')!='ordinary_apb_completed_access.v1'
                            or type(row.get('association')) is not dict or type(row.get('receipt')) is not dict
                            or type(row.get('request_evidence')) is not dict or type(row.get('cpu_response')) is not list
                            or row['association'].get('status')!='cpu_delivery_confirmed'):
                        return None,'missing_actual_selected_read'
                    context=row['receipt'].get('delivery_context')
                    if (type(context) is not dict or not in_domains(row)
                            or context.get('write') is not False or context.get('be')!=15
                            or context.get('offset')!=rule['offset']):continue
                    if (row['receipt'].get('rdata')!=payload['rdata'] or len(row['cpu_response'])!=3
                            or row['cpu_response'][0]!=payload['rdata']):
                        return None,'actual_selected_read_link_mismatch'
                    candidates.append((command,row,payload['rdata']))
            if not candidates:return None,'missing_actual_selected_read'
            if len({(command['command_ordinal'],row['association']['access_id']) for command,row,_ in candidates})>1:
                return None,'ambiguous_selected_read'
            command,row,rdata=candidates[0]
            # The source rule -- never the compiler plan -- supplies the expected default.
            observed=(rdata&((1<<rule['width'])-1))
            if observed!=rule['reset_value']:return None,'observed_readback_is_not_source_reset_default'
            association=row['association'];receipt=row['receipt'];transaction=association['source_transaction']
            expected_cells=list(observed.to_bytes(4,'little'))
            matched=[]
            for entry in commits:
                if type(entry) is not dict or set(entry)!={'certificate','logged'}:continue
                certificate=entry['certificate'];logged=entry['logged']
                if type(certificate) is not dict or type(logged) is not dict:continue
                document=certificate.get('commit_document');fullkey=certificate.get('fullkey')
                if type(document) is not dict or type(fullkey) is not dict:continue
                journal=self.runtime.runner._event_ref_by_id(logged.get('event_id'))
                if type(journal) is not dict or _json(journal)!=_json(logged):continue
                if (fullkey.get('source_component')!=seal['cpu_component']
                        or fullkey.get('source_epoch')!=seal['cpu_source_epoch']
                        or fullkey.get('channel_id')!='data'
                        or any(fullkey.get(name)!=transaction.get(name) for name in
                               ('execution_id','testcase_id'))
                        or type(fullkey.get('source_sequence')) is not int
                        or fullkey['source_sequence']<=transaction['source_sequence']):
                    continue
                cells=document.get('enabled_byte_cells')
                if (document.get('schema_version')!='memory_write_commit_receipt.v1'
                        or document.get('memory_kind')!='modeled_host_persistent_memory'
                        or document.get('commit_status')!='complete' or document.get('performed_effect') is not True
                        or document.get('memory_id') not in seal['memory_ids']
                        or document.get('generation')!=seal['memory_generation']
                        or document.get('width_bytes')!=4 or document.get('byte_enable')!=15
                        or type(document.get('byte_offset')) is not int or document['byte_offset']%4
                        or type(cells) is not list or len(cells)!=4
                        or [cell.get('value') for cell in cells]!=expected_cells):
                    continue
                matched.append(entry)
            if not commits:return None,'missing_issued_ram_commit'
            if not matched:return None,'foreign_issued_ram_commit'
            if len(matched)>1:return None,'ambiguous_issued_ram_commit'
            issued=matched[0]['certificate'];logged=matched[0]['logged']
            document=issued['commit_document']
            permitted=[entry['command_ordinal'] for entry,kind in classified
                       if kind=='readback_independent_write']
            body=dict(schema_version=_CERTIFICATE_SCHEMA,target_instance=seal['target_instance'],
                register=rule['register'],field=rule['field'],operation='register_read',offset=rule['offset'],
                width=rule['width'],reset_value=rule['reset_value'],observed_reset_value=observed,
                alias_period=rule['alias_period'],address_decode_mask=rule['address_decode_mask'],
                rule_sha256=hashlib.sha256(_json(rule).encode()).hexdigest(),
                configuration_sha256=hashlib.sha256(self._config_pin.encode()).hexdigest(),
                native_reset_configuration_sha256=hashlib.sha256(self._evidence_pin.encode()).hexdigest(),
                profile_fingerprint=rule['profile_fingerprint'],sidecar_fingerprint=rule['sidecar_fingerprint'],
                source_path=rule['source_path'],source_sha256=rule['source_sha256'],
                source_revision=rule['source_revision'],probe_contract_source=rule['probe_contract_source'],
                probe_contract_sha256=rule['probe_contract_sha256'],
                register_map_sha256=rule['register_map_sha256'],evidence_ref=rule['evidence_ref'],
                reset_seal=deepcopy(seal),
                coverage_cursor=dict(first_command_ordinal=ordinals[0],last_command_ordinal=ordinals[-1],
                    command_count=len(ordinals),first_command_sequence=sequences[0],
                    last_command_sequence=sequences[-1],last_coverage_cursor=commands[-1]['coverage_cursor'],
                    commands_sha256=hashlib.sha256(_json(list(commands)).encode()).hexdigest()),
                read_access_ref=dict(access_id=association['access_id'],ordinal=row['ordinal'],
                    target_receipt_event_id=association['target_receipt_event_id'],
                    acceptance_event_id=association['acceptance_event_id'],
                    delivery_event_id=association['delivery_event_id'],
                    source_transaction=deepcopy(transaction),request_evidence=deepcopy(row['request_evidence']),
                    cpu_response=list(row['cpu_response']),command_ordinal=command['command_ordinal'],
                    command_sequence=command['command_sequence'],target_receipt_rdata=receipt['rdata'],
                    observed_readback=observed),
                ram_commit_ref=dict(commit_id=issued['commit_id'],
                    service_commit_sequence=issued['service_commit_sequence'],event_id=logged['event_id'],
                    fullkey=deepcopy(issued['fullkey']),memory_id=document['memory_id'],
                    generation=document['generation'],byte_offset=document['byte_offset'],width_bytes=4,
                    byte_enable=15,enabled_byte_cells=deepcopy(document['enabled_byte_cells']),
                    payload_sha256=document['payload_sha256']),
                proof_scope=_READBACK_SCOPE,grants_storage=False,grants_version_dependency=False,
                grants_prerequisites=False,grants_functional=False,
                # Explicit: the permission is a statement about the observed readback
                # only.  r_gpio_en gates the IRQ output at :138, so an allowed
                # DIR/OUT/GPIOEN write may still change whether an interrupt fires.
                readback_allowance=dict(**{'class':rule['readback_allowance_class'],
                    'scope':_ALLOWANCE_SCOPE,'irq_semantics_granted':False},
                    observed_register=rule['register'],observed_offset=rule['offset'],
                    permitted_registers=[entry['register'] for entry in rule['readback_independent_writes']],
                    permitted_offsets=list(rule['readback_independent_offsets']),
                    permitted_command_ordinals=permitted,permitted_command_count=len(permitted),
                    inten_writer_source_lines=list(rule['inten_writer_source_lines']),
                    irq_output_gate_source_line=rule['irq_output_gate_source_line']))
            body['evidence_id']=hashlib.sha256(_json(body).encode()).hexdigest()
            return json.loads(_json(body)),None

        def report(self):
            methods['_validate'][0](self)
            state=evidence_entries['snapshot'][0](self._evidence)
            blocked=self._bad or state['status']=='incomplete' or self.runtime._uncertain
            refused={}
            if blocked:
                refused={name:[(None,False,'incomplete_reset_evidence')] for name in self._rules}
            else:
                intervals=evidence_entries['completed_intervals'][0](self._evidence)
                accesses=self._ordinary_access_rows()
                commits=tuple(json.loads(encoded) for encoded in self._commits.values())
                for name in sorted(self._rules):
                    rows=[row for row in intervals if row.get('target_instance')==name]
                    if not rows:
                        refused[name]=[(None,False,'missing_native_reset_default_readback')];continue
                    reasons=[]
                    for row in rows:
                        if row.get('native_eligible') is not True:continue
                        epoch=row.get('target_epoch')
                        epoch=epoch if type(epoch) is int and epoch>=0 else None
                        barrier=row.get('reset_barrier_event_id')
                        event=(self.runtime.runner._event_ref_by_id(barrier)
                               if type(barrier) is int and barrier>=1 else None)
                        if type(event) is not dict or event.get('kind')!='reset_barrier':
                            reasons.append((epoch,False,'missing_actual_reset_barrier_binding'));continue
                        if set(row)!=set(_RESET_SEAL_KEYS)|{'native_eligible','lifecycle','commands'}|set(_GRANT_NAMES):
                            reasons.append((epoch,True,'interval_seal_domain_mismatch'));continue
                        seal={key:deepcopy(row[key]) for key in _RESET_SEAL_KEYS}
                        certificate,reason=methods['_certificate_for_interval'][0](self,seal,
                            commands=row.get('commands'),accesses=accesses,commits=commits)
                        if certificate is None:
                            reasons.append((epoch,True,
                                reason if reason in _GAP_REASONS else 'interval_seal_domain_mismatch'))
                            continue
                        digest=certificate['evidence_id']
                        if digest not in self._history and len(self._history)>=self._limit:
                            raise ValueError('reset-default-capacity')
                        self._history[digest]=certificate
                    refused[name]=reasons
            current=[] if blocked else [certificate for certificate in self._history.values()
                if self._certificate_is_current(certificate)]
            certified={certificate['target_instance'] for certificate in current}
            gaps=[];published=[]
            for name in sorted(self._rules):
                reasons=refused.get(name) or [(None,False,'missing_native_reset_default_readback')]
                published.extend(dict(target_instance=name,target_epoch=epoch,reason=reason)
                    for epoch,bound,reason in reasons)
                if name in certified:continue
                # The headline reason is the first reason from an interval that actually
                # bound a reset barrier -- never whichever interval happened to be visited
                # first.  Every interval's own reason stays published above, so a pre-reset
                # (barrier-less) interval can no longer mask the real one.
                barriered=[reason for epoch,bound,reason in reasons if bound]
                gaps.append(dict(target_instance=name,
                    reason=(barriered[0] if barriered else reasons[0][2])))
            result=dict(schema_version='register_reset_default_state.v1',configuration=json.loads(self._config_pin),
                proof_scope=(_REFUSAL_SCOPE if not current else _READBACK_SCOPE),
                current_certificates=current,historical_certificates=list(self._history.values()),gaps=gaps,
                interval_refusals=published,
                grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
            return json.loads(_json(result))

        def _certificate_is_current(self,certificate):
            seal=certificate['reset_seal'];runner=self.runtime.runner
            target=runner.sessions.get(certificate['target_instance'])
            cpu=runner.sessions.get(seal['cpu_component'])
            if type(target) is not GeneratedPulpGpioSession or type(cpu) is not GeneratedCve2Session:return False
            return (target.reset_epoch==seal['target_epoch'] and cpu.reset_epoch==seal['cpu_source_epoch']
                and cpu.memory.generation==seal['memory_generation'] and runner.command_epoch>=seal['runner_command_epoch'])

        def session_document(self):
            return validate_register_reset_default_session_document(dict(schema_version='register_reset_default_session.v1',
                configuration=methods['configuration'][0](self),state=methods['report'][0](self)),configuration=runtime_entries['configuration'][0](self.runtime))

    cls=RegisterResetDefaultVerifier
    methods=MappingProxyType({n:(m,m.__code__) for n,m in vars(cls).items()
        if callable(m) and hasattr(m,'__code__')})
    helpers={n:(globals()[n],globals()[n].__code__) for n in
        ('_json','derive_inten_reset_rule','classify_inten_command',
         'validate_register_reset_default_session_document','load_ip_test_capability',
         '_revalidate_ip_test_capability','load_component_profile','pulp_gpio_register_map','_validate_inten_rule','_current_source_files','_make_path_guard','_path_member_code',
         '_reviewed_readback_independence','_assigned_signal','_assignment_sites','_decode_offset')}
    path_type=Path;path_guard=_make_path_guard(Path)
    reader=Path.read_bytes;reader_code=reader.__code__;digest=hashlib.sha256
    resolver=MemoryAuthorityDistribution.resolve;resolver_code=resolver.__code__
    constants=(_SOURCE,_SOURCE_SHA,_REVISION,_EVIDENCE_REF,_PROBE_SOURCE,_PROBE_SHA,_CRITICAL_SOURCE_NAMES,
        _READBACK_SCOPE,_REFUSAL_SCOPE,_CERTIFICATE_SCHEMA,_GAP_REASONS,_RESET_SEAL_KEYS,_COMMAND_KEYS,
        _CERTIFICATE_KEYS,_COVERAGE_CURSOR_KEYS,_READ_ACCESS_KEYS,_RAM_COMMIT_KEYS,_GRANT_NAMES,
        _INTEN_WRITE_SITES,_INTEN_ENABLE_SITES,_INTEN_NEXT_STATE_SITES,_INTEN_IRQ_GATE_SITE,
        _INTEN_READBACK_SITES,_READBACK_INDEPENDENT_WRITES,_INDEPENDENCE_EVIDENCE_REF,_READBACK_ALLOWANCE_KEYS,_ALLOWANCE_SCOPE)
    probe_module=_probe_contract;probe_function=pulp_gpio_register_map;probe_code=probe_function.__code__
    program_module=_program_verifier_module;program_type=_RegisterProgramVerifier
    program_validate=program_type._validate;program_code=program_validate.__code__
    runtime_type=RegisterProgramRuntime
    runtime_entries={n:(getattr(runtime_type,n),getattr(runtime_type,n).__code__) for n in
        ('validate','validate_static_configuration','configuration')}
    evidence_type=NativeResetEvidence;native_module=_native_reset_module;native_table=native_module._METHODS
    evidence_entries={n:native_table[n] for n in ('validate','configuration','snapshot','completed_intervals')}
    ordinary_type=_OrdinaryApbAccessEvidence
    ordinary_entries={'completed_accesses':(_OrdinaryApbAccessEvidence.completed_accesses,
                                            _OrdinaryApbAccessEvidence.completed_accesses.__code__)}
    domain_types=(GeneratedPulpGpioSession,GeneratedCve2Session)
    domain_getters={t:t.__getattribute__ for t in domain_types}
    authority_type=MemoryCommitAuthority;distribution_type=MemoryAuthorityDistribution
    authority_entries={n:(getattr(distribution_type,n),getattr(distribution_type,n).__code__) for n in
        ('resolve','register_consumer','validate_consumer_registration')}
    dependency_getters={t:t.__getattribute__ for t in (runtime_type,evidence_type,authority_type,distribution_type)}
    def require_runtime(runtime):
        if type(runtime) is not runtime_type or any(n in vars(runtime) for n in runtime_entries):
            raise ValueError('reset-default-runtime-method-dispatch-drift')
    def require_evidence(evidence):
        if type(evidence) is not evidence_type or any(n in vars(evidence) for n in evidence_entries):
            raise ValueError('reset-default-task2-method-dispatch-drift')
    def require_authority(authority):
        if type(authority) is not authority_type or any(n in vars(authority) for n in authority_entries):
            raise ValueError('reset-default-authority-method-dispatch-drift')
    def require_ordinary(collector):
        if (type(collector) is not ordinary_type
                or any(n in vars(collector) for n in ordinary_entries)):
            raise ValueError('reset-default-ordinary-method-dispatch-drift')
    def guard():
        path_guard()
        if (globals()['RegisterResetDefaultVerifier'] is not cls or _TYPE is not cls or _METHODS is not methods
                or any(getattr(cls,n) is not f or f.__code__ is not code for n,(f,code) in methods.items())
                or any(globals()[n] is not f or f.__code__ is not code for n,(f,code) in helpers.items())
                or (_SOURCE,_SOURCE_SHA,_REVISION,_EVIDENCE_REF,_PROBE_SOURCE,_PROBE_SHA,_CRITICAL_SOURCE_NAMES,
                    _READBACK_SCOPE,_REFUSAL_SCOPE,_CERTIFICATE_SCHEMA,_GAP_REASONS,_RESET_SEAL_KEYS,_COMMAND_KEYS,
                    _CERTIFICATE_KEYS,_COVERAGE_CURSOR_KEYS,_READ_ACCESS_KEYS,_RAM_COMMIT_KEYS,_GRANT_NAMES,
        _INTEN_WRITE_SITES,_INTEN_ENABLE_SITES,_INTEN_NEXT_STATE_SITES,_INTEN_IRQ_GATE_SITE,
        _INTEN_READBACK_SITES,_READBACK_INDEPENDENT_WRITES,_INDEPENDENCE_EVIDENCE_REF,_READBACK_ALLOWANCE_KEYS,_ALLOWANCE_SCOPE)!=constants
                or _probe_contract is not probe_module or probe_module.pulp_gpio_register_map is not probe_function
                or probe_function.__code__ is not probe_code
                or _program_verifier_module is not program_module or _RegisterProgramVerifier is not program_type
                or program_module.RegisterProgramVerifier is not program_type
                or program_type._validate is not program_validate or program_validate.__code__ is not program_code
                or any(t.__getattribute__ is not function for t,function in dependency_getters.items())
                or RegisterProgramRuntime is not runtime_type
                or any(getattr(runtime_type,n) is not f or f.__code__ is not code for n,(f,code) in runtime_entries.items())
                or NativeResetEvidence is not evidence_type or _native_reset_module is not native_module
                or native_module._METHODS is not native_table
                or any(getattr(evidence_type,n) is not f or f.__code__ is not code for n,(f,code) in evidence_entries.items())
                or MemoryCommitAuthority is not authority_type or MemoryAuthorityDistribution is not distribution_type
                or any(getattr(distribution_type,n) is not f or getattr(authority_type,n) is not f or f.__code__ is not code
                       for n,(f,code) in authority_entries.items())
                or _OrdinaryApbAccessEvidence is not ordinary_type
                or any(getattr(ordinary_type,n) is not f or f.__code__ is not code for n,(f,code) in ordinary_entries.items())
                or any(t is not u for t,u in zip((GeneratedPulpGpioSession,GeneratedCve2Session),domain_types))
                or any(t.__getattribute__ is not function for t,function in domain_getters.items())
                or MemoryAuthorityDistribution.resolve is not resolver or resolver.__code__ is not resolver_code
                or Path is not path_type or Path.read_bytes is not reader or reader.__code__ is not reader_code or hashlib.sha256 is not digest):
            raise ValueError('reset-default-import-time-method-drift')
    sealed.add(cls)
    return cls,methods



def validate_register_reset_default_session_document(document,*,configuration):
    """Validate closed comparison data; a saved document installs no authority.

    Both the empty refusal shape and a strictly valid non-empty certificate list
    are accepted. Validation compares against the current source rule and the
    current configuration bytes; it never touches a live verifier, token,
    private fact or eligibility decision, and it returns detached data only.
    """
    value=json.loads(_json(document))
    def fail(reason):raise ValueError('invalid-register-reset-default-session-document:'+reason)
    def keys(row,names):
        if type(row) is not dict or any(type(k) is not str for k in row) or set(row)!=set(names):fail('closed-fields')
    def text(value,limit=256):
        if type(value) is not str or not 0<len(value)<=limit or value.strip()!=value:fail('text')
    def uint(value,maximum=(1<<64)-1,minimum=0):
        if type(value) is not int or not minimum<=value<=maximum:fail('unsigned-integer')
    def digest(value):
        if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):fail('sha256')
    def fingerprint(value):
        if type(value) is not str or not value.startswith('sha256:'):fail('fingerprint')
        digest(value[7:])
    def false(row,names):
        if any(row[k] is not False for k in names):fail('saved-grants')
    def same(left,right):
        if _json(left)!=_json(right):fail('comparison-mismatch')
    def items(value,maximum,minimum=0):
        if type(value) is not list or not minimum<=len(value)<=maximum:fail('bounded-list')
    def transaction(row):
        keys(row,('execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence'))
        for name in ('execution_id','testcase_id','source_component','channel_id'):text(row[name])
        for name in ('source_epoch','source_sequence'):uint(row[name])
        if row['channel_id']!='data':fail('data-transaction-required')
    keys(value,('schema_version','configuration','state'))
    if value['schema_version']!='register_reset_default_session.v1':fail('session-version')
    cfg=value['configuration'];state=value['state']
    keys(cfg,{'schema_version','max_records','runtime_configuration_sha256',
        'native_reset_configuration_sha256','rules','source_files','proof_scope'}|set(_GRANT_NAMES))
    if cfg['schema_version']!='register_reset_default_configuration.v1':fail('configuration-version')
    if cfg['proof_scope']!=_READBACK_SCOPE:fail('configuration-scope')
    false(cfg,_GRANT_NAMES)
    uint(cfg['max_records'],65536,1);limit=cfg['max_records']
    for name in ('runtime_configuration_sha256','native_reset_configuration_sha256'):digest(cfg[name])
    if cfg['runtime_configuration_sha256']!=hashlib.sha256(_json(configuration).encode()).hexdigest():
        fail('runtime-configuration')
    keys(state,{'schema_version','configuration','proof_scope','current_certificates',
        'historical_certificates','gaps','interval_refusals'}|set(_GRANT_NAMES))
    if state['schema_version']!='register_reset_default_state.v1':fail('state-version')
    false(state,_GRANT_NAMES);same(state['configuration'],cfg)
    items(state['gaps'],limit+256)
    for gap in state['gaps']:
        keys(gap,('target_instance','reason'));text(gap['target_instance'])
        if gap['reason'] not in _GAP_REASONS:fail('gap-reason')
    # Per-interval refusal projection: every considered interval's own reason, with the
    # accepted target_epoch (unsigned integer, or null when no interval was considered).
    published={}
    items(state['interval_refusals'],limit+256)
    seen=set()
    for row in state['interval_refusals']:
        keys(row,('target_instance','target_epoch','reason'));text(row['target_instance'])
        if row['target_epoch'] is not None:uint(row['target_epoch'])
        if row['reason'] not in _GAP_REASONS:fail('interval-refusal-reason')
        if row['target_instance'] not in cfg['rules']:fail('interval-refusal-target')
        if _json(row) in seen:fail('duplicate-interval-refusal')
        seen.add(_json(row))
        published.setdefault(row['target_instance'],[]).append(row['reason'])
    for gap in state['gaps']:
        if gap['reason'] not in published.get(gap['target_instance'],[]):
            fail('gap-reason-not-published')
    if type(cfg['rules']) is not dict or type(cfg['source_files']) is not dict:
        fail('closed-current-source-rules')
    expected={}
    for alias,sidecar in configuration['sidecars'].items():
        profile_path=Path(configuration['artifacts'][alias]['profile_path'])
        profile=load_component_profile(profile_path)
        path=Path(sidecar['path'])
        if hashlib.sha256(path.read_bytes()).hexdigest()!=sidecar['sha256']:
            raise ValueError('reset-default-current-sidecar-drift')
        expected[alias]=derive_inten_reset_rule(profile,load_ip_test_capability(path,profile=profile),
            base_dir=Path(__file__).resolve().parents[3],target_instance=alias)
    if (_json(cfg['rules'])!=_json(expected) or _json(cfg['source_files'])!=_json(_current_source_files())):
        raise ValueError('reset-default-current-source-comparison-mismatch')
    configuration_sha256=hashlib.sha256(_json(cfg).encode()).hexdigest()
    def certificate(cert):
        keys(cert,_CERTIFICATE_KEYS)
        if cert['schema_version']!=_CERTIFICATE_SCHEMA:fail('certificate-schema')
        if cert['proof_scope']!=_READBACK_SCOPE:fail('certificate-scope')
        false(cert,_GRANT_NAMES)
        digest(cert['evidence_id'])
        same(cert['evidence_id'],hashlib.sha256(_json(
            {k:v for k,v in cert.items() if k!='evidence_id'}).encode()).hexdigest())
        text(cert['target_instance'])
        rule=expected.get(cert['target_instance'])
        if rule is None:fail('certificate-target')
        for name in ('profile_fingerprint','sidecar_fingerprint'):fingerprint(cert[name])
        for name in ('register','field','offset','width','reset_value','alias_period',
                     'address_decode_mask','profile_fingerprint','sidecar_fingerprint','source_path',
                     'source_sha256','source_revision','probe_contract_source','probe_contract_sha256',
                     'register_map_sha256','evidence_ref'):
            same(cert[name],rule[name])
        if cert['operation']!='register_read':fail('certificate-operation')
        uint(cert['observed_reset_value'],(1<<32)-1)
        same(cert['observed_reset_value'],cert['reset_value'])
        same(cert['rule_sha256'],hashlib.sha256(_json(rule).encode()).hexdigest())
        same(cert['configuration_sha256'],configuration_sha256)
        digest(cert['native_reset_configuration_sha256'])
        allowance=cert['readback_allowance'];keys(allowance,_READBACK_ALLOWANCE_KEYS)
        same(allowance['class'],rule['readback_allowance_class'])
        same(allowance['observed_register'],rule['register'])
        same(allowance['observed_offset'],rule['offset'])
        same(allowance['permitted_registers'],[row['register'] for row in rule['readback_independent_writes']])
        same(allowance['permitted_offsets'],rule['readback_independent_offsets'])
        same(allowance['inten_writer_source_lines'],rule['inten_writer_source_lines'])
        same(allowance['irq_output_gate_source_line'],rule['irq_output_gate_source_line'])
        if allowance['scope']!=_ALLOWANCE_SCOPE:fail('readback-allowance-scope')
        if allowance['irq_semantics_granted'] is not False:fail('readback-allowance-irq')
        items(allowance['permitted_command_ordinals'],limit)
        uint(allowance['permitted_command_count'],limit)
        same(allowance['permitted_command_count'],len(allowance['permitted_command_ordinals']))
        if len(set(allowance['permitted_command_ordinals']))!=len(allowance['permitted_command_ordinals']):
            fail('readback-allowance-ordinals')
        for number in allowance['permitted_command_ordinals']:uint(number,(1<<31)-1,1)
        seal=cert['reset_seal'];keys(seal,_RESET_SEAL_KEYS)
        if seal['schema_version']!='native_reset_interval.v1':fail('seal-version')
        same(seal['target_instance'],cert['target_instance'])
        for name in ('target_epoch','cpu_source_epoch','cpu_logical_process','runner_command_epoch',
                     'memory_generation'):uint(seal[name])
        uint(seal['logical_process'],(1<<31)-1,1)
        uint(seal['reset_barrier_event_id'],(1<<63)-1,1)
        text(seal['cpu_component'])
        items(seal['memory_ids'],256,1)
        for memory_id in seal['memory_ids']:text(memory_id)
        if len(set(seal['memory_ids']))!=len(seal['memory_ids']):fail('seal-memory-ids')
        cursor=cert['coverage_cursor'];keys(cursor,_COVERAGE_CURSOR_KEYS)
        for name in _COVERAGE_CURSOR_KEYS-{'commands_sha256'}:uint(cursor[name])
        digest(cursor['commands_sha256'])
        if (cursor['command_count']<1 or cursor['last_command_ordinal']<cursor['first_command_ordinal']
                or cursor['last_command_ordinal']-cursor['first_command_ordinal']+1!=cursor['command_count']
                or cursor['first_command_sequence']<1
                or cursor['last_command_sequence']<cursor['first_command_sequence']
                or cursor['last_command_sequence']-cursor['first_command_sequence']+1<cursor['command_count']
                or cursor['last_coverage_cursor']!=cursor['last_command_ordinal']):fail('coverage-cursor')
        if any(not cursor['first_command_ordinal']<=number<=cursor['last_command_ordinal']
               for number in allowance['permitted_command_ordinals']):
            fail('readback-allowance-ordinals')
        read=cert['read_access_ref'];keys(read,_READ_ACCESS_KEYS)
        text(read['access_id']);transaction(read['source_transaction'])
        uint(read['ordinal'],65536,1);uint(read['command_ordinal'],(1<<31)-1,1)
        uint(read['command_sequence'],(1<<31)-1,1)
        for name in ('target_receipt_event_id','acceptance_event_id','delivery_event_id'):
            uint(read[name],(1<<63)-1,1)
        if (read['acceptance_event_id']>=read['delivery_event_id']
                or len({read['target_receipt_event_id'],read['acceptance_event_id'],
                        read['delivery_event_id']})!=3):
            fail('read-event-order')
        if not (cursor['first_command_ordinal']<=read['command_ordinal']<=cursor['last_command_ordinal']
                and cursor['first_command_sequence']<=read['command_sequence']<=cursor['last_command_sequence']):
            fail('read-command-outside-cursor')
        evidence=read['request_evidence']
        keys(evidence,('transaction','raw_address','aligned_address','address','write','be','wdata','acceptance_tick'))
        same(evidence['transaction'],read['source_transaction'])
        for name in ('raw_address','aligned_address','address','wdata','acceptance_tick'):
            uint(evidence[name],(1<<64)-1)
        same(evidence['write'],0);same(evidence['be'],15)
        same(evidence['aligned_address'],evidence['address'])
        if evidence['raw_address']&~3!=evidence['aligned_address']:fail('request-evidence-address')
        items(read['cpu_response'],3,3)
        for number in read['cpu_response']:uint(number)
        same(read['cpu_response'][0],cert['observed_reset_value'])
        same(read['cpu_response'][2],read['source_transaction']['source_sequence'])
        uint(read['target_receipt_rdata'],(1<<32)-1)
        same(read['target_receipt_rdata'],cert['observed_reset_value'])
        commit=cert['ram_commit_ref'];keys(commit,_RAM_COMMIT_KEYS)
        digest(commit['commit_id']);uint(commit['service_commit_sequence'],(1<<64)-1,1)
        uint(commit['event_id'],(1<<63)-1,1)
        if commit['event_id']<=read['delivery_event_id']:fail('ram-commit-order')
        transaction(commit['fullkey'])
        for name in ('execution_id','testcase_id','source_component','source_epoch','channel_id'):
            same(commit['fullkey'][name],read['source_transaction'][name])
        if commit['fullkey']['source_sequence']<=read['source_transaction']['source_sequence']:
            fail('ram-commit-sequence')
        text(commit['memory_id']);digest(commit['payload_sha256'])
        if commit['memory_id'] not in seal['memory_ids']:fail('ram-commit-memory')
        same(commit['generation'],seal['memory_generation'])
        uint(commit['byte_offset'],(1<<32)-1)
        if commit['byte_offset']%4:fail('ram-commit-span')
        same(commit['width_bytes'],4);same(commit['byte_enable'],15)
        items(commit['enabled_byte_cells'],4,4)
        for cell in commit['enabled_byte_cells']:
            keys(cell,('byte_offset','value','version','writer_kind','writer_event_id'))
            uint(cell['byte_offset'],(1<<32)-1);uint(cell['value'],255)
            items(cell['version'],2,2)
            for number in cell['version']:uint(number)
            text(cell['writer_kind']);text(cell['writer_event_id'],512)
        if [cell['byte_offset'] for cell in commit['enabled_byte_cells']]!=[
                commit['byte_offset']+lane for lane in range(4)]:fail('ram-commit-span')
        if [cell['value'] for cell in commit['enabled_byte_cells']]!=[
                value for value in cert['observed_reset_value'].to_bytes(4,'little')]:fail('ram-commit-data')
    history=state['historical_certificates'];current=state['current_certificates']
    items(history,limit);items(current,limit)
    for cert in history:certificate(cert)
    by_id={}
    for cert in history:
        if cert['evidence_id'] in by_id:fail('duplicate-certificate')
        by_id[cert['evidence_id']]=cert
    current_ids=set()
    for cert in current:
        certificate(cert)
        if type(cert.get('evidence_id')) is not str or cert['evidence_id'] not in by_id:fail('current-certificate')
        same(cert,by_id[cert['evidence_id']])
        if cert['evidence_id'] in current_ids:fail('duplicate-current')
        same(cert['configuration_sha256'],configuration_sha256)
        current_ids.add(cert['evidence_id'])
    certified={cert['target_instance'] for cert in current}
    gapped=[gap['target_instance'] for gap in state['gaps']]
    if len(gapped)!=len(set(gapped)) or certified&set(gapped) or certified|set(gapped)!=set(expected):
        fail('target-partition')
    if current and state['proof_scope']!=_READBACK_SCOPE:fail('state-scope')
    if not current and state['proof_scope']!=_REFUSAL_SCOPE:fail('state-scope')
    return value


def _bind_rule_entries():
    names=('derive_inten_reset_rule','classify_inten_command','validate_register_reset_default_session_document')
    originals={n:(globals()[n],globals()[n].__code__) for n in names}
    imports={n:(globals()[n],globals()[n].__code__) for n in
        ('_json','load_ip_test_capability','_revalidate_ip_test_capability','load_component_profile','pulp_gpio_register_map','_validate_inten_rule','_current_source_files','_make_path_guard','_path_member_code',
         '_reviewed_readback_independence','_assigned_signal','_assignment_sites','_decode_offset')}
    constants=(_SOURCE,_SOURCE_SHA,_REVISION,_EVIDENCE_REF,_PROBE_SOURCE,_PROBE_SHA,_CRITICAL_SOURCE_NAMES,
        _READBACK_SCOPE,_REFUSAL_SCOPE,_CERTIFICATE_SCHEMA,_GAP_REASONS,_RESET_SEAL_KEYS,_COMMAND_KEYS,
        _CERTIFICATE_KEYS,_COVERAGE_CURSOR_KEYS,_READ_ACCESS_KEYS,_RAM_COMMIT_KEYS,_GRANT_NAMES,
        _INTEN_WRITE_SITES,_INTEN_ENABLE_SITES,_INTEN_NEXT_STATE_SITES,_INTEN_IRQ_GATE_SITE,
        _INTEN_READBACK_SITES,_READBACK_INDEPENDENT_WRITES,_INDEPENDENCE_EVIDENCE_REF,_READBACK_ALLOWANCE_KEYS,_ALLOWANCE_SCOPE)
    probe_module=_probe_contract;probe_function=pulp_gpio_register_map;probe_code=probe_function.__code__
    path_type=Path;path_guard=_make_path_guard(Path)
    reader=Path.read_bytes;reader_code=reader.__code__;digest=hashlib.sha256
    entries={}
    def guard():
        path_guard()
        if ((_SOURCE,_SOURCE_SHA,_REVISION,_EVIDENCE_REF,_PROBE_SOURCE,_PROBE_SHA,_CRITICAL_SOURCE_NAMES,
                _READBACK_SCOPE,_REFUSAL_SCOPE,_CERTIFICATE_SCHEMA,_GAP_REASONS,_RESET_SEAL_KEYS,_COMMAND_KEYS,
                _CERTIFICATE_KEYS,_COVERAGE_CURSOR_KEYS,_READ_ACCESS_KEYS,_RAM_COMMIT_KEYS,_GRANT_NAMES,
        _INTEN_WRITE_SITES,_INTEN_ENABLE_SITES,_INTEN_NEXT_STATE_SITES,_INTEN_IRQ_GATE_SITE,
        _INTEN_READBACK_SITES,_READBACK_INDEPENDENT_WRITES,_INDEPENDENCE_EVIDENCE_REF,_READBACK_ALLOWANCE_KEYS,_ALLOWANCE_SCOPE)!=constants
                or _probe_contract is not probe_module or probe_module.pulp_gpio_register_map is not probe_function
                or probe_function.__code__ is not probe_code
                or any(globals()[n] is not entry or entry.__code__ is not code for n,(entry,code) in entries.items())
                or any(f.__code__ is not code for f,code in originals.values())
                or any(globals()[n] is not f or f.__code__ is not code for n,(f,code) in imports.items())
                or Path is not path_type or Path.read_bytes is not reader or reader.__code__ is not reader_code or hashlib.sha256 is not digest):
            raise ValueError('reset-rule-import-time-drift')
    def bind(original):
        def entry(*args,**kwargs):
            guard()
            return original(*args,**kwargs)
        return entry
    for name,(original,_) in originals.items():
        function=bind(original);entries[name]=(function,function.__code__)
    return tuple(entries[name][0] for name in names)

(derive_inten_reset_rule,classify_inten_command,
 validate_register_reset_default_session_document)=_bind_rule_entries()
RegisterResetDefaultVerifier,_METHODS=_create_verifier_type()
_TYPE=RegisterResetDefaultVerifier
