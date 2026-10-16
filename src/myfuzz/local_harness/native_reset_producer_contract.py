"""Closed actual-class mechanics registry; no storage/version authority.

Class tables are sealed when each code-owned session module is imported, not
when an observer is requested. There is deliberately no registration API.
"""
from .native_physical_observation import verify_apb_register_trace
_VERIFY = (verify_apb_register_trace, verify_apb_register_trace.__code__)
from types import MappingProxyType
from importlib import import_module
_DEPENDENCIES = MappingProxyType({name: (module, MappingProxyType({
    key: (value, value.__code__) for key,value in vars(module).items()
    if hasattr(value, '__code__')})) for name in (
    'myfuzz.local_harness.native_physical_observation',
    'myfuzz.local_harness.runtime_renderer', 'myfuzz.local_harness.renderer',
    'myfuzz.local_harness.apb3_register_template',
    'myfuzz.local_harness.apb_storage_source_contract',
    'myfuzz.local_harness.apb_storage_probe_contract',
    'myfuzz.scenario.apb_storage_register_version')
    for module in (import_module(name),)})
_DEPENDENCIES_PIN = _DEPENDENCIES
from pathlib import Path
import hashlib
_STORAGE_ISSUER_SOURCE = (_DEPENDENCIES['myfuzz.scenario.apb_storage_register_version'][0],
    hashlib.sha256(Path(_DEPENDENCIES['myfuzz.scenario.apb_storage_register_version'][0].__file__).read_bytes()).hexdigest())


def _make_closed_registry():
    # Origins live in a lexical closure, independently of mutable module aliases.
    # Only execution of the two complete code-owned module bodies may seal once.
    origins = {}
    allowed = {'myfuzz.local_harness.gpio_session': ('GPIO', 'GeneratedPulpGpioSession'),
               'myfuzz.local_harness.apb3_register_session': ('APB', 'GeneratedApb3RegisterSession')}

    def seal(cls):
        import sys
        from pathlib import Path
        frame = sys._getframe(1)
        name = frame.f_globals.get('__name__')
        module = sys.modules.get(name)
        if (name not in allowed or name in origins or module is None
                or vars(module) is not frame.f_globals or frame.f_code.co_name != '<module>'
                or frame.f_code != compile(Path(module.__file__).read_bytes(),
                    frame.f_code.co_filename, 'exec', dont_inherit=True)
                or cls is not getattr(module, allowed[name][1])):
            raise ValueError('native reset producer seal requires original module execution')
        prefix = '_NATIVE_RESET_' + allowed[name][0]
        declarations = getattr(module, prefix+'_DECLARATIONS')
        resolved = getattr(module, prefix+'_RESOLVED')
        if set(vars(cls)) != set(declarations) or any(vars(cls)[key] is not value for key,value in declarations.items()):
            raise ValueError('native reset invalid original declaration seal')
        origins[name] = (module, cls, prefix, declarations, resolved)

    def check_origin(owner):
        # Importing may complete an unexecuted code-owned module; observer calls
        # never choose the baseline and cannot replace an already sealed origin.
        from . import gpio_session, apb3_register_session
        for name,(module,cls,prefix,declarations,resolved) in origins.items():
            if type(owner) is not cls:
                continue
            if (import_module(name) is not module
                    or getattr(module, allowed[name][1]) is not cls
                    or getattr(module, prefix+'_CLASS') is not cls
                    or getattr(module, prefix+'_DECLARATIONS') is not declarations
                    or getattr(module, prefix+'_DECLARATIONS_PIN') is not declarations
                    or getattr(module, prefix+'_RESOLVED') is not resolved
                    or getattr(module, prefix+'_RESOLVED_PIN') is not resolved
                    or set(vars(cls)) != set(declarations)
                    or any(key in vars(owner) for key in declarations)
                    or any(vars(cls)[key] is not value for key,value in declarations.items())):
                raise ValueError('native reset sealed producer declaration drift')
            for key,(method,code) in resolved.items():
                if getattr(cls,key) is not method or method.__code__ is not code or key in vars(owner):
                    raise ValueError('native reset resolved producer method drift:'+key)
            return 'gpio' if allowed[name][0] == 'GPIO' else 'apb_storage'
        raise ValueError('native reset requires registered exact producer class')
    return seal, check_origin

_seal_code_owned_producer, _check_origin = _make_closed_registry()
_CHECK_ORIGIN = (_check_origin, _check_origin.__code__)


def check_producer(owner):
    if _check_origin is not _CHECK_ORIGIN[0] or _check_origin.__code__ is not _CHECK_ORIGIN[1]:
        raise ValueError('native reset sealed origin checker drift')
    selected = _CHECK_ORIGIN[0](owner)
    if selected == 'apb_storage':
        if _DEPENDENCIES is not _DEPENDENCIES_PIN:
            raise ValueError('native reset storage dependency registry drift')
        if hashlib.sha256(Path(_STORAGE_ISSUER_SOURCE[0].__file__).read_bytes()).hexdigest()!=_STORAGE_ISSUER_SOURCE[1]:
            raise ValueError('native reset storage issuer source drift')
        for name,(module,functions) in _DEPENDENCIES.items():
            if import_module(name) is not module or any(
                    getattr(module,key) is not function or function.__code__ is not code
                    for key,(function,code) in functions.items()):
                raise ValueError('native reset storage canonical dependency drift:'+name)
        if (type(owner.setup_writes) is not tuple or owner.setup_writes
                or type(owner.probe_offsets) is not tuple or owner.probe_offsets
                or any(type(value) is not dict or value for value in (
                    owner._dynamic, owner._bound, owner._dynamic_values, owner._bound_values))
                or owner._artifact_document.get('dynamic_physical_inputs')
                or owner._artifact_document.get('bound_physical_inputs')
                or 'storage_observation' not in owner._artifact_document):
            raise ValueError('native reset storage producer requires empty setup and registered inputs')
        if verify_apb_register_trace is not _VERIFY[0] or verify_apb_register_trace.__code__ is not _VERIFY[1]:
            raise ValueError('native reset storage verifier drift')
        # Canonical reconstruction rereads exact registered source bytes and
        # reprojects every storage port/metadata/runtime expression. No frontend.
        if _VERIFY[0](owner.artifact) is not True:
            raise ValueError('native reset storage probe canonical projection required')
    return selected
