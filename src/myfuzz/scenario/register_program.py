"""Restricted declarative RV32I register programs, never execution evidence."""
from dataclasses import asdict, dataclass
import hashlib
import json

from myfuzz.composition.test_capability import plan_register_operation
from .memory import MemoryRegion
from .rv32i_sources import (MmioWindow, Rv32iInstruction, fragment_bytes, mmio_access_fragment,
                            mmio_write_fragment, validate_instruction_bytes)
from .session_runtime import OnlineInstruction


_WRITE_EFFECTS = frozenset(('none', 'write_drives_output_enable', 'write_drives_pads',
                            'write_one_sets', 'write_one_clears'))
_READ_EFFECTS = frozenset(('none', 'write_drives_output_enable', 'write_drives_pads'))


def _uint(value):
    return type(value) is int and 0 <= value < 1 << 32


def _overlap(a, size, b, other_size):
    return a < b + other_size and b < a + size


def _regions(regions, mmio_base, aperture):
    if type(regions) is not tuple or not regions:
        raise ValueError('register-program-explicit-ram-regions-required')
    for region in regions:
        if type(region) is not MemoryRegion:
            raise ValueError('register-program-explicit-ram-regions-required')
        # Revalidate frozen objects at the compilation boundary.
        MemoryRegion(**asdict(region))
        if (not _uint(region.base) or type(region.size) is not int
                or region.base + region.size > 1 << 32 or region.aliases
                or _overlap(region.base, region.size, mmio_base, aperture)):
            raise ValueError('register-program-ram-region-invalid-or-overlaps-mmio')
    for index, region in enumerate(regions):
        if any(_overlap(region.base, region.size, other.base, other.size)
               for other in regions[index + 1:]):
            raise ValueError('register-program-ambiguous-ram-regions')


@dataclass(frozen=True)
class RegisterProgram:
    instructions: tuple
    fragment: bytes
    source: OnlineInstruction
    _identity_json: str

    def document(self):
        return json.loads(self._identity_json)


def compile_register_program(profile, capability, *, register, field, operation,
        address_base, windows, cpu_component, action_id, program_address,
        program_size, program_regions, value=None, allow_side_effect=False,
        result_address=None, result_regions=(), base_register=1, data_register=2,
        read_modify_write=False, mask_register=3):
    """Compile accesses for existing CPU instruction admission.

    Region arguments are caller declarations, not live memory authority. An
    actual Session must still admit the resulting source into reserved slots.
    """
    plan = plan_register_operation(profile, capability, register=register, field=field,
        operation=operation, value=value, allow_side_effect=allow_side_effect)
    if type(read_modify_write) is not bool:
        raise ValueError('register-program-rmw-flag-must-be-boolean')
    if type(mask_register) is not int or not 1 <= mask_register <= 31:
        raise ValueError('register-program-rmw-invalid-mask-register')
    if read_modify_write:
        fields = [row for row in capability.register_semantics if row.register == register]
        readable_writable_mask = 0
        for row in fields:
            mask = (1 << row.width) - 1
            if (row.access != 'rw' or row.side_effect != 'none'
                    or row.read_mask != mask or row.write_mask != mask):
                raise ValueError('register-program-rmw-requires-complete-plain-rw-register')
            readable_writable_mask |= mask << row.lsb
        if (operation != 'register_write' or plan.side_effect != 'none'
                or profile.capabilities.get('read') is not True
                or readable_writable_mask != 0xffffffff):
            raise ValueError('register-program-rmw-requires-complete-plain-rw-register')
        if mask_register in (base_register, data_register):
            raise ValueError('register-program-rmw-mask-register-conflict')
    reg = next(row for row in profile.address.registers if row.name == register)
    if (type(profile.capabilities.get('data_width')) is not int
            or profile.capabilities['data_width'] != 32
            or type(reg.width) is not int or reg.width != 32):
        raise ValueError('register-program-requires-32-bit-bus-and-register')
    permission = 'read' if operation == 'register_read' else 'write'
    if profile.capabilities.get(permission) is not True:
        raise ValueError('register-program-profile-bus-permission-denied')
    read_field = None
    if operation == 'register_read' and plan.bus_mask != 0xffffffff:
        readable_mask = 0
        for row in capability.register_semantics:
            if row.register != register:
                continue
            mask = (1 << row.width) - 1
            bus_mask = mask << row.lsb
            if (row.access not in ('ro', 'rw') or row.side_effect != 'none'
                    or row.read_mask != mask or readable_mask & bus_mask):
                raise ValueError('register-program-field-read-requires-full-word-complete-plain-readable-register')
            readable_mask |= bus_mask
            if row.field == field:
                read_field = row
        if readable_mask != 0xffffffff or read_field is None:
            raise ValueError('register-program-field-read-requires-full-word-complete-plain-readable-register')
        if mask_register in (base_register, data_register):
            raise ValueError('register-program-field-read-mask-register-conflict')
    if (operation == 'register_write' and not read_modify_write and plan.side_effect not in (
                'write_one_sets', 'write_one_clears') and plan.bus_mask != 0xffffffff):
        raise ValueError('register-program-full-word-field-required')
    # The field contract uses one effect label for both operations. These
    # closed output-write labels do not authorize a read-side effect; the
    # original planner still requires its explicit caller authorization.
    if (operation == 'register_read' and plan.side_effect not in _READ_EFFECTS
            or operation == 'register_write' and plan.side_effect not in _WRITE_EFFECTS):
        raise ValueError('register-program-unsupported-side-effect')
    aperture = profile.address.window_size
    if (not _uint(address_base) or address_base % profile.address.alignment
            or address_base + aperture > 1 << 32):
        raise ValueError('register-program-invalid-mmio-base')
    if type(windows) is not tuple or not windows:
        raise ValueError('register-program-explicit-mmio-windows-required')
    for window in windows:
        if type(window) is not MmioWindow:
            raise ValueError('register-program-explicit-mmio-windows-required')
        MmioWindow(**asdict(window))
        if window.base < address_base or window.base + window.size > address_base + aperture:
            raise ValueError('register-program-window-exceeds-profile-aperture')
    if (not _uint(program_address) or program_address % 4
            or type(program_size) is not int or program_size < 4 or program_size % 4
            or program_address + program_size > 1 << 32):
        raise ValueError('register-program-invalid-program-slot')
    _regions(program_regions, address_base, aperture)
    if sum(region.readable and region.writable and region.base <= program_address
            and program_address + program_size <= region.base + region.size
            for region in program_regions) != 1:
        raise ValueError('register-program-slot-outside-authorized-ram')
    address = address_base + plan.offset
    if not address_base <= address or address + 4 > address_base + aperture:
        raise ValueError('register-program-register-outside-aperture')
    result = None
    if operation == 'register_write':
        if result_address is not None or result_regions != ():
            raise ValueError('register-program-write-result-storage-not-allowed')
        if read_modify_write:
            # The original word comes from the CPU's actual LW. The generated
            # mask/value operations do not use a host reset or readback oracle.
            read = mmio_access_fragment('LW', address, windows=windows,
                base_register=base_register, data_register=data_register)
            clear = mmio_write_fragment('SW', address, (~plan.bus_mask) & 0xffffffff,
                windows=windows, base_register=base_register, data_register=mask_register)[:2]
            set_value = mmio_write_fragment('SW', address, plan.bus_value,
                windows=windows, base_register=base_register, data_register=mask_register)[:2]
            store = mmio_access_fragment('SW', address, windows=windows,
                base_register=base_register, data_register=data_register)[1:]
            instructions = (*read, *clear,
                Rv32iInstruction('AND', rd=data_register, rs1=data_register, rs2=mask_register),
                *set_value,
                Rv32iInstruction('OR', rd=data_register, rs1=data_register, rs2=mask_register),
                *store)
        else:
            instructions = mmio_write_fragment('SW', address, plan.bus_value,
                windows=windows, base_register=base_register, data_register=data_register)
    else:
        if not _uint(result_address) or result_address % 4:
            raise ValueError('register-program-explicit-aligned-read-result-required')
        _regions(result_regions, address_base, aperture)
        if (sum(region.writable and region.base <= result_address
                and result_address + 4 <= region.base + region.size
                for region in result_regions) != 1
                or _overlap(result_address, 4, program_address, program_size)):
            raise ValueError('register-program-read-result-outside-ram-or-overlaps-slot')
        extraction = ()
        if read_field is not None:
            mask = read_field.read_mask
            if read_field.lsb:
                extraction = (Rv32iInstruction('SRLI', rd=data_register,
                    rs1=data_register, immediate=read_field.lsb),)
            if mask <= 0x7ff:
                extraction += (Rv32iInstruction('ANDI', rd=data_register,
                    rs1=data_register, immediate=mask),)
            else:
                extraction += (*mmio_write_fragment('SW', address, mask,
                    windows=windows, base_register=base_register,
                    data_register=mask_register)[:2],
                    Rv32iInstruction('AND', rd=data_register,
                        rs1=data_register, rs2=mask_register))
        instructions = (*mmio_access_fragment('LW', address, windows=windows,
                base_register=base_register, data_register=data_register), *extraction,
            *mmio_access_fragment('SW', result_address,
                windows=(MmioWindow(result_address, 4, readable=False, write_widths=(4,)),),
                base_register=base_register, data_register=data_register))
        result = dict(address=result_address, width_bytes=4,
            purpose='caller_declared_result_storage',
            evidence_scope='requires_actual_cpu_store_and_read_snapshot')
        if read_field is not None:
            result['field_extraction'] = dict(lsb=read_field.lsb,
                width=read_field.width, read_mask=read_field.read_mask,
                bus_width=32, representation='field_relative_zero_extended')
    fragment = fragment_bytes(instructions)
    validate_instruction_bytes(fragment)
    if len(fragment) > program_size:
        raise ValueError('register-program-fragment-exceeds-authorized-slot')
    if any(type(text) is not str or not text or text.strip() != text
           for text in (cpu_component, action_id)):
        raise ValueError('register-program-source-identity-invalid')
    source = OnlineInstruction(action_id, cpu_component, program_address, fragment.hex())
    body = dict(schema_version='declarative_register_program.v1',
        profile_fingerprint=profile.profile_fingerprint,
        sidecar_fingerprint=capability.sidecar_fingerprint, operation_plan=asdict(plan),
        scope='declarative_cpu_register_program_only', grants_prerequisites=False,
        source=asdict(source), fragment_sha256=hashlib.sha256(fragment).hexdigest(),
        result_storage=result, access_context=dict(address_base=address_base,
            windows=[asdict(w) for w in windows], program_size=program_size,
            program_regions=[asdict(r) for r in program_regions],
            result_regions=[asdict(r) for r in result_regions],
            allow_side_effect=allow_side_effect, base_register=base_register,
            data_register=data_register, read_modify_write=read_modify_write,
            mask_register=mask_register))
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False)
    body['identity_sha256'] = hashlib.sha256(canonical.encode()).hexdigest()
    return RegisterProgram(tuple(instructions), fragment, source,
        json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False))


def verify_register_program_document(profile, capability, saved_document,
                                     **current_compile_arguments):
    """Recompile using current declarations and compare the complete saved data.

    Saved bytes, plans, regions, and hashes are never compilation inputs. The
    caller must obtain current arguments from its actual runtime context;
    this comparison itself grants neither live authority nor a capability
    grade. Return the freshly compiled program, never a saved source object.
    """
    if type(saved_document) is not dict:
        raise ValueError('register-program-saved-program-invalid')

    def plain_json(value):
        if value is None or type(value) in (str, bool, int):
            return True
        if type(value) is list:
            return all(plain_json(item) for item in value)
        if type(value) is dict:
            return all(type(key) is str and plain_json(item)
                       for key, item in value.items())
        return False

    try:
        if not plain_json(saved_document):
            raise ValueError('register-program-saved-program-invalid')
        saved_json = json.dumps(saved_document, sort_keys=True,
                                separators=(',', ':'), allow_nan=False)
    except (TypeError, RecursionError) as exc:
        raise ValueError('register-program-saved-program-invalid') from exc
    actual = compile_register_program(profile, capability,
                                      **current_compile_arguments)
    # JSON distinguishes bool/int, unlike Python dictionary equality.
    if saved_json != actual._identity_json:
        raise ValueError('register-program-saved-program-mismatch')
    return actual
