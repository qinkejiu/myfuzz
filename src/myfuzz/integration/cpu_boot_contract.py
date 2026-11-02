"""Source-pinned boot predictions, never native fetch observations.

An optional profile declaration associates a boot formula with locked source
bytes. The formula is a component author's description, not a proof obtained
by interpreting RTL; actual fetch observations remain the execution evidence.
"""
from hashlib import sha256
from pathlib import Path

# Each formula is tied to the complete reviewed IF-stage source, not a CPU name.
_BOOT_STRATEGIES=(
    ('third_party/rfuzz/upstream/ibex/rtl/ibex_if_stage.sv',
     '8b99f212f06aa942e53e8a768863587ffdc29176f5a486c6e273262311c9f6ae',0xffffff00,0x80),
    ('third_party/cv32e20_upstream_reference/rtl/cve2_if_stage.sv',
     'c42468e108838a1c78bdddde679ba520d4acf9396176637c7b30a4f06a23a325',0xfffffffc,0),
    # cv32e40p_if_stage.sv:157/160: PC_BOOT = {boot_addr_i[31:2], 2'b0}.
    ('external_designs/cv32e40p/rtl/cv32e40p_if_stage.sv',
     'e2d1cc9bc433a093938f2d4e4268c611f9a9bf199101e85114d417ff04597626',0xfffffffc,0),
)


def source_backed_boot_fetch(profile,*,base_dir,configured_boot_base):
    from myfuzz.local_harness.source_lock import verify_local_source_lock
    if (type(configured_boot_base) is not int or not 0<=configured_boot_base<2**32
            or configured_boot_base%4 or profile.cpu is None or profile.cpu.xlen!=32):
        raise ValueError('CPU boot requires an aligned RV32 configured base')
    root=Path(base_dir).resolve()
    declared={(root/profile.source.source_root/path).resolve() for path in profile.source.files}
    contract=profile.evidence.get('boot_fetch')
    if contract is not None:
        if (type(contract) is not dict
                or set(contract)!={'source_file','source_sha256','base_mask','fixed_bits'}):
            raise ValueError('CPU boot profile contract invalid')
        source=contract['source_file']; digest=contract['source_sha256']
        mask=contract['base_mask']; bits=contract['fixed_bits']
        if (type(source) is not str or not source or Path(source).is_absolute()
                or type(digest) is not str or len(digest)!=64
                or any(c not in '0123456789abcdef' for c in digest)
                or type(mask) is not int or not 0<=mask<2**32
                or type(bits) is not int or not 0<=bits<2**32
                or mask & 3 or bits & 3 or mask & bits):
            raise ValueError('CPU boot profile contract invalid')
        path=(root/profile.source.source_root/source).resolve()
        if path not in declared:
            raise ValueError('CPU boot profile source not declared')
        verify_local_source_lock(profile,base_dir=root)
        if sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('CPU boot profile source changed')
        return (configured_boot_base&mask)|bits
    matches=[(root/path,digest,mask,bits) for path,digest,mask,bits in _BOOT_STRATEGIES
        if (root/path).resolve() in declared]
    if len(matches)!=1:
        raise ValueError('CPU boot source strategy is not registered')
    verify_local_source_lock(profile,base_dir=root)
    path,digest,mask,bits=matches[0]
    if sha256(path.read_bytes()).hexdigest()!=digest:
        raise ValueError('CPU boot source strategy changed')
    return (configured_boot_base&mask)|bits
