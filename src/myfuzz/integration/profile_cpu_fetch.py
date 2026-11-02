"""Source-backed CPU fetch behavior declarations, without RTL proof claims."""
from hashlib import sha256
from pathlib import Path


def _verify_sources(profile, root, sources):
    from myfuzz.local_harness.source_lock import verify_local_source_lock
    if type(sources) is not dict or not sources:
        raise ValueError('CPU-fetch-source-declaration-required')
    declared=set(profile.source.files)
    for path,digest in sources.items():
        if (type(path) is not str or path not in declared or type(digest) is not str
                or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest)):
            raise ValueError('CPU-fetch-source-declaration-invalid')
    verify_local_source_lock(profile,base_dir=root)
    for path,digest in sources.items():
        source=root/profile.source.source_root/path
        if source.is_symlink() or sha256(source.read_bytes()).hexdigest()!=digest:
            raise ValueError('CPU-fetch-source-mismatch')


def profile_fetch_granule(profile, *, base_dir):
    """Return a profile author's source-backed fetch supply granularity."""
    doc=profile.evidence.get('instruction_fetch_granule')
    if doc is None:return None
    if (type(doc) is not dict or set(doc)!={'schema_version','bytes','source_files'}
            or doc['schema_version']!='cpu_fetch_granule.v1' or type(doc['bytes']) is not int
            or not 4<=doc['bytes']<=4096 or doc['bytes'] & (doc['bytes']-1)):
        raise ValueError('CPU-fetch-granule-declaration-invalid')
    _verify_sources(profile,Path(base_dir).resolve(),doc['source_files'])
    return doc['bytes']


def profile_axil_fetch_observation(profile, *, base_dir):
    """Only a declared CPU fetch signal may classify AXI-Lite read handshakes."""
    doc=profile.evidence.get('axi4_lite_fetch_observation')
    if doc is None:return None
    keys={'schema_version','role','bit','asserted','qualified_by','basis','source_files','request_identity'}
    if (type(doc) is not dict or set(doc)!=keys or doc['schema_version']!='axi4_lite_fetch_observation.v1'
            or doc['role']!='arprot' or type(doc['bit']) is not int or doc['bit']!=2
            or doc['asserted']!='instruction_fetch' or doc['qualified_by']!=['arvalid','arready']
            or doc['request_identity']!='stable_through_backend_acceptance'
            or type(doc['basis']) is not str or not doc['basis']):
        raise ValueError('CPU-AXI-Lite-fetch-declaration-invalid')
    _verify_sources(profile,Path(base_dir).resolve(),doc['source_files'])
    return {key:doc[key] for key in ('role','bit','asserted','qualified_by','basis')}
