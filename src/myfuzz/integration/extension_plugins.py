"""Named extension seam for protocol adapters outside the built-in pair.

The built-in executor covers APB3 and Wishbone targets and the OBI,
Wishbone, AHB-Lite and AXI4-Lite CPUs.  A protocol that needs its own
adapter is added as one module with a fixed name; this seam only imports
the module and delegates.  A missing module means "not adapted yet", never
a fabricated success.
"""
from importlib import import_module

# Artifact kind -> module that exposes ``target_adapter(artifact, access, request)``.
_TARGET_MODULES = {
    'tlul_register_observe': 'myfuzz.integration.target_tlul',
    'axi4lite_register_observe': 'myfuzz.integration.target_axi4lite',
    'ahb_lite_register_observe': 'myfuzz.integration.target_ahb_lite',
}

# Artifact kind -> module that exposes ``cpu_adapter(artifact, image, stream, base_dir=None)``.
_CPU_MODULES = {
    'reduced_dual_axi_cpu': 'myfuzz.integration.cpu_axi4',
    'reduced_dual_axi_irq_cpu': 'myfuzz.integration.cpu_axi4',
    'axi4_cpu': 'myfuzz.integration.cpu_axi4',
    'cva6_packed_axi4_cpu': 'myfuzz.integration.cpu_axi4',
    # BOOM's real artifact kind.  The previous map named a *kind* that does not
    # exist ("boom_cpu") and a *module* that does not exist either, so it could
    # never be imported: every BOOM row fell through as "not adapted".  The
    # module now exists and refuses with the machine-readable gap list
    # (``MMIO-CPU-adapter-unsupported:tilelink:<kind>:{...}``), which is what
    # ``mmio_support`` reports as ``status='unsupported'``.
    'tilelink_coherent_cpu': 'myfuzz.integration.cpu_tlul',
}


def _module(name):
    try:
        return import_module(name)
    except ModuleNotFoundError:
        return None


def target_adapter(artifact, access, request):
    document = getattr(artifact, 'runtime_document', None)
    name = _TARGET_MODULES.get(document.get('kind')) if isinstance(document, dict) else None
    module = _module(name) if name else None
    return None if module is None else module.target_adapter(artifact, access, request)


def cpu_adapter(artifact, image, stream, *, base_dir=None):
    document = getattr(artifact, 'runtime_document', None)
    name = _CPU_MODULES.get(document.get('kind')) if isinstance(document, dict) else None
    module = _module(name) if name else None
    return None if module is None else module.cpu_adapter(
        artifact, image, stream, base_dir=base_dir)
