"""Authenticated passive observation of one fixed, official PULP GPIO top.

These facts authenticate measurement expressions, not instruction operands or
cross-component causality. Packed INTTYPE bit 2*i is pin i's type bit zero.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from myfuzz.composition.component_profile import load_component_profile

PULP_GPIO_PROFILE = 'configs/peripherals/pulp_gpio_causal_local/component_profile.json'
_PROFILE_SHA256 = 'ebda4798cc5e3874957e3b4aad8aa3fe3131c94f01537e90759fbd2f1bbfead0'
PULP_GPIO_PROBES = MappingProxyType({
    'apb_addr': (12, 'PADDR'), 'psel': (1, 'PSEL'),
    'penable': (1, 'PENABLE'), 'pwrite': (1, 'PWRITE'),
    'pwdata': (32, 'PWDATA'), 'prdata': (32, 'PRDATA'),
    'pready': (1, 'PREADY'), 'pslverr': (1, 'PSLVERR'),
    'decoded_word': (5, 's_apb_addr'), 'write': (1, 's_write'),
    'write_out': (64, 's_write_out'), 'write_inten': (64, 's_write_inten'),
    'write_gpioen': (64, 's_write_gpen'), 'write_inttype': (64, 's_write_inttype'),
    'out': (32, 'r_gpio_out'), 'dir': (32, 'r_gpio_dir'),
    'gpioen': (32, 'r_gpio_en'), 'inten': (32, 'r_gpio_inten'),
    'inttype': (64, 'r_gpio_inttype'), 'sync0': (32, 'r_gpio_sync0'),
    'sync1': (32, 'r_gpio_sync1'), 'padin_latch': (32, 'r_gpio_in'),
    'input_clock_enable': (16, 's_clk_en'), 'rise': (32, 's_gpio_rise'),
    'fall': (32, 's_gpio_fall'), 'irq_trigger_mask': (32, 's_is_int_all'),
    'status': (32, 'r_status'), 'native_irq': (1, 's_rise_int'),
})

def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def pulp_gpio_register_map():
    return {
        'decode': 'PADDR[6:2]', 'alias_period_bytes': 128,
        'registers': {str(offset): {'name': name, 'semantics': semantics} for offset,name,semantics in (
            (0,'PADDIR','overwrite'),(4,'GPIOEN','overwrite'),(8,'PADIN','read_pre_r_gpio_in'),
            (12,'PADOUT','overwrite'),(16,'PADOUTSET','old_or_wdata'),(20,'PADOUTCLR','old_and_not_wdata'),
            (24,'INTEN','overwrite'),(28,'INTTYPE_LOW','packed_two_bits_pins_0_15'),
            (32,'INTTYPE_HIGH','packed_two_bits_pins_16_31'),
            (36,'INTSTATUS','read_pre_status_clear_unless_pre_native_trigger'))},
        'inttype': {'0':'fall','1':'rise','2':'rise_or_fall','3':'disabled'},
        'upper_bank': 'decode_masks_preserved_no_physical_pad_update',
        'padcfg': 'outside_consumption_pilot',
    }

def pulp_gpio_probe_document():
    return {
        'schema_version': 'pulp_gpio_probe_contract.v1',
        'template_id':'pulp.gpio.causal','template_version':'1','variant_id':'pulp_gpio_causal_v1',
        'source': {'root':'third_party/soc-pulp-apb-gpio','revision':'git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83',
                   'top_module':'apb_gpio','path':'rtl/apb_gpio.sv',
                   'sha256':'1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef'},
        'parameters': {'APB_ADDR_WIDTH':12,'PAD_NUM':32,'NBIT_PADCFG':4},
        'hierarchy':'u_component.u_dut',
        'probes': {name:{'width':width,'expression':'u_component.u_dut.'+signal,
                          'physical_port':'gpio_probe_'+name,'runtime_name':'probe_gpio_'+name}
                   for name,(width,signal) in PULP_GPIO_PROBES.items()},
        'sampling':'pre_post_rising','irq_semantics':'native_transition_pulse',
        'register_map':pulp_gpio_register_map(),
        'synchronizer': {'enable':'s_clk_en[pin/4]', 'sync0':'pre_gpio_in',
                         'sync1':'pre_r_gpio_sync0','padin_latch':'pre_r_gpio_sync1'},
        'inttype_packing':'pin_i_bits_2i_plus_1_to_2i',
        'status_priority':'pre_trigger_or_before_read_clear',
    }

def pulp_gpio_observation_contract():
    document=pulp_gpio_probe_document()
    return {'schema_version':'pulp_gpio_observation.v1','template_id':'pulp.gpio.causal',
            'template_version':'1','variant_id':'pulp_gpio_causal_v1',
            'register_map_sha256':_sha(document['register_map']),
            'probes_sha256':_sha(document), 'sampling':'pre_post_rising',
            'irq_semantics':'native_transition_pulse'}

def validate_pulp_gpio_observation_contract(value):
    if value != pulp_gpio_observation_contract():
        raise ValueError('pulp-gpio-observation-contract-mismatch')

def validate_pulp_gpio_probe_document(value):
    if value != pulp_gpio_probe_document():
        raise ValueError('pulp-gpio-probe-document-mismatch')

def verify_pulp_gpio_profile(profile, *, base_dir: Path):
    raw=(Path(base_dir).resolve()/PULP_GPIO_PROFILE).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=_PROFILE_SHA256:
        raise ValueError('pulp-gpio-profile-changed')
    if (load_component_profile(json.loads(raw)) != profile
            or dict(profile.source_document) != json.loads(raw)['source']):
        raise ValueError('pulp-gpio-profile-object-mismatch')

def decoded_gpio_word(raw_offset):
    if type(raw_offset) is not int or not 0 <= raw_offset < 4096:
        raise ValueError('pulp-gpio-raw-offset-outside-fixed-window')
    return (raw_offset >> 2) & 31

def unpack_gpio_inttype(value):
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ValueError('pulp-gpio-inttype-width')
    return tuple((value >> (2 * pin)) & 3 for pin in range(32))

def verify_pulp_gpio_source_contract(profile, *, base_dir: Path):
    """Reuse actual upstream Git/content verification and pin local variant bytes.

    The new local closure describes the same official source elaboration. Its
    trusted hash is checked explicitly; no staging is needed to admit it.
    """
    import copy
    from .source_lock import verify_local_source_lock
    root=Path(base_dir).resolve()
    verify_pulp_gpio_profile(profile,base_dir=root)
    upstream=load_component_profile(json.loads((root/'configs/peripherals/pulp_gpio/component_profile.json').read_bytes()))
    source=pulp_gpio_probe_document()['source']
    if (upstream.source.revision,upstream.source.source_root,upstream.source.top_module,upstream.source.files)!=(
            source['revision'],source['root'],source['top_module'],(source['path'],)):
        raise ValueError('pulp-gpio-upstream-source-mismatch')
    verified=verify_local_source_lock(upstream,base_dir=root)
    if hashlib.sha256((root/source['root']/source['path']).read_bytes()).hexdigest()!=source['sha256']:
        raise ValueError('pulp-gpio-upstream-content-mismatch')
    closure_path='configs/soc/closures/pulp_gpio_causal_local.json'
    closure_raw=(root/closure_path).read_bytes()
    closure_sha=hashlib.sha256(closure_raw).hexdigest()
    if closure_sha!='bcf42dc3b40aa2e61a115c8a3fc874c2ec28a1a4aebe2b6c85f64d331c1563c7':
        raise ValueError('pulp-gpio-closure-changed')
    lock=json.loads((root/'configs/soc/sources.lock.json').read_bytes())
    original=next(r for r in lock['components'] if r['id']=='pulp_gpio')
    expected=copy.deepcopy(original);expected['id']='pulp_gpio_causal_local'
    expected['source']['top_port_selection']='all'
    expected['elaboration']['evidence']=closure_path
    expected['elaboration']['evidence_sha256']=closure_sha
    variants=[r for r in lock['components'] if r['id']=='pulp_gpio_causal_local']
    if variants!=[expected]: raise ValueError('pulp-gpio-variant-lock-mismatch')
    return {**verified,'closure_sha256':closure_sha,
            'profile_sha256':_PROFILE_SHA256,
            'gpio_observation_contract':pulp_gpio_observation_contract(),
            'gpio_probe_contract_sha256':_sha(pulp_gpio_probe_document())}
