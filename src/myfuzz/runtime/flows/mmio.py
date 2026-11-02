"""Bus facts do not certify internal storage or cross-case writer provenance."""
from ..evidence.contracts import EffectEvidence,EvidenceRef
from ...scenario.ledger import TransactionKey


def _sample_names(row):
    """The declared native request/response sample names for this join."""
    apb='native_APB_event' in row
    pairs={request: response for request, response in (
        ('native_wishbone_request_event','native_wishbone_response_event'),
        ('native_axi4lite_request_event','native_axi4lite_response_event'),
        ('native_ahb_request_event','native_ahb_response_event'),
        ('native_tlul_request_event','native_tlul_response_event'))
        if request in row or response in row}
    if apb and pairs:raise ValueError('MMIO-native-protocol-sample-shape')
    if apb:return ('native_APB_event',)
    if len(pairs)!=1:
        raise ValueError('MMIO-native-protocol-sample-shape')
    request, response = next(iter(pairs.items()))
    if request not in row or response not in row:
        raise ValueError('MMIO-native-protocol-sample-shape')
    return (request, response)


def capture_mmio(context,receipt):
    if (receipt.get('status')!='observed' or receipt.get('flow_id')!=context.flow_id
            or receipt.get('internal_storage_version')!='unknown'
            or receipt.get('cross_case_origin')!='unknown' or receipt.get('reward_eligible') is not False):
        raise ValueError('MMIO-observation-contract-required')
    rows=receipt.get('joins')
    if not rows:raise ValueError('MMIO-native-transaction-joins-required')
    result=[]
    for row in rows:
        key=TransactionKey(**row['source_transaction'])
        sample_names=_sample_names(row)
        refs=tuple(EvidenceRef(context.target_component,row[name],'local_tick_sample')
            for name in sample_names)
        destination=(EvidenceRef(context.cpu_component,row['delivery_event'],'mmio_delivery'),)
        # Component effect deliberately unsupported: a successful bus transfer
        # is not a source-verified persistent register-version certificate.
        result.append(EffectEvidence(key=key,status='certified',scope='physical_protocol_sample',
            binding_sha256=receipt['execution_binding_sha256'],semantic_contract_sha256=context.semantic_contract_sha256,
            source_refs=(),native_refs=refs,destination_refs=destination,
            obligation_results=(('physical_protocol_sample','certified'),)))
    return tuple(result)
