"""Operation-scoped F2 route evidence, independent of instance names."""
from copy import deepcopy
import pytest
from myfuzz.scenario.edge_provenance import edge_endpoints_from_compiled
from myfuzz.scenario.runtime_path_contract import RuntimeNode,RuntimeEdgeContract,RuntimePathContract


def contract_and_compiled():
    contract=RuntimePathContract('a'*64,(
        RuntimeNode('load','initiator_renamed','logical'),
        RuntimeNode('reply','storage_renamed','logical'),
        RuntimeNode('consumed','initiator_renamed','logical')),
        tuple(RuntimeEdgeContract(i,0,'mmio_route',initiator_component='initiator_renamed',
            device_id='storage_renamed',base=0x40000000,size=0x1000) for i in (0,1)))
    edges=[dict(rule_index=i,prerequisite_index=0,prerequisite=s,target=t,kind='DATA_BINDING')
           for i,s,t in ((0,'load','reply'),(1,'reply','consumed'))]
    compiled=dict(schema_version='compiled_runtime_paths.v1',graph_sha256=contract.graph_sha256,
        contract_sha256=contract.identity_sha256,topology_sha256='b'*64,
        topology={'routers':[{'initiator':'initiator_renamed','windows':[
            {'device_id':'storage_renamed','base':0x40000000,'size':0x1000}]}]},
        paths=[{'path_id':'path'}],proof_scope='declared_topology_only',
        runtime_causality_verified=False,resource_versions_verified=False,
        declaration={'selections':[{'path_id':'path','edges':edges}]})
    return contract,compiled


def test_mmio_return_endpoints_keep_declared_node_ownership():
    contract,compiled=contract_and_compiled()
    endpoints=edge_endpoints_from_compiled(contract,compiled)
    assert endpoints[(0,0)].source.component=='initiator_renamed'
    assert endpoints[(0,0)].target.component=='storage_renamed'
    assert endpoints[(1,0)].source.component=='storage_renamed'
    assert endpoints[(1,0)].target.component=='initiator_renamed'
