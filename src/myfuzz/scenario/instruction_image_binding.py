"""Explicit admission of a selected memory-image source to actual CPU RAM."""
from dataclasses import asdict, dataclass
from .genome import DIRECTIONS
from .memory import PersistentMemory


@dataclass(frozen=True)
class InstructionImageSourceBinding:
    path_id: str
    direction: str
    source_id: str
    logical_source_id: str
    component: str
    memory_id: str
    base: int
    size: int
    readable: bool
    writable: bool

    def __post_init__(self):
        if any(type(value) is not str or not value for value in (
                self.path_id, self.direction, self.source_id, self.logical_source_id,
                self.component, self.memory_id)) or self.direction not in DIRECTIONS:
            raise ValueError('instruction image binding identity is invalid')
        if (type(self.base) is not int or self.base < 0
                or type(self.size) is not int or self.size <= 0
                or self.base + self.size > 1 << 64
                or type(self.readable) is not bool or type(self.writable) is not bool):
            raise ValueError('instruction image binding range or permissions are invalid')

    def document(self):
        return {'schema_version': 'instruction_image_source_binding.v1', **asdict(self)}

    @classmethod
    def from_document(cls, document):
        fields = set(cls.__dataclass_fields__)
        if (type(document) is not dict or set(document) != fields | {'schema_version'}
                or document['schema_version'] != 'instruction_image_source_binding.v1'):
            raise ValueError('invalid instruction image source binding document')
        binding = cls(**{key: document[key] for key in fields})
        if binding.document() != document:
            raise ValueError('noncanonical instruction image binding')
        return binding

    def validate_prepared(self, prepared):
        """Validate immutable source and selected edge facts without constructing RTL."""
        prepared.validate_cached_identity()
        direction, path = prepared.resolve_path_id(self.path_id)
        candidates = prepared.source_nodes_for(self.path_id)
        images = [source for source in candidates if source.kind == 'memory_image']
        if direction != self.direction or len(images) != 1:
            raise ValueError('instruction image binding requires one selected image source and direction')
        source = images[0]
        if ((source.source_id, source.component, source.port, source.bit_offset, source.width)
                != (self.source_id, self.component, self.memory_id, 0, self.size * 8)
                or self.direction not in source.directions
                or (source.image_address is not None and source.image_address != self.base)):
            raise ValueError('instruction image binding differs from selected graph source')
        declarations = {edge.key: edge for edge in prepared.contract.edges}
        edges = [declarations[(edge.rule_index, edge.prerequisite_index)]
                 for edge in path.edges if edge.prerequisite == self.source_id
                 and (edge.rule_index, edge.prerequisite_index) in declarations]
        if (not edges or any(edge.relation != 'persistent_state'
                or (edge.resource_component, edge.resource_id) != (self.component, self.memory_id)
                for edge in edges)):
            raise ValueError('instruction image binding lacks exact selected persistent resource edge')

    def validate(self, prepared, runner):
        self.validate_prepared(prepared)
        session = runner.sessions.get(self.component)
        memory = getattr(session, 'memory', None)
        if not isinstance(memory, PersistentMemory):
            raise ValueError('instruction image binding requires real PersistentMemory')
        regions = [region for region in memory._regions if region.memory_id == self.memory_id]
        if len(regions) != 1 or (
                regions[0].base, regions[0].size, regions[0].readable, regions[0].writable) != (
                self.base, self.size, self.readable, self.writable):
            raise ValueError('instruction image binding differs from exact RAM region')
        expected_windows = tuple((base, base + region.size, region)
            for region in memory._regions for base in (region.base, *region.aliases))
        if tuple(memory._windows) != expected_windows:
            raise ValueError('instruction image binding RAM address index drift')

    def validate_instruction(self, instruction, *, instruction_slots):
        if (getattr(instruction, 'source_id', None) != self.source_id
                or instruction.component != self.component
                or instruction.address < self.base
                or instruction.address + len(instruction.data) > self.base + self.size):
            raise ValueError('bound instruction source, component or image range mismatch')
        if (type(instruction_slots) not in (list, tuple)
                or any(type(row) not in (list, tuple) or len(row) != 3
                       or type(row[0]) is not str or not row[0]
                       or type(row[1]) is not int or row[1] < 0 or row[1] % 4
                       or type(row[2]) is not int or row[2] <= 0
                       for row in instruction_slots)):
            raise ValueError('invalid declared instruction slots')
        intervals = tuple((address, address + count * 4)
                          for component, address, count in instruction_slots
                          if component == self.component)
        if any(not any(start <= address and address + 4 <= end
                       for start, end in intervals)
               for address in range(instruction.address,
                                    instruction.address + len(instruction.data), 4)):
            raise ValueError('bound instruction lies outside declared instruction slots')
