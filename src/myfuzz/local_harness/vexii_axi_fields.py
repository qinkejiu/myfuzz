"""Reduced single-beat AXI shapes, without invented physical burst fields."""
from .axi4_fields import AXI_INPUT_FIELDS, AXI_WIDTHS

ABSENT = frozenset(('awlen', 'awburst', 'awlock', 'awqos',
                    'arlen', 'arburst', 'arlock', 'arqos'))
DATA_SHAPE = {role: ('input' if role in AXI_INPUT_FIELDS else 'output', width)
              for role, width in AXI_WIDTHS.items() if role not in ABSENT}
FETCH_SHAPE = {role: shape for role, shape in DATA_SHAPE.items()
               if role.startswith(('ar', 'r'))}
SHAPES = {'i': FETCH_SHAPE, 'd': DATA_SHAPE}
STEP_PORTS = tuple(prefix+'_'+role for prefix, shape in SHAPES.items()
                   for role, (direction, _) in shape.items() if direction == 'input')
STEP_MAXIMA = tuple((1 << SHAPES[name[0]][name[2:]][1])-1 for name in STEP_PORTS)
