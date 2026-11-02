"""Closed, versioned search configuration; data never selects Python imports."""
from hashlib import sha256
import json
from pathlib import Path
import re

SCHEMA = 'dependency_search_scenario.v1'
KEYS = {'schema_version', 'name', 'backend', 'descriptor', 'flow', 'records', 'goal', 'rounds'}

def identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def load_scenario(path, root):
    config = json.loads(Path(path).read_text())
    if not isinstance(config, dict):
        raise ValueError('scenario must be an object')
    unknown = set(config) - KEYS
    if unknown:
        raise ValueError(f'unknown scenario keys: {sorted(unknown)}')
    if config.get('schema_version') != SCHEMA:
        raise ValueError('unsupported scenario schema_version')
    if not isinstance(config.get('name'), str) or not config['name']:
        raise ValueError('scenario name required')
    if config.get('backend') not in {'gpio', 'storage', 'descriptor'}:
        raise ValueError('unsupported backend')
    if config['backend'] != 'gpio':
        relative = config.get('descriptor')
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise ValueError('descriptor must be project-relative')
        resolved = (Path(root) / relative).resolve()
        if not resolved.is_relative_to(Path(root).resolve()) or not resolved.is_file():
            raise ValueError('descriptor must exist within project root')
        if config.get('flow') not in {'F1','F2','F3','F4','F5','F6','mixed'}:
            raise ValueError('unsupported flow')
        if config['backend'] == 'storage' and (config['flow'] != 'mixed' or config.get('records') is not None):
            raise ValueError('storage requires mixed flow and null records for its registered finite catalog')
        records = config.get('records')
        if records is None and config['backend'] == 'storage' and config['flow'] == 'mixed':
            records = []
        elif not isinstance(records, list) or not records or len(records) > 64:
            raise ValueError('records must be a nonempty finite list (at most 64)')
        if any(not isinstance(row, str) or not re.fullmatch(r'(?:F[123456]:)?(?:[0-9a-fA-F]{2})+', row) or len(row)>131072 for row in records):
            raise ValueError('records must contain bounded nonempty hex byte strings')
    goal=config.get('goal')
    if not isinstance(goal, dict) or set(goal) - {'id','description'} or not isinstance(goal.get('id'), str) or not goal['id']:
        raise ValueError('goal requires id and optional description only')
    if 'rounds' in config and (type(config['rounds']) is not int or not 1 <= config['rounds'] <= 1000000):
        raise ValueError('rounds must be a positive bounded integer')
    return config
