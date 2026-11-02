"""Pure DAG queries over current documentary observations."""
from .model import Goal, Snapshot


def _statuses(goal: Goal, snapshot: Snapshot):
    nodes, cache = goal.nodes, {}

    def resolve(key):
        if key in cache:
            return cache[key]
        node = nodes[key]
        if node.mode == "effect":
            answer = snapshot.get(key).status
        else:
            children = [resolve(child) for child in node.prerequisites]
            if node.mode == "all":
                answer = ("refuted" if "refuted" in children else
                          "satisfied" if all(c == "satisfied" for c in children) else "unknown")
            else:
                answer = ("satisfied" if "satisfied" in children else
                          "refuted" if all(c == "refuted" for c in children) else "unknown")
        cache[key] = answer
        return answer

    for key in nodes:
        resolve(key)
    return cache


def status(goal: Goal, snapshot: Snapshot, key: str) -> str:
    return _statuses(goal, snapshot)[key]


def frontier(goal: Goal, snapshot: Snapshot) -> tuple[str, ...]:
    nodes, statuses, result, visited = goal.nodes, _statuses(goal, snapshot), set(), set()

    def walk(key):
        if key in visited or statuses[key] == "satisfied":
            return
        visited.add(key)
        node = nodes[key]
        missing = [child for child in node.prerequisites if statuses[child] != "satisfied"]
        if not missing and node.mode == "effect":
            result.add(key)
        for child in missing:
            walk(child)

    walk(goal.root)
    return tuple(sorted(result))
