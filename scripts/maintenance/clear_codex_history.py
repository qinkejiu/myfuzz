#!/usr/bin/env python3
"""清理 /home/qinkejiu/myfuzz 的本地 Codex 对话。运行前请退出 Codex。"""

import argparse
import json
import sqlite3
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="仅预览，不删除")
    args = parser.parse_args()
    base = Path.home() / ".codex"
    target = "/home/qinkejiu/myfuzz"
    ids, files = set(), set()

    for folder in ("sessions", "archived_sessions"):
        for path in (base / folder).rglob("*.jsonl"):
            with path.open() as stream:
                try:
                    entry = json.loads(stream.readline())
                except ValueError:
                    continue
            meta = entry.get("payload", {})
            if entry.get("type") == "session_meta" and meta.get("cwd") == target:
                ids.add(meta["id"])
                files.add(path)

    state_path = base / "state_5.sqlite"
    if state_path.exists():
        db = sqlite3.connect(state_path.as_uri() + "?mode=ro", uri=True)
        try:
            for sid, path in db.execute(
                "SELECT id, rollout_path FROM threads WHERE cwd=?", (target,)
            ):
                ids.add(sid)
                files.add(Path(path))
        finally:
            db.close()

    # 先解析索引，避免解析失败时已经发生删除。
    updates = {}
    for name, key in (("history.jsonl", "session_id"), ("session_index.jsonl", "id")):
        path = base / name
        if path.exists():
            kept = []
            for line in path.read_text().splitlines(keepends=True):
                try:
                    remove = json.loads(line).get(key) in ids
                except ValueError:
                    remove = False
                if not remove:
                    kept.append(line)
            updates[path] = "".join(kept)

    # 数据库提供的文件路径必须仍在 Codex 会话目录下。
    roots = [(base / folder).resolve() for folder in ("sessions", "archived_sessions")]
    for path in files:
        if not any(path.resolve().is_relative_to(root) for root in roots):
            raise RuntimeError(f"拒绝删除会话目录外的文件：{path}")

    print(f"项目：{target}")
    print(f"匹配 {len(ids)} 个会话，{sum(p.exists() for p in files)} 个会话文件。")
    if args.dry_run:
        print("预览完成，未修改任何记录。")
        return
    if not ids:
        return

    if state_path.exists():
        db = sqlite3.connect(state_path)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                for sid in ids:
                    db.execute(
                        "DELETE FROM thread_spawn_edges "
                        "WHERE parent_thread_id=? OR child_thread_id=?", (sid, sid)
                    )
                    db.execute("DELETE FROM threads WHERE id=?", (sid,))
        finally:
            db.close()

    history_path = base / "thread_history_1.sqlite"
    if history_path.exists():
        db = sqlite3.connect(history_path)
        try:
            with db:
                for table in (
                    "thread_turns", "thread_items", "thread_history_projection_state",
                    "thread_realtime_items",
                ):
                    db.executemany(
                        f"DELETE FROM {table} WHERE thread_id=?", [(sid,) for sid in ids]
                    )
        finally:
            db.close()

    for path, content in updates.items():
        path.write_text(content)
    for path in files:
        path.unlink(missing_ok=True)
    print(f"已清理 {len(ids)} 个会话的本地记录及历史索引。")


if __name__ == "__main__":
    main()
