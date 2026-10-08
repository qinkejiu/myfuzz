"""The P5 replay receipt binds fresh comparison to its actual input files."""

from pathlib import Path
import tempfile

import pytest

from scripts.runs import replay_p5_online_verified as verified
from scripts.runs.replay_p5_online_verified import run_verified_replay


def test_verified_replay_rejects_untrusted_fake_cli():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        online = root / "online"
        online.mkdir()
        for name in ("online_plan.json", "online_final_trace.meta.json",
                     "online_events.zlib", "online_run_identity.json"):
            (online / name).write_text(name)
        cli = root / "replay_cli.py"
        cli.write_text('print("{\\"matches\\": true, \\"first_difference\\": null}")\n')
        result_path = root / "replay.json"
        with pytest.raises(ValueError, match="trusted frozen replay CLI"):
            run_verified_replay(cli, root / "cache",
                                online / "online_plan.json",
                                online / "online_final_trace.meta.json",
                                result_path)
        assert not result_path.exists()


def test_verified_replay_resolves_manifest_before_checking_snapshot(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
        root = Path(temp)
        snapshot = root / "snapshot"
        (snapshot / "scripts").mkdir(parents=True)
        cli = snapshot / "scripts/run_ibex_pulp_online.py"
        cli.write_text('print("{\\"matches\\": true, \\"first_difference\\": null}")\n')
        online = root / "run/online"
        online.mkdir(parents=True)
        for name in ("online_plan.json", "online_final_trace.meta.json",
                     "online_events.zlib", "online_run_identity.json", "report.json"):
            (online / name).write_text(name)
        (online.parent / "run-time.txt").write_text("run_wall_seconds=600\n")
        manifest = online.parent / "snapshot.sha256"
        manifest.write_text(f"{verified._sha256(cli)}  scripts/run_ibex_pulp_online.py\n")
        monkeypatch.setattr(verified, "SNAPSHOT_ROOT", snapshot)
        monkeypatch.setattr(verified, "SNAPSHOT_MANIFEST_SHA256", verified._sha256(manifest))
        monkeypatch.setattr(verified, "TRUSTED_CLI_SHA256", verified._sha256(cli))
        relative = online.relative_to(Path.cwd())
        result = run_verified_replay(cli, root / "cache",
                                     relative / "online_plan.json",
                                     relative / "online_final_trace.meta.json",
                                     root / "result.json")
        assert result["matches"] is True
        assert result["inputs"]["report.json"] == verified._sha256(online / "report.json")
