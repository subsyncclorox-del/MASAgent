import pytest
from masagent.cli import main


def test_cli_run_requires_scope():
    with pytest.raises(SystemExit):
        main(["run", "--target", "example.com"])  # missing --scope -> argparse exits


def test_cli_no_command_returns_2():
    assert main([]) == 2


def test_cli_run_missing_scope_file(tmp_path):
    with pytest.raises(SystemExit):
        main(["run", "--scope", str(tmp_path / "nope.yaml"), "--target", "example.com"])
