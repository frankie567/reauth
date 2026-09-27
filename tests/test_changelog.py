import pathlib
import subprocess
import sys


def test_changelog_release_and_notes(tmp_path: pathlib.Path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n## [Unreleased]\n\n### Security\n\n"
        "- Reject replayed codes.\n\n## [1.0.0] - 2026-01-01\n\n"
        "### Added\n\n- Initial release.\n\n"
        "[Unreleased]: https://github.com/frankie567/reauth/compare/v1.0.0...HEAD\n"
    )
    command = [sys.executable, "-m", "keepachangelog"]
    subprocess.run(
        [*command, "release", "1.0.1"], cwd=tmp_path, check=True, capture_output=True
    )
    notes = subprocess.run(
        [*command, "show", "1.0.1"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Reject replayed codes." in notes
    assert "Initial release." not in notes
    assert "## [1.0.1] - " in changelog.read_text()
    assert "v1.0.1...HEAD" in changelog.read_text()
    missing = subprocess.run(
        [*command, "show", "9.9.9"], cwd=tmp_path, capture_output=True, check=False
    )
    assert missing.returncode != 0
