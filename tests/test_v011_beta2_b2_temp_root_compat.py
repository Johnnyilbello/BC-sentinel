from pathlib import Path

from tools.v011_beta2_b2_temp_root_compat import (
    PROFILE,
    apply_interactive_temp_root_fix,
    is_structural_high_churn_root,
)


def _legacy_realtime_source() -> str:
    return (
        'from pathlib import Path\n'
        'import os\n\n'
        'def canonical_path(path):\n'
        '    return str(path)\n\n'
        'def _watchdog_recursive_for_root(path: Path) -> bool:\n'
        '    try:\n'
        '        target = canonical_path(path)\n'
        '    except Exception:\n'
        '        return True\n'
        '    high_churn = set()\n'
        '    for raw in (os.getenv("TEMP", ""), os.getenv("APPDATA", "")):\n'
        '        if not raw:\n'
        '            continue\n'
        '        try:\n'
        '            high_churn.add(canonical_path(Path(raw)))\n'
        '        except Exception:\n'
        '            continue\n'
        '    return target not in high_churn\n'
    )


def test_structural_high_churn_classification_is_independent_of_service_identity():
    assert is_structural_high_churn_root(r"C:\Users\InteractiveUser\AppData\Local\Temp") is True
    assert is_structural_high_churn_root(r"D:\Profiles\Other\AppData\Local\Temp\") is True
    assert is_structural_high_churn_root(r"C:\Users\InteractiveUser\AppData\Roaming") is True
    assert is_structural_high_churn_root(r"C:\Windows\Temp") is True
    assert is_structural_high_churn_root(r"C:\Users\InteractiveUser\Downloads") is False
    assert is_structural_high_churn_root(r"C:\Temp\project") is False


def test_patch_is_surgical_idempotent_and_preserves_root_level_watch_semantics(tmp_path: Path):
    target = tmp_path / "realtime.py"
    target.write_text(_legacy_realtime_source(), encoding="utf-8")

    first = apply_interactive_temp_root_fix(target)
    second = apply_interactive_temp_root_fix(target)
    text = target.read_text(encoding="utf-8")

    assert first["patched"] is True
    assert second["patched"] is False
    assert second["already_compatible"] is True
    assert first["profile"] == PROFILE
    assert text.count("def _watchdog_recursive_for_root(path: Path) -> bool:") == 1
    assert "if target in high_churn:" in text
    assert '("appdata", "local", "temp")' in text
    assert '("appdata", "roaming")' in text
    assert '("windows", "temp")' in text
    assert "return False\n    return True" in text


def test_patched_runtime_helper_treats_interactive_temp_as_non_recursive_when_service_env_differs(
    tmp_path: Path,
    monkeypatch,
):
    target = tmp_path / "realtime.py"
    target.write_text(_legacy_realtime_source(), encoding="utf-8")
    apply_interactive_temp_root_fix(target)

    monkeypatch.setenv("TEMP", r"C:\Windows\Temp")
    monkeypatch.setenv("APPDATA", r"C:\Windows\System32\config\systemprofile\AppData\Roaming")

    namespace = {"__name__": "b2_temp_root_fixture"}
    exec(compile(target.read_text(encoding="utf-8"), str(target), "exec"), namespace)
    recursive = namespace["_watchdog_recursive_for_root"]

    assert recursive(Path(r"C:\Users\InteractiveUser\AppData\Local\Temp")) is False
    assert recursive(Path(r"C:\Users\InteractiveUser\AppData\Roaming")) is False
    assert recursive(Path(r"C:\Users\InteractiveUser\Downloads")) is True


def test_patch_refuses_unknown_helper_shape(tmp_path: Path):
    target = tmp_path / "realtime.py"
    target.write_text(
        "from pathlib import Path\n"
        "def _watchdog_recursive_for_root(path: Path) -> bool:\n"
        "    return True\n",
        encoding="utf-8",
    )

    try:
        apply_interactive_temp_root_fix(target)
    except RuntimeError as exc:
        assert "Unexpected watchdog recursion helper shape" in str(exc)
    else:
        raise AssertionError("compatibility patch must fail closed on an unknown helper shape")
