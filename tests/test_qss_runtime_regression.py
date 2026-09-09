import ast
from pathlib import Path

def _app_style_assignment():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "APP_STYLE" for t in node.targets):
                return node.value
    raise AssertionError("APP_STYLE assignment not found")

def test_app_style_fstring_only_interpolates_design_token_dictionary():
    value = _app_style_assignment()
    assert isinstance(value, ast.JoinedStr)

    formatted = [
        node.value
        for node in ast.walk(value)
        if isinstance(node, ast.FormattedValue)
    ]
    assert formatted

    for expr in formatted:
        # Every valid interpolation must be C["token"].
        assert isinstance(expr, ast.Subscript)
        assert isinstance(expr.value, ast.Name)
        assert expr.value.id == "C"

def test_sidebar_settings_uses_same_nav_component():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert '("Impostazioni", "⚙")' in source
    assert 'b.setObjectName("nav")' in source
