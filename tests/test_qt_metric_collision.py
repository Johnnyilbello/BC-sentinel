from pathlib import Path
import ast

def test_mainwindow_does_not_override_qpaintdevice_metric():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert node.name != "metric", (
                "Do not define MainWindow.metric(): QMainWindow/QPaintDevice already "
                "uses metric(PaintDeviceMetric) internally."
            )

def test_dashboard_uses_metric_card_helper():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "def metric_card(" in source
    assert "self.metric_card(" in source
