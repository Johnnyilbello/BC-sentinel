from sentinel.startup import StartupManager

def test_background_command():
    assert "--background" in StartupManager().command(True)
