from sentinel.persistence_monitor import _persistence_score

def test_encoded_powershell_persistence_scores_higher():
    normal,_=_persistence_score("registry:Run",r"C:\Program Files\App\app.exe","added")
    risky,reasons=_persistence_score(
        "registry:Run",
        r"powershell.exe -EncodedCommand AAAA C:\Users\A\AppData\Local\Temp\x.ps1",
        "added",
    )
    assert risky > normal
    assert any("codificato" in x.lower() for x in reasons)
